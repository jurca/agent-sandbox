"""Talking to the proxy container: pushing tier configurations, deadline and reloads.

The proxy has no host mount. Files are copied in with `engine cp` (owned by the unprivileged
proxy user), its state is read with `engine exec`, and its log is the container log. The host
runtime directory only holds the CLI's own records (the deadline copy, the `net` session).
"""

from __future__ import annotations

import os
import subprocess
import time
from pathlib import Path

from . import proxy
from .config import ALLOW_BASE_FILE, ALLOW_EXTRA_FILE, PROJECT_DIR, PROXY_CONF_FILE
from .engine import Engine
from .project import Project
from .util import SandboxError, atomic_write, eprint, runtime_dir


def runtime_path(project: Project) -> Path:
    return runtime_dir() / project.id


def prepare_runtime(project: Project) -> Path:
    path = runtime_path(project)
    path.mkdir(parents=True, exist_ok=True)
    path.chmod(0o700)
    return path


def push(engine: Engine, project: Project, files: dict[str, str]) -> None:
    engine.copy_in(
        project.proxy_container, proxy.PROXY_DIR, files, uid=proxy.PROXY_UID, gid=proxy.PROXY_UID
    )


def read_allowlist(project: Project, name: str) -> list[str]:
    path = project.root / PROJECT_DIR / name
    try:
        text = path.read_text()
    except FileNotFoundError:
        return []
    return proxy.parse_allow_text(text, f"{PROJECT_DIR}/{name}")


def read_allowlists(project: Project) -> tuple[list[str], list[str]]:
    return read_allowlist(project, ALLOW_BASE_FILE), read_allowlist(project, ALLOW_EXTRA_FILE)


def static_config(project: Project) -> str:
    path = project.root / PROJECT_DIR / PROXY_CONF_FILE
    try:
        text = path.read_text()
    except FileNotFoundError:
        return ""
    proxy.validate_static_config(text, f"{PROJECT_DIR}/{PROXY_CONF_FILE}")
    return text


def render_tier(
    project: Project, tier: str, *, entries: list[str], subnet: str | None, allow_all: bool
) -> dict[str, str]:
    """The files of one tier; the filter comes first so it is complete before the config."""
    env = proxy.read_proxy_env(os.environ)
    for warning in env.warnings:
        eprint(f"warning: {warning}")
    files: dict[str, str] = {}
    filter_path = None
    if not allow_all:
        filter_path = f"{proxy.PROXY_DIR}/{tier}.filter"
        files[f"{tier}.filter"] = proxy.render_filter(entries, f"{tier} tier")
    upstream = proxy.upstream_lines(env, allow_all=allow_all, allowlist=entries)
    files[f"{tier}.conf"] = proxy.render_config(
        static_config(project), subnet=subnet, filter_path=filter_path, upstream=upstream
    )
    return files


def write_base_tier(engine: Engine, project: Project, subnet: str | None) -> list[str]:
    """Push the always-on tier (and a copy as the net tier while no `net` session runs)."""
    base, _ = read_allowlists(project)
    files = render_tier(project, "base", entries=base, subnet=subnet, allow_all=False)
    if active_deadline(project) is None:
        files |= render_tier(project, "net", entries=base, subnet=subnet, allow_all=False)
    push(engine, project, files)
    return base


def write_net_tier(
    engine: Engine,
    project: Project,
    subnet: str | None,
    extra_hosts: list[str],
    *,
    allow_all: bool,
) -> list[str]:
    base, extra = read_allowlists(project)
    entries = proxy.merge_entries(base, extra, extra_hosts)
    files = render_tier(project, "net", entries=entries, subnet=subnet, allow_all=allow_all)
    push(engine, project, files)
    return entries


# --- deadline: enforced by the proxy, mirrored on the host for the CLI ------------------


def read_deadline(project: Project) -> float | None:
    try:
        return float((runtime_path(project) / "deadline").read_text().strip())
    except (FileNotFoundError, ValueError):
        return None


def active_deadline(project: Project) -> float | None:
    deadline = read_deadline(project)
    return deadline if deadline is not None and deadline > time.time() else None


def write_deadline(engine: Engine, project: Project, deadline: float) -> None:
    push(engine, project, {"deadline": f"{int(deadline)}\n"})
    atomic_write(prepare_runtime(project) / "deadline", f"{int(deadline)}\n")


def clear_deadline(engine: Engine, project: Project) -> None:
    (runtime_path(project) / "deadline").unlink(missing_ok=True)
    if engine.exists("container", project.proxy_container):
        push(engine, project, {"deadline": "0\n"})


# --- proxy state ------------------------------------------------------------------------


def proxy_status(engine: Engine, project: Project) -> tuple[str, str] | None:
    """(tier, last reload nonce) as reported by the supervisor, or None if it is not serving."""
    result = engine.run(
        "exec", project.proxy_container, "cat", f"{proxy.PROXY_DIR}/state", check=False
    )
    if result.returncode != 0:
        return None
    tier, _, nonce = result.stdout.strip().partition(" ")
    return (tier, nonce) if tier else None


def proxy_state(engine: Engine, project: Project) -> str | None:
    status = proxy_status(engine, project)
    return status[0] if status else None


def wait_for_state(engine: Engine, project: Project, wanted: str, timeout: float = 8.0) -> bool:
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if proxy_state(engine, project) == wanted:
            return True
        time.sleep(0.3)
    return False


def request_reload(engine: Engine, project: Project, timeout: float = 8.0) -> bool:
    """Push a new nonce (after the configurations) and wait until the supervisor applied it."""
    nonce = str(time.time_ns())
    push(engine, project, {"reload": nonce + "\n"})
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        status = proxy_status(engine, project)
        if status and status[1] == nonce:
            return True
        time.sleep(0.3)
    return False


def tinyproxy_running(engine: Engine, project: Project) -> bool:
    result = engine.run("exec", project.proxy_container, "pidof", proxy.PROXY_BINARY, check=False)
    return result.returncode == 0


def wait_until_serving(engine: Engine, project: Project, timeout: float = 15.0) -> None:
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if proxy_status(engine, project) and tinyproxy_running(engine, project):
            return
        time.sleep(0.3)
    logs = engine.run("logs", "--tail", "20", project.proxy_container, check=False)
    raise SandboxError(
        "The proxy container did not become ready.\n" + (logs.stdout + logs.stderr).strip()
    )


def follow_log(engine: Engine, project: Project, since: float) -> subprocess.Popen[str]:
    """The proxy's container log (tinyproxy writes to stderr) from `since` on."""
    cmd = [*engine.base_cmd(), "logs", "--follow", "--since", f"{since:.3f}"]
    cmd.append(project.proxy_container)
    return subprocess.Popen(
        cmd,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        errors="replace",
    )
