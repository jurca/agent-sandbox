"""init, clone, ls, prune, rm-by-name, status, doctor and repair."""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path

from . import approval, proxyctl, setup, templates
from .config import (
    ALLOW_BASE_FILE,
    ALLOW_EXTRA_FILE,
    CONFIG_FILE,
    PROJECT_DIR,
    PROXY_CONF_FILE,
    load_user_config,
)
from .engine import Engine, probe_engines
from .images import host_uid_for, parse_uid_map
from .mounts import has_workspace_acl
from .net import owner_alive
from .project import (
    LABEL_HOME,
    LABEL_ID,
    LABEL_ROLE,
    LABEL_SPEC,
    LABEL_STATE_SCOPE,
    LABEL_WORKSPACE,
    Project,
    make_id,
)
from .proxy import PROXY_UID
from .sandbox import (
    Context,
    base_ref,
    compute_spec,
    container_home,
    make_plan,
    reclaim_workspace,
    remove_by_id,
    reset_volume_ownership,
    share_workspace,
    spec_hash,
)
from .util import SandboxError, confirm, eprint, format_duration, is_tty, state_dir

# --- init and clone ---------------------------------------------------------------------


def init_project(project: Project, image: str, *, force: bool = False) -> list[Path]:
    target = project.root / PROJECT_DIR
    files = {
        CONFIG_FILE: templates.render_config(image),
        PROXY_CONF_FILE: templates.TINYPROXY_CONF,
        ALLOW_BASE_FILE: templates.ALLOW_BASE,
        ALLOW_EXTRA_FILE: templates.ALLOW_EXTRA,
    }
    existing = [name for name in files if (target / name).exists()]
    if existing and not force:
        raise SandboxError(
            f"{PROJECT_DIR}/ already has {', '.join(existing)}. Use --force to overwrite."
        )
    target.mkdir(exist_ok=True)
    written = []
    for name, content in files.items():
        (target / name).write_text(content)
        written.append(target / name)
    approval.record(project)
    return written


def clone_repository(url: str, dest: str | None) -> Path:
    if shutil.which("git") is None:
        raise SandboxError("git is not installed.")
    dest = dest or clone_dir_name(url)
    cmd = ["git", "-c", "protocol.ext.allow=never", "clone", "--", url, dest]
    if subprocess.run(cmd, check=False).returncode != 0:
        raise SandboxError("git clone failed.")
    return Path(dest).resolve()


def clone_dir_name(url: str) -> str:
    """The directory `git clone URL` would pick."""
    path = url.rstrip("/").removesuffix("/.git").rstrip("/")
    name = re.split(r"[/:]", path)[-1].removesuffix(".git")
    if not name or name in (".", ".."):
        raise SandboxError(f"Cannot derive a directory name from {url!r}; pass DIR.")
    return name


# --- listing ----------------------------------------------------------------------------


@dataclass
class Workspace:
    id: str
    path: str | None
    engine: Engine
    containers: dict[str, str] = field(default_factory=dict)  # role -> status
    networks: list[str] = field(default_factory=list)
    volumes: list[str] = field(default_factory=list)

    def orphan_reason(self) -> str | None:
        if not self.path:
            return "no workspace path recorded"
        path = Path(self.path)
        if not path.is_dir():
            return "the workspace directory no longer exists"
        if not (path / ".git").exists():
            return "the directory is no longer a git working tree"
        if make_id(path) != self.id:
            return "the directory's identity no longer matches"
        return None

    @property
    def state(self) -> str:
        roles = self.containers
        if not roles:
            return "state only" if self.volumes else "empty"
        if roles.get("workspace") == "running":
            return "running"
        return "stopped" if "workspace" in roles else "incomplete"


def collect_workspaces(engines: list[Engine]) -> list[Workspace]:
    found: dict[tuple[str, str, bool], Workspace] = {}
    for engine in engines:
        for kind, key in (
            ("container", "containers"),
            ("network", "networks"),
            ("volume", "volumes"),
        ):
            for name in engine.list_names(kind, "agent-sandbox.managed=true"):
                labels = engine.labels(kind, name)
                if not labels or LABEL_ID not in labels:
                    continue
                if labels.get(LABEL_STATE_SCOPE, "per-workspace") != "per-workspace":
                    continue  # shared state volumes belong to no single workspace
                ident = (engine.kind, labels[LABEL_ID], engine.rootless)
                ws = found.setdefault(
                    ident, Workspace(labels[LABEL_ID], labels.get(LABEL_WORKSPACE), engine)
                )
                if kind == "container":
                    status = engine.container_status(name) or "unknown"
                    ws.containers[labels.get(LABEL_ROLE, "?")] = status
                else:
                    getattr(ws, key).append(name)
    return sorted(found.values(), key=lambda w: (w.path or "", w.id))


def list_workspaces() -> list[Workspace]:
    return collect_workspaces(probe_engines(load_user_config()))


def print_workspaces(workspaces: list[Workspace]) -> None:
    if not workspaces:
        print("No sandboxes found.")
        return
    rows = [("ID", "STATE", "ENGINE", "PATH", "NOTES")]
    for ws in workspaces:
        reason = ws.orphan_reason()
        notes = f"orphaned: {reason}" if reason else ""
        rows.append((ws.id, ws.state, ws.engine.mode, ws.path or "-", notes))
    widths = [max(len(row[i]) for row in rows) for i in range(4)]
    for row in rows:
        print("  ".join(row[i].ljust(widths[i]) for i in range(4)) + "  " + row[4])


def find_workspace(name: str, workspaces: list[Workspace]) -> Workspace:
    exact = [w for w in workspaces if w.id == name]
    matches = exact or [w for w in workspaces if w.id.startswith(name)]
    if not matches:
        raise SandboxError(f"No sandbox matches {name!r}. See `agent-sandbox ls`.")
    if len(matches) > 1:
        ids = ", ".join(w.id for w in matches)
        raise SandboxError(f"{name!r} is ambiguous: {ids}")
    return matches[0]


def remove_workspace(ws: Workspace, *, state: bool) -> list[str]:
    removed = remove_by_id(ws.engine, ws.id, state=state)
    if state:
        shutil.rmtree(state_dir() / "approved" / ws.id, ignore_errors=True)
    return removed


def prune(*, keep_state: bool = False) -> int:
    orphans = [w for w in list_workspaces() if w.orphan_reason()]
    if not orphans:
        print("No orphaned sandboxes.")
        return 0
    if not is_tty():
        raise SandboxError("prune asks for confirmation, so it needs an interactive terminal.")
    removed_count = 0
    for ws in orphans:
        print(f"\n{ws.id}  ({ws.engine.mode})")
        print(f"  path:   {ws.path or '-'}")
        print(f"  reason: {ws.orphan_reason()}")
        has = ", ".join(f"{r} {s}" for r, s in ws.containers.items()) or "no containers"
        print(f"  has:    {has}")
        if ws.volumes:
            what = "kept" if keep_state else "REMOVED"
            print(f"  state volumes ({what}): {', '.join(ws.volumes)}")
        if confirm(f"Remove sandbox {ws.id}?"):
            for item in remove_workspace(ws, state=not keep_state):
                print(f"  removed {item}")
            removed_count += 1
    print(f"\nRemoved {removed_count} of {len(orphans)} orphaned sandbox(es).")
    return 0


# --- status -----------------------------------------------------------------------------


def status(ctx: Context) -> None:
    engine, project = ctx.engine, ctx.project
    print(f"workspace:  {project.root}")
    print(f"id:         {project.id}")
    print(f"engine:     {engine.mode}")
    if ctx.config.devcontainer is not None:
        print(f"image:      devcontainer {ctx.config.devcontainer} ({base_ref(ctx)})")
    else:
        print(f"image:      {ctx.config.image}")
    print(
        f"config:     {'approved' if approval.is_approved(project) else 'NOT approved (will ask)'}"
    )
    for role, name in (
        ("workspace", project.workspace_container),
        ("proxy", project.proxy_container),
    ):
        print(f"{role + ':':11} {engine.container_status(name) or 'not created'} ({name})")
    state = proxyctl.proxy_state(engine, project)
    deadline = proxyctl.active_deadline(project)
    if state:
        extra = f", {format_duration(deadline - time.time())} left" if deadline else ""
        print(f"network:    {state} tier{extra}")
    info = engine.inspect("container", project.workspace_container)
    if info:
        labels = (info.get("Config") or {}).get("Labels") or {}
        try:
            plan = make_plan(ctx, labels.get(LABEL_HOME))
            current = spec_hash(compute_spec(ctx, plan, engine.image_id(base_ref(ctx))))
            drift = (
                "matches the configuration"
                if labels.get(LABEL_SPEC) == current
                else ("DIFFERS from the configuration; run `agent-sandbox recreate`")
            )
        except SandboxError as exc:
            drift = f"cannot be checked ({exc})"
        print(f"container:  {drift}")
        current = setup.session(ctx)
        done = setup.create_done(ctx, current, setup.plan_for(ctx, current))
        print(f"setup:      {'done' if done else 'pending (runs before the next harness start)'}")


# --- doctor -----------------------------------------------------------------------------

_DOCTOR_SCRIPT = r"""
probe() { ( exec 3<>"/dev/tcp/$1/$2" ) 2>/dev/null && echo yes || echo no; }
echo "direct=$(probe 1.1.1.1 443)"
echo "proxy=$(probe proxy 8888)"
if exec 3<>/dev/tcp/proxy/8888; then
  printf 'CONNECT agent-sandbox-doctor.invalid:443 HTTP/1.1\r\nHost: x\r\n\r\n' >&3
  read -r -t 5 line <&3
  echo "connect=$line"
fi 2>/dev/null
echo "sockets_begin"
find /tmp /run /var/run /dev/shm "$HOME" -xdev -type s 2>/dev/null | head -20
echo "sockets_end"
"""


def doctor(ctx: Context) -> int:
    engine, project = ctx.engine, ctx.project
    problems = 0

    def report(ok: bool, text: str, *, warn: bool = False) -> None:
        nonlocal problems
        label = "ok  " if ok else ("warn" if warn else "FAIL")
        problems += 0 if ok or warn else 1
        print(f"{label}  {text}")

    report(True, f"engine: {engine.mode}")
    if engine.kind == "docker" and engine.rootless:
        from .mounts import acl_tools_available

        report(acl_tools_available(), "setfacl is installed (needed to share the workspace)")
    if engine.container_status(project.workspace_container) != "running":
        print("note  sandbox is not running; start it with `agent-sandbox` for the live checks")
        return 1 if problems else 0

    if engine.kind == "docker" and engine.rootless:
        result = engine.run(
            "exec", project.workspace_container, "cat", "/proc/self/uid_map", check=False
        )
        mapping = parse_uid_map(result.stdout)
        if mapping:
            host_uid = host_uid_for(mapping, ctx.uid)
            if host_uid != os.getuid():
                report(
                    has_workspace_acl(project.root, host_uid),
                    f"workspace ACL grants host uid {host_uid} (the sandbox user) and you access"
                    " (if not: `agent-sandbox repair`)",
                )
    proxy_uid = engine.run("exec", project.proxy_container, "id", "-u", check=False).stdout.strip()
    proxy_mounts = (engine.inspect("container", project.proxy_container) or {}).get("Mounts")
    report(
        proxy_uid == str(PROXY_UID) and not proxy_mounts,
        f"the proxy runs unprivileged (uid {proxy_uid or '?'}) and has no host mounts",
    )
    probe = engine.run(
        "exec",
        "--user",
        f"{ctx.uid}:{ctx.gid}",
        project.workspace_container,
        "bash",
        "-c",
        _DOCTOR_SCRIPT,
        check=False,
    )
    values = dict(line.split("=", 1) for line in probe.stdout.splitlines() if "=" in line)
    if probe.returncode != 0 and not values:
        report(False, "could not run the network checks (bash is needed in the image)", warn=True)
    else:
        report(values.get("direct") == "no", "no direct route to the internet from the sandbox")
        report(values.get("proxy") == "yes", "the proxy is reachable from the sandbox")
        connect = values.get("connect", "")
        report(
            " 403 " in connect or " 502 " in connect or " 503 " in connect,
            f"a non-allowlisted host is refused by the proxy ({connect.strip() or 'no answer'})",
        )
    inside = probe.stdout.partition("sockets_begin")[2].partition("sockets_end")[0].split()
    report(
        not inside,
        "no unix sockets in /tmp, /run, /dev/shm or the home directory"
        + (f": {', '.join(inside)}" if inside else ""),
    )
    info = engine.inspect("container", project.workspace_container) or {}
    for mount in info.get("Mounts", []):
        source = str(mount.get("Source", ""))
        if source.endswith(".sock"):
            report(False, f"a socket is mounted into the sandbox: {source}")
    print(f"\n{'No problems found.' if not problems else f'{problems} problem(s) found.'}")
    return 1 if problems else 0


# --- repair -----------------------------------------------------------------------------


def repair(ctx: Context) -> None:
    engine, project = ctx.engine, ctx.project
    if not owner_alive(ctx):
        proxyctl.clear_deadline(engine, project)
    running = engine.container_status(project.workspace_container) == "running"
    acl = engine.kind == "docker" and engine.rootless
    if acl and not running:
        raise SandboxError("Start the sandbox first (`agent-sandbox`), then run repair.")
    if running:
        home = container_home(ctx)
        plan = make_plan(ctx, home)
        # First, so that the host owns (and may set ACLs on) what the sandbox user created.
        reclaimed, failed = reclaim_workspace(ctx, plan)
        if reclaimed or failed:
            eprint(
                f"Gave {reclaimed} workspace path(s) owned by the sandbox user back to you"
                + (f" ({failed} could not be changed)." if failed else ".")
            )
        if acl:
            result = engine.run("exec", project.workspace_container, "cat", "/proc/self/uid_map")
            host_uid = host_uid_for(parse_uid_map(result.stdout), ctx.uid)
            if host_uid != os.getuid():
                failed = share_workspace(ctx, plan, host_uid)
                eprint(f"Re-applied workspace ACLs ({failed} path(s) could not be changed).")
        info = engine.inspect("container", project.workspace_container) or {}
        reset_volume_ownership(ctx, plan, str(info.get("Image", "")))
        eprint("Reset ownership of the harness state and isolated volumes.")
    eprint("Done.")


def json_dump(data: object) -> str:
    return json.dumps(data, indent=2, sort_keys=True)
