"""Creating, starting, entering and removing a workspace sandbox."""

from __future__ import annotations

import contextlib
import fcntl
import getpass
import grp
import hashlib
import json
import os
import shlex
import shutil
import sys
from collections.abc import Generator
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from . import approval, proxyctl
from .config import (
    DEFAULT_PROXY_BASE_IMAGE,
    PROJECT_DIR,
    ProjectConfig,
    UserConfig,
    load_project_config,
    load_user_config,
)
from .engine import Engine, detect_engine
from .images import ensure_proxy_image, ensure_user_image, host_uid_for
from .mounts import (
    SOCKET_RISK,
    BindMount,
    VolumeMount,
    apply_acls,
    ensure_mountpoint,
    scan_for_sockets,
    validate_extra_mounts,
    workspace_path,
)
from .project import (
    LABEL_BASE_ID,
    LABEL_HOME,
    LABEL_SPEC,
    LABEL_SPEC_JSON,
    LABEL_STATE_SCOPE,
    GitLayout,
    Project,
    git_layout,
)
from .proxy import PROXY_ALIAS, PROXY_PORT, PROXY_UID
from .util import SandboxError, eprint, require_phrase, runtime_dir

SPEC_VERSION = 2
PROXY_URL = f"http://{PROXY_ALIAS}:{PROXY_PORT}"
ROOT_ACK_PHRASE = "I understand the risks"
STOP_TIMEOUT = "3"


@dataclass
class Context:
    project: Project
    config: ProjectConfig
    user: UserConfig
    engine: Engine
    uid: int
    gid: int
    username: str
    groupname: str
    umask: int

    @property
    def git_mode(self) -> str:
        return self.user.git_mode(self.project.root)

    @property
    def state_scope(self) -> str:
        return self.user.state_scope(self.project.root)

    @property
    def proxy_base_image(self) -> str:
        return (
            self.config.proxy_base_image or self.user.proxy_base_image or DEFAULT_PROXY_BASE_IMAGE
        )


def build_context(project: Project, engine: Engine | None = None) -> Context:
    if os.getuid() == 0:
        raise SandboxError("Refusing to run as root: the sandbox user must not be root.")
    user = load_user_config()
    config = load_project_config(project.root)
    umask = os.umask(0)
    os.umask(umask)
    return Context(
        project=project,
        config=config,
        user=user,
        engine=engine or detect_engine(user),
        uid=os.getuid(),
        gid=os.getgid(),
        username=getpass.getuser(),
        groupname=grp.getgrgid(os.getgid()).gr_name,
        umask=umask,
    )


@contextlib.contextmanager
def project_lock(project: Project) -> Generator[None]:
    path = runtime_dir() / f"{project.id}.lock"
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w") as handle:
        fcntl.flock(handle, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(handle, fcntl.LOCK_UN)


# --- desired state ----------------------------------------------------------------------


def ownership_mode(engine: Engine) -> str:
    if not engine.rootless:
        return "none"
    return "keep-id" if engine.kind == "podman" else "acl"


@dataclass
class Plan:
    layout: GitLayout
    mounts: list[BindMount]
    volumes: list[tuple[str, str]]  # (volume name, path relative to the home directory)
    isolated: list[tuple[str, str]]  # (volume name, absolute path inside the workspace)
    ownership: str


def make_plan(ctx: Context, home: str | None = None) -> Plan:
    """The desired mounts. The workspace keeps its host path inside the container, so paths
    in tool output, caches and harness state mean the same on both sides.

    `home` is the container user's home directory, for `~` in mount targets.
    """
    project, readonly = ctx.project, ctx.git_mode == "ro"
    root = project.root
    layout = git_layout(root)
    mounts = [
        BindMount(str(root), str(root), readonly=False),
        BindMount(str(layout.git_path), str(root / ".git"), readonly=readonly),
        BindMount(str(root / PROJECT_DIR), str(root / PROJECT_DIR), readonly=True),
    ]
    for rel in ctx.config.protected:
        path = workspace_path(root, rel)
        mounts.append(BindMount(str(path), str(path), readonly=True))
    mounts += [BindMount(str(d), str(d), readonly=readonly) for d in layout.external_dirs]
    mounts += validate_extra_mounts(
        ctx.config.mounts,
        Path.home(),
        workspace=root,
        container_home=home or f"/home/{ctx.username}",
    )
    volumes = [(project.state_volume(ctx.state_scope, rel), rel) for rel in ctx.config.state_paths]
    isolated = [
        (project.isolated_volume(rel), str(workspace_path(root, rel)))
        for rel in ctx.config.isolated
    ]
    return Plan(layout, mounts, volumes, isolated, ownership_mode(ctx.engine))


def compute_spec(ctx: Context, plan: Plan, base_id: str | None) -> dict[str, object]:
    return {
        "spec_version": SPEC_VERSION,
        "engine": ctx.engine.kind,
        "rootless": ctx.engine.rootless,
        "base_ref": ctx.config.image,
        "base_id": base_id or "missing",
        "user": ctx.username,
        "uid": ctx.uid,
        "gid": ctx.gid,
        "ownership": plan.ownership,
        "git": ctx.git_mode,
        "mounts": sorted([m.source, m.target, m.readonly] for m in plan.mounts),
        "state": [[name, rel] for name, rel in plan.volumes],
        "isolated": [[name, target] for name, target in plan.isolated],
        "network": ctx.project.network,
    }


def spec_hash(spec: dict[str, object]) -> str:
    return hashlib.sha256(json.dumps(spec, sort_keys=True).encode()).hexdigest()[:16]


def spec_differences(old: dict[str, object], new: dict[str, object]) -> list[str]:
    keys = sorted(set(old) | set(new))
    return [k for k in keys if old.get(k) != new.get(k)]


# --- mount safety -----------------------------------------------------------------------


def check_sockets(ctx: Context, plan: Plan, *, unsafe: bool) -> None:
    targets = [("the workspace", ctx.project.root)]
    targets += [
        (f"mount {m.target}", Path(m.source))
        for m in plan.mounts
        if not Path(m.source).is_relative_to(ctx.project.root)
    ]
    found: list[tuple[str, Path]] = []
    for label, path in targets:
        result = scan_for_sockets(path)
        found += [(label, sock) for sock in result.sockets]
        if not result.complete:
            eprint(
                f"note: scanning {label} for unix sockets stopped early after "
                f"{result.entries} entries; sockets deeper in the tree were not checked."
            )
    if not found:
        return
    listing = "\n".join(f"  {label}: {sock}" for label, sock in found[:20])
    if len(found) > 20:
        listing += f"\n  ... and {len(found) - 20} more"
    if not unsafe:
        raise SandboxError(
            f"Unix sockets found in mounted directories:\n{listing}\n\n{SOCKET_RISK}\n\n"
            "Remove the sockets (or stop the service that owns them), or override with "
            "--unsafely-mount-dirs-with-sockets."
        )
    eprint(f"WARNING: mounting directories that contain unix sockets:\n{listing}\n\n{SOCKET_RISK}")
    require_phrase(ROOT_ACK_PHRASE)


# --- creation ---------------------------------------------------------------------------


def _label_args(labels: dict[str, str]) -> list[str]:
    args: list[str] = []
    for key, value in labels.items():
        args += ["--label", f"{key}={value}"]
    return args


def _selinux_relabel(ctx: Context) -> bool:
    return ctx.engine.kind == "podman" and ctx.engine.selinux


def _remove_quietly(engine: Engine, kind: str, name: str) -> None:
    if kind == "container":
        engine.run("rm", "-f", name, check=False)
    else:
        engine.run(kind, "rm", name, check=False)


def _log_args(engine: Engine) -> list[str]:
    """A bounded container log: it carries the proxy's access log."""
    if engine.kind == "podman":
        return ["--log-driver", "k8s-file", "--log-opt", "max-size=10mb"]
    return ["--log-driver", "json-file", "--log-opt", "max-size=10m", "--log-opt", "max-file=2"]


def ensure_proxy_container(ctx: Context, proxy_image: str) -> bool:
    """Create the proxy (it holds no state), replacing one built from another image.

    Returns whether a container was created.
    """
    project, engine = ctx.project, ctx.engine
    info = engine.inspect("container", project.proxy_container)
    if info is not None:
        if info.get("Image") == engine.image_id(proxy_image):
            return False
        eprint("Replacing the proxy container (its image changed) ...")
        engine.run("rm", "-f", project.proxy_container)
    engine.run(
        "create", "--name", project.proxy_container, "--init",
        "--user", f"{PROXY_UID}:{PROXY_UID}", "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges", *_log_args(engine),
        *_label_args(project.labels("proxy")),
        proxy_image,
    )  # fmt: skip
    engine.run(
        "network", "connect", "--alias", PROXY_ALIAS, project.network, project.proxy_container
    )
    return True


def start_proxy(ctx: Context) -> None:
    """Make the proxy run with up-to-date tier configuration."""
    project, engine = ctx.project, ctx.engine
    subnet = engine.network_subnet(project.network)
    running = engine.container_status(project.proxy_container) == "running"
    if not running:
        proxyctl.clear_deadline(engine, project)  # a (re)started proxy begins on the base tier
    proxyctl.write_base_tier(engine, project, subnet)
    if running:
        if not proxyctl.request_reload(engine, project):
            raise SandboxError("The proxy did not pick up its new configuration.")
        return
    engine.run("start", project.proxy_container)
    proxyctl.wait_until_serving(engine, project)


def create_sandbox(ctx: Context, *, unsafe_sockets: bool = False) -> None:
    engine, project = ctx.engine, ctx.project
    image = ensure_user_image(
        engine, ctx.config.image, user=ctx.username, uid=ctx.uid, gid=ctx.gid, group=ctx.groupname
    )
    proxy_image = ensure_proxy_image(engine, ctx.proxy_base_image)
    plan = make_plan(ctx, image.home)
    check_sockets(ctx, plan, unsafe=unsafe_sockets)
    # Mount points inside the workspace; the engine would create missing ones itself, but
    # with root-owned results under a rootful engine.
    for rel in ctx.config.protected:
        ensure_mountpoint(ctx.project.root, rel, file_ok=True)
    for rel in ctx.config.isolated:
        ensure_mountpoint(ctx.project.root, rel, file_ok=False)

    if plan.ownership == "acl":
        failed = share_workspace(ctx, plan, host_uid_for(image.uid_map, ctx.uid))
        if failed:
            eprint(
                f"warning: {failed} path(s) in the workspace could not be given the sandbox "
                "user's access (not owned by you?)."
            )

    created: list[tuple[str, str]] = []
    try:
        base_labels = project.labels("network")
        if not engine.exists("network", project.network):
            engine.run(
                "network", "create", "--internal", *_label_args(base_labels), project.network
            )
            created.append(("network", project.network))
        for volume, _ in plan.volumes:
            if not engine.exists("volume", volume):
                labels = {**project.labels("state"), LABEL_STATE_SCOPE: ctx.state_scope}
                engine.run("volume", "create", *_label_args(labels), volume)
                created.append(("volume", volume))
        for volume, _ in plan.isolated:
            if not engine.exists("volume", volume):
                labels = {**project.labels("isolated"), LABEL_STATE_SCOPE: "per-workspace"}
                engine.run("volume", "create", *_label_args(labels), volume)
                created.append(("volume", volume))

        if ensure_proxy_container(ctx, proxy_image):
            created.append(("container", project.proxy_container))
        start_proxy(ctx)

        spec = compute_spec(ctx, plan, image.base_id)
        labels = {
            **project.labels("workspace"),
            LABEL_SPEC: spec_hash(spec),
            LABEL_SPEC_JSON: json.dumps(spec, sort_keys=True),
            LABEL_HOME: image.home,
            LABEL_BASE_ID: image.base_id,
        }
        args = [
            "create", "--name", project.workspace_container, "--hostname", project.hostname,
            "--user", f"{ctx.uid}:{ctx.gid}", "--init", "--workdir", str(project.root),
            "--network", project.network, "--security-opt", "no-new-privileges",
            "--entrypoint", "sleep", *_label_args(labels),
        ]  # fmt: skip
        if plan.ownership == "keep-id":
            args.append("--userns=keep-id")
        relabel = _selinux_relabel(ctx)
        for mount in plan.mounts:
            args += mount.engine_args(relabel=relabel and mount.target == str(project.root))
        for volume, rel in plan.volumes:
            args += VolumeMount(volume, str(PurePosixPath(image.home) / rel)).engine_args()
        for volume, target in plan.isolated:
            args += VolumeMount(volume, target).engine_args()
        args += [image.ref, "infinity"]
        engine.run(*args)
        created.append(("container", project.workspace_container))
        engine.run("start", project.workspace_container)
        fix_state_ownership(ctx, image.home)
    except BaseException:
        for kind, name in reversed(created):
            _remove_quietly(engine, kind, name)
        raise
    eprint(f"Created sandbox {project.workspace_container} ({engine.mode}).")


def share_workspace(ctx: Context, plan: Plan, host_uid: int) -> int:
    """ACLs for the sandbox user; git data is included only when it is mounted writable.

    Protected paths are mounted read-only and isolated ones are covered by volumes, so
    neither needs (or, for a large virtualenv, should pay for) ACLs.
    """
    if host_uid == os.getuid():
        return 0
    skip = (PROJECT_DIR, *ctx.config.protected, *ctx.config.isolated)
    if ctx.git_mode != "rw":
        return apply_acls(ctx.project.root, host_uid, skip=(".git", *skip))
    failed = apply_acls(ctx.project.root, host_uid, skip=skip)
    for git_dir in plan.layout.external_dirs:
        failed += apply_acls(git_dir, host_uid, skip=())
    return failed


def fix_state_ownership(ctx: Context, home: str) -> None:
    """Docker creates volume mount points owned by root; hand them to the sandbox user."""
    paths: list[str] = []
    for rel in ctx.config.state_paths:
        current = PurePosixPath(home)
        for part in PurePosixPath(rel).parts:
            current /= part
            if str(current) not in paths:
                paths.append(str(current))
    # Only the volume roots: their parents are workspace directories owned by the host user.
    paths += [str(ctx.project.root / rel) for rel in ctx.config.isolated]
    if not paths:
        return
    owner = f"{ctx.uid}:{ctx.gid}"
    ctx.engine.run(
        "exec", "--user", "0", ctx.project.workspace_container, "sh", "-c",
        'owner=$1; shift; for p; do chown "$owner" "$p"; done', "sh", owner, *paths,
    )  # fmt: skip


# --- attaching --------------------------------------------------------------------------


def ensure_ready(ctx: Context, *, unsafe_sockets: bool = False) -> None:
    """Approve the config, create the sandbox if needed, and make sure it is running."""
    engine, project = ctx.engine, ctx.project
    with project_lock(project):
        approval.ensure_approved(project)
        info = engine.inspect("container", project.workspace_container)
        if info is None:
            create_sandbox(ctx, unsafe_sockets=unsafe_sockets)
            return
        labels = (info.get("Config") or {}).get("Labels") or {}
        owner = labels.get("agent-sandbox.workspace")
        if owner != str(project.root):
            raise SandboxError(
                f"Container {project.workspace_container} belongs to {owner}, not to this "
                "directory. Remove it with `agent-sandbox ls` / `agent-sandbox rm NAME`."
            )
        plan = make_plan(ctx, labels.get(LABEL_HOME))
        spec = compute_spec(ctx, plan, engine.image_id(ctx.config.image))
        if labels.get(LABEL_SPEC) != spec_hash(spec):
            try:
                old = json.loads(labels.get(LABEL_SPEC_JSON, "{}"))
            except json.JSONDecodeError:
                old = {}
            changed = ", ".join(spec_differences(old, spec)) or "unknown"
            raise SandboxError(
                "The sandbox container no longer matches its configuration "
                f"(changed: {changed}).\nRun `agent-sandbox recreate` to apply it; the workspace "
                "files and harness state are kept."
            )
        if not engine.exists("network", project.network):
            raise SandboxError("The sandbox network is missing. Run `agent-sandbox recreate`.")
        state = (info.get("State") or {}).get("Status")
        if state != "running":
            eprint("Starting the sandbox ...")
        ensure_proxy_container(ctx, ensure_proxy_image(engine, ctx.proxy_base_image))
        start_proxy(ctx)
        if state != "running":
            engine.run("start", project.workspace_container)


# --- running things in the container ----------------------------------------------------


def container_home(ctx: Context) -> str:
    labels = ctx.engine.labels("container", ctx.project.workspace_container) or {}
    return labels.get(LABEL_HOME, f"/home/{ctx.username}")


def exec_env(ctx: Context, home: str) -> list[str]:
    values: dict[str, str] = {
        "HTTP_PROXY": PROXY_URL,
        "HTTPS_PROXY": PROXY_URL,
        "http_proxy": PROXY_URL,
        "https_proxy": PROXY_URL,
        "NO_PROXY": "localhost,127.0.0.1,::1",
        "no_proxy": "localhost,127.0.0.1,::1",
        "GIT_CONFIG_COUNT": "1",
        "GIT_CONFIG_KEY_0": "safe.directory",
        "GIT_CONFIG_VALUE_0": "*",
        "GIT_OPTIONAL_LOCKS": "0",
        "AGENT_SANDBOX": "1",
    }
    args: list[str] = []
    for key, value in values.items():
        args += ["-e", f"{key}={value}"]
    for name in ctx.config.env_pass:
        if name in os.environ:
            args += ["-e", name]
    for key, value in ctx.config.env_set.items():
        args += ["-e", f"{key}={value.replace('{home}', home)}"]
    return args


SHELL_FALLBACK = ["sh", "-c", "command -v bash >/dev/null 2>&1 && exec bash || exec sh"]

ROOT_BANNER = """\
================================ ROOT SHELL ================================
This is for setting up the container (installing packages, fixing files).
Do NOT start an agent harness here, and do not leave long-running work in it.
{mode_note}
=============================================================================
"""
ROOT_NOTE_ROOTLESS = (
    "Rootless engine: root here is your own host user on everything that is mounted\n"
    "(your workspace and any extra mounts), with extra capabilities inside the container."
)
ROOT_NOTE_ROOTFUL = (
    "ROOTFUL engine: root here can create root-owned and setuid files in your workspace,\n"
    "which are root-equivalent on the host once you run or open them there."
)


def _resolve_command(ctx: Context, command: list[str] | None, home: str) -> list[str]:
    if command:
        return command
    harness = ctx.config.harness
    if harness == "bash":
        return SHELL_FALLBACK
    try:
        words = shlex.split(harness)
    except ValueError as exc:
        raise SandboxError(f"Cannot parse harness {harness!r}: {exc}") from exc
    if not words:
        return SHELL_FALLBACK
    probe = ctx.engine.run(
        "exec", "--user", f"{ctx.uid}:{ctx.gid}", ctx.project.workspace_container,
        "sh", "-c", 'command -v "$1" >/dev/null 2>&1', "sh", words[0],
        check=False,
    )  # fmt: skip
    if probe.returncode != 0:
        eprint(
            f"The harness {words[0]!r} was not found in the container.\n"
            f"Set `harness` in {PROJECT_DIR}/config.toml (and install it in the image or via "
            "`agent-sandbox root`). Starting a shell instead."
        )
        return SHELL_FALLBACK
    return words


def run_in_container(ctx: Context, command: list[str] | None = None, *, root: bool = False) -> None:
    """Replace this process with `engine exec` into the workspace container."""
    home = container_home(ctx)
    tty = sys.stdin.isatty() and sys.stdout.isatty()
    args = ["exec", "-i"] + (["-t"] if tty else [])
    args += ["--user", "0" if root else f"{ctx.uid}:{ctx.gid}"]
    args += ["--workdir", str(ctx.project.root)]
    args += exec_env(ctx, home)
    if root:
        note = ROOT_NOTE_ROOTLESS if ctx.engine.rootless else ROOT_NOTE_ROOTFUL
        args += [
            "-e", f"AGENT_SANDBOX_BANNER={ROOT_BANNER.format(mode_note=note)}",
            "-e", "AGENT_SANDBOX_ROOT=1",
            "-e", r"PROMPT_COMMAND=PS1='\[\e[41;97m\] ROOT \[\e[0m\] \w # '",
        ]  # fmt: skip
        argv = ["sh", "-c", 'printf "%s" "$AGENT_SANDBOX_BANNER" >&2; exec "$@"', "sh"]
        argv += command or SHELL_FALLBACK
    else:
        argv = command_with_umask(_resolve_command(ctx, command, home), ctx.umask)
    ctx.engine.exec_replace([*args, ctx.project.workspace_container, *argv])


def command_with_umask(command: list[str], umask: int) -> list[str]:
    return ["sh", "-c", 'umask "$0"; exec "$@"', f"{umask:04o}", *command]


# --- stopping and removing --------------------------------------------------------------


def stop_sandbox(engine: Engine, project: Project) -> list[str]:
    stopped: list[str] = []
    for name in (project.workspace_container, project.proxy_container):
        if engine.container_status(name) == "running":
            engine.run("stop", "--time", STOP_TIMEOUT, name)
            stopped.append(name)
    return stopped


def is_per_workspace_volume(engine: Engine, name: str) -> bool:
    labels = engine.labels("volume", name) or {}
    return labels.get(LABEL_STATE_SCOPE, "per-workspace") == "per-workspace"


def remove_by_id(engine: Engine, sandbox_id: str, *, state: bool) -> list[str]:
    """Remove everything labelled with the given workspace id; returns what was removed."""
    selector = f"agent-sandbox.id={sandbox_id}"
    removed: list[str] = []
    for name in engine.list_names("container", selector):
        engine.run("rm", "-f", name)
        removed.append(f"container {name}")
    for name in engine.list_names("network", selector):
        engine.run("network", "rm", name)
        removed.append(f"network {name}")
    if state:
        for name in engine.list_names("volume", selector):
            if not is_per_workspace_volume(engine, name):
                eprint(f"Kept shared state volume {name} (other workspaces may use it).")
                continue
            engine.run("volume", "rm", name)
            removed.append(f"volume {name}")
    shutil.rmtree(runtime_dir() / sandbox_id, ignore_errors=True)
    return removed
