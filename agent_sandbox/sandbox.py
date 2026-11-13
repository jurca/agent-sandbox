"""Creating, starting, entering and removing a workspace sandbox."""

from __future__ import annotations

import contextlib
import fcntl
import getpass
import grp
import hashlib
import json
import os
import shutil
import sys
from collections.abc import Generator
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

from . import approval, devcontainer, proxyctl, secretfiles
from .config import (
    DEFAULT_PROXY_BASE_IMAGE,
    DOCKERFILE,
    PROJECT_DIR,
    STANDARD_FILES,
    ProjectConfig,
    UserConfig,
    load_project_config,
    load_user_config,
)
from .engine import Engine, detect_engine, labels_of
from .images import (
    UserImage,
    ensure_extension_image,
    ensure_proxy_image,
    ensure_user_image,
    host_uid_for,
    project_tag,
)
from .mounts import (
    SOCKET_RISK,
    BindMount,
    VolumeMount,
    apply_acls,
    batches,
    ensure_mountpoint,
    foreign_paths,
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
from .util import SandboxError, eprint, require_phrase, runtime_dir, state_dir

SPEC_VERSION = 2
# Engines keep the writable layer across stop/start; a tmpfs gives every start an empty /tmp.
# `exec` because Podman defaults to `noexec`; no `size=` (the kernel default is half of RAM).
TMP_TMPFS = "/tmp:rw,exec,nosuid,nodev,mode=1777"
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
    def harness(self) -> list[list[str]]:
        """The user's preferred harnesses first, then the project's, without duplicates."""
        candidates: list[list[str]] = []
        for words in [*self.user.harness_preference(self.project.root), *self.config.harness]:
            if words not in candidates:
                candidates.append(words)
        return candidates

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


# --- the image ------------------------------------------------------------------------


def base_ref(ctx: Context) -> str:
    """The image the user layer goes on: `image`, or the devcontainer build of the approved
    `.devcontainer/` tree (named after its content, so it is known without building)."""
    if ctx.config.devcontainer is not None:
        return devcontainer.image_tag(ctx.project, ctx.username)
    assert ctx.config.image is not None
    return ctx.config.image


def extension_digest(ctx: Context) -> str | None:
    """The `.agent-sandbox/` content an extension build sees, or None without a Dockerfile.

    The toolkit's own files are left out: they never change the image.
    """
    files = approval.tree_files(ctx.project.root / PROJECT_DIR)
    if DOCKERFILE not in files:
        return None
    return approval.tree_hash({k: v for k, v in files.items() if k not in STANDARD_FILES})


def workspace_image(ctx: Context, *, rebuild: bool = False, pull: bool = False) -> UserImage:
    """Base (image or devcontainer build), user layer, then `.agent-sandbox/Dockerfile`."""
    engine, remote_user, user_tag = ctx.engine, None, None
    if ctx.config.devcontainer is not None:
        ref = devcontainer.ensure_image(
            engine, ctx.user, ctx.project, ctx.config.devcontainer,
            username=ctx.username, rebuild=rebuild, pull=pull,
        )  # fmt: skip
        user_tag = project_tag(ctx.username, ctx.project.id, "user", ref.rpartition(":")[2])
        info = engine.inspect("image", ref) or {}
        metadata = devcontainer.parse_metadata(labels_of("image", info))
        image_user = (info.get("Config") or {}).get("User")
        remote_user = devcontainer.remote_user(metadata, image_user)
        pull = False  # a local image
    else:
        ref = base_ref(ctx)
        if "@sha256:" not in ref:
            eprint(f"warning: {PROJECT_DIR}/config.toml: {devcontainer.unpinned_warning(ref)}")
    image = ensure_user_image(
        engine, ref, user=ctx.username, uid=ctx.uid, gid=ctx.gid, group=ctx.groupname,
        rebuild=rebuild, pull=pull, remote_user=remote_user, tag=user_tag,
    )  # fmt: skip
    digest = extension_digest(ctx)
    if digest is not None:
        image = ensure_extension_image(
            engine, image, ctx.project.root / PROJECT_DIR,
            user=ctx.username, project_id=ctx.project.id, digest=digest, rebuild=rebuild,
        )  # fmt: skip
    return image


def compute_spec(ctx: Context, plan: Plan, base_id: str | None) -> dict[str, object]:
    spec: dict[str, object] = {
        "spec_version": SPEC_VERSION,
        "engine": ctx.engine.kind,
        "rootless": ctx.engine.rootless,
        "base_ref": base_ref(ctx),
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
        "tmp": "tmpfs",
    }
    # Only when used, so containers created before these existed keep their hash.
    if (digest := extension_digest(ctx)) is not None:
        spec["dockerfile"] = digest
    return spec


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
        if m.scan_sockets and not Path(m.source).is_relative_to(ctx.project.root)
    ]
    found: list[tuple[str, Path]] = []
    for label, path in targets:
        result = scan_for_sockets(path)
        found += [(label, sock) for sock in result.sockets]
        if not result.complete:
            hint = (
                ""
                if path == ctx.project.root
                else (" For a [[mounts]] entry, `check_sockets = false` skips the scan.")
            )
            eprint(
                f"note: scanning {label} for unix sockets stopped early after "
                f"{result.entries} entries; sockets deeper in the tree were not checked.{hint}"
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
    image = workspace_image(ctx)
    if ctx.config.devcontainer is not None:
        metadata = devcontainer.parse_metadata(engine.labels("image", image.ref) or {})
        for message in devcontainer.not_applied(metadata):
            eprint(f"warning: {message}")
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
                "user's access (not owned by you?). If an earlier sandbox created them, run "
                "`agent-sandbox repair` once this one is running."
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
            "--tmpfs", TMP_TMPFS, "--entrypoint", "sleep", *_label_args(labels),
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
    return sum(apply_acls(root, host_uid, skip=skip) for root, skip in shared_trees(ctx, plan))


def shared_trees(ctx: Context, plan: Plan) -> list[tuple[Path, tuple[str, ...]]]:
    """Host trees the sandbox user may write, each with the paths (relative to it) to skip."""
    skip = (PROJECT_DIR, *ctx.config.protected, *ctx.config.isolated)
    if ctx.git_mode != "rw":
        return [(ctx.project.root, (".git", *skip))]
    return [(ctx.project.root, skip), *((d, ()) for d in plan.layout.external_dirs)]


# `find -maxdepth 0` tests each listed path itself (never its contents) as the container sees
# it and does not follow symlinks; `chown -h` changes a symlink, not its target. Prints what
# it changed so the caller knows which unreadable directories may be listable now.
_RECLAIM = r"""
uid=$1 gid=$2 to_uid=$3 to_gid=$4; shift 4
find "$@" -maxdepth 0 -user "$uid" -print -exec chown -h "$to_uid" {} +
find "$@" -maxdepth 0 -group "$gid" -print -exec chown -h ":$to_gid" {} +
"""


def reclaim_workspace(ctx: Context, plan: Plan) -> tuple[int, int]:
    """Hand workspace files owned by the sandbox user back to the host user.

    Only a file's owner may change its ACL, so files the sandbox user owns (created or replaced
    in the sandbox) are out of reach for `apply_acls` on the host. The ids are observed instead
    of computed from /proc/self/uid_map, which is relative to the parent user namespace (podman's
    own one for rootless podman): `.agent-sandbox` is owned by the host user and read-only
    inside, so its owner as `stat` reports it inside the container is the host user's id there.
    Returns (paths reclaimed, failures).
    """
    engine, project = ctx.engine, ctx.project
    reference = project.root / PROJECT_DIR
    info = reference.lstat()
    if info.st_uid != os.getuid():
        raise SandboxError(f"{reference} is not owned by you; cannot tell whom to give files to.")
    seen = engine.run("exec", project.workspace_container, "stat", "-c", "%u %g", str(reference))
    to_uid, to_gid = (int(part) for part in seen.stdout.split())
    if to_uid == ctx.uid:
        # The sandbox user is the host user (rootful, keep-id); the group alone (a setgid
        # project directory) is no reason to touch the user's own files.
        return 0, 0
    trees = shared_trees(ctx, plan)
    attempted: set[str] = set()
    reclaimed = failed = 0
    while True:
        # A reclaimed directory the host could not read before may reveal more files.
        pending = [
            path
            for root, skip in trees
            for path in foreign_paths(root, frozenset(skip), info.st_uid, info.st_gid)
            if path not in attempted
        ]
        if not pending:
            break
        attempted.update(pending)
        changed: set[str] = set()
        for batch in batches(pending):
            result = engine.run(
                "exec", "--user", "0", project.workspace_container, "sh", "-c", _RECLAIM,
                "sh", str(ctx.uid), str(ctx.gid), str(to_uid), str(to_gid), *batch,
                check=False,
            )  # fmt: skip
            changed.update(line for line in result.stdout.splitlines() if line)
            failed += len([line for line in result.stderr.splitlines() if line.strip()])
        if not changed:
            break
        reclaimed += len(changed)
    return reclaimed, failed


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
        secretfiles.enforce(project.root, project.id, ctx.config, history=info is None)
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
        spec = compute_spec(ctx, plan, engine.image_id(base_ref(ctx)))
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


@dataclass
class Session:
    """What execs as the sandbox user need to know about the running container."""

    home: str
    labels: dict[str, str]
    container_id: str
    started_at: str
    image_env: dict[str, str]

    @property
    def metadata(self) -> list[dict[str, Any]]:
        return devcontainer.parse_metadata(self.labels)


def session(ctx: Context) -> Session:
    info = ctx.engine.inspect("container", ctx.project.workspace_container) or {}
    labels = labels_of("container", info)  # includes the image's labels
    env = dict(item.partition("=")[::2] for item in (info.get("Config") or {}).get("Env") or [])
    return Session(
        home=labels.get(LABEL_HOME, f"/home/{ctx.username}"),
        labels=labels,
        container_id=str(info.get("Id", "")),
        started_at=str((info.get("State") or {}).get("StartedAt", "")),
        image_env=env,
    )


def substitution(ctx: Context, current: Session) -> devcontainer.Substitution:
    return devcontainer.Substitution(
        workspace=ctx.project.root,
        devcontainer_id=ctx.project.id,
        env_pass=ctx.config.env_pass,
        container_env=current.image_env,
    )


def remote_env(ctx: Context, current: Session) -> dict[str, str]:
    """The devcontainer's remoteEnv with its variables resolved (null unsets: left out)."""
    if ctx.config.devcontainer is None:
        return {}
    subst = substitution(ctx, current)
    return {
        key: subst.text(value)
        for key, value in devcontainer.remote_env(current.metadata).items()
        if value is not None
    }


DEFAULT_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"


def user_path(path: str, home: str) -> str:
    """`path` with the user's `~/.local/bin` in front (where the profile would put it)."""
    entry = f"{home}/.local/bin"
    parts = [p for p in path.split(":") if p]
    return path if entry in parts else ":".join([entry, *parts])


def exec_env(
    ctx: Context, home: str, extra: dict[str, str] | None = None, *, path: str | None = None
) -> list[str]:
    """Environment arguments; `extra` (remoteEnv) never overrides the toolkit's own variables
    or the configured ones. With `path` (the container's PATH), `PATH` gets `~/.local/bin` in
    front, of remoteEnv's PATH if it has one; a configured PATH is left alone."""
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
    configured = set(ctx.config.env_set) | {n for n in ctx.config.env_pass if n in os.environ}
    if path is not None and "PATH" not in configured:
        values["PATH"] = user_path((extra or {}).get("PATH") or path or DEFAULT_PATH, home)
    args: list[str] = []
    for key, value in values.items():
        args += ["-e", f"{key}={value}"]
    for key, value in (extra or {}).items():
        if key not in values and key not in configured:
            args += ["-e", f"{key}={value}"]
    for name in ctx.config.env_pass:
        if name in os.environ:
            args += ["-e", name]
    for key, value in ctx.config.env_set.items():
        args += ["-e", f"{key}={value.replace('{home}', home)}"]
    return args


PROBE_FLAGS = {"loginShell": "-lc", "interactiveShell": "-ic", "loginInteractiveShell": "-lic"}
PROBE_TIMEOUT = 10  # seconds, where the container has `timeout`
# Variables of the probing shell itself, not of the user's environment.
PROBE_IGNORED = frozenset({"PWD", "OLDPWD", "SHLVL", "_"})
# Fixed, so probe output is recognizable; the environment is taken from its first to its last
# occurrence, so a value that contains it (or rc output after the probe) cannot cut it short.
PROBE_MARKER = "--agent-sandbox--user-env-probe--"
PROBE_COMMAND = f"printf %s '{PROBE_MARKER}'; cat /proc/self/environ; printf %s '{PROBE_MARKER}'"

# The user's login shell from /etc/passwd (bash, else sh, if it has none or a nologin one) runs
# the command in $2 (PROBE_COMMAND) with the flags in $1.
_PROBE = r"""
shell=$(awk -F: -v u="$(id -u)" '$3 == u { print $7; exit }' /etc/passwd 2>/dev/null)
case $shell in ""|*/nologin|*/false) shell= ;; esac
if [ -z "$shell" ] || [ ! -x "$shell" ]; then
  if command -v bash >/dev/null 2>&1; then shell=bash; else shell=sh; fi
fi
if command -v timeout >/dev/null 2>&1; then exec timeout "$0" "$shell" "$1" "$2"; fi
exec "$shell" "$1" "$2"
"""


def probe_user_env(ctx: Context, current: Session) -> dict[str, str]:
    """The environment the user's shell sets up (devcontainer `userEnvProbe`): what Features
    and setup commands add in rc files (`/etc/bash.bashrc`, `~/.bashrc`, `/etc/profile.d`).
    Only what differs from the image's environment is returned; a failed probe warns and
    returns nothing."""
    mode = (
        devcontainer.user_env_probe(current.metadata)
        if ctx.config.devcontainer is not None
        else devcontainer.DEFAULT_USER_ENV_PROBE
    )
    flags = PROBE_FLAGS.get(mode)
    if flags is None:
        return {}
    env = exec_env(ctx, current.home, path=current.image_env.get("PATH", ""))
    result = ctx.engine.run(
        "exec", "--user", f"{ctx.uid}:{ctx.gid}", "--workdir", str(ctx.project.root), *env,
        ctx.project.workspace_container, "sh", "-c", _PROBE, str(PROBE_TIMEOUT), flags,
        PROBE_COMMAND,
        check=False,
    )  # fmt: skip
    out = result.stdout or ""
    start, end = out.find(PROBE_MARKER), out.rfind(PROBE_MARKER)
    if result.returncode != 0 or start == end:  # also when it is not there at all (-1)
        hint = (
            ' Set "userEnvProbe": "none" in devcontainer.json to skip the probe.'
            if ctx.config.devcontainer is not None
            else ""
        )
        eprint(
            f"warning: probing the user's shell environment ({mode}) failed (exit code "
            f"{result.returncode}); what rc files add (e.g. to PATH) is missing.{hint}"
        )
        return {}
    found: dict[str, str] = {}
    for entry in out[start + len(PROBE_MARKER) : end].split("\0"):
        key, sep, value = entry.partition("=")
        if sep and key and key not in PROBE_IGNORED and current.image_env.get(key) != value:
            found[key] = value
    return found


def merge_paths(shell_path: str, container_path: str) -> str:
    """The shell's PATH with the container's entries it dropped put back in place (a login
    shell's `/etc/profile` resets PATH on Debian and Alpine), like the devcontainers CLI."""
    result = [p for p in shell_path.split(":") if p]
    insert_at = 0
    for entry in dict.fromkeys(p for p in container_path.split(":") if p):
        if entry in result:
            insert_at = result.index(entry) + 1
        else:
            result.insert(insert_at, entry)
            insert_at += 1
    return ":".join(result)


def user_exec_env(ctx: Context, current: Session) -> list[str]:
    """Environment arguments for the sandbox user: the image's environment, then the probed
    one, then remoteEnv, then the toolkit's own and the configured variables."""
    probed = probe_user_env(ctx, current)
    path = current.image_env.get("PATH", "")
    if "PATH" in probed:
        path = merge_paths(probed.pop("PATH"), path or DEFAULT_PATH)
    return exec_env(ctx, current.home, {**probed, **remote_env(ctx, current)}, path=path)


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


# Prints the index of the first argument that is an installed command.
_FIRST_INSTALLED = (
    'i=0; for c; do command -v "$c" >/dev/null 2>&1 && { echo "$i"; exit 0; }; i=$((i+1)); done;'
    " exit 1"
)


def _resolve_command(ctx: Context, command: list[str] | None, env: list[str]) -> list[str]:
    if command:
        return command
    candidates = ctx.harness
    probe = ctx.engine.run(
        "exec", "--user", f"{ctx.uid}:{ctx.gid}", *env, ctx.project.workspace_container,
        "sh", "-c", _FIRST_INSTALLED, "sh", *(words[0] for words in candidates),
        check=False,
    )  # fmt: skip
    if probe.returncode == 0:
        with contextlib.suppress(ValueError, IndexError):
            return candidates[int(probe.stdout.strip())]
    names = ", ".join(repr(words[0]) for words in candidates)
    eprint(
        f"No harness was found in the container (tried {names}).\n"
        f"Set `harness` in {PROJECT_DIR}/config.toml or in the user configuration (and install "
        "it in the image or via `agent-sandbox root`). Starting a shell instead."
    )
    return SHELL_FALLBACK


def run_in_container(ctx: Context, command: list[str] | None = None, *, root: bool = False) -> None:
    """Replace this process with `engine exec` into the workspace container."""
    current = session(ctx)
    home = current.home
    tty = sys.stdin.isatty() and sys.stdout.isatty()
    args = ["exec", "-i"] + (["-t"] if tty else [])
    args += ["--user", "0" if root else f"{ctx.uid}:{ctx.gid}"]
    args += ["--workdir", str(ctx.project.root)]
    if root:
        args += exec_env(ctx, home)
        note = ROOT_NOTE_ROOTLESS if ctx.engine.rootless else ROOT_NOTE_ROOTFUL
        args += [
            "-e", f"AGENT_SANDBOX_BANNER={ROOT_BANNER.format(mode_note=note)}",
            "-e", "AGENT_SANDBOX_ROOT=1",
            "-e", r"PROMPT_COMMAND=PS1='\[\e[41;97m\] ROOT \[\e[0m\] \w # '",
        ]  # fmt: skip
        argv = ["sh", "-c", 'printf "%s" "$AGENT_SANDBOX_BANNER" >&2; exec "$@"', "sh"]
        argv += command or SHELL_FALLBACK
    else:
        env = user_exec_env(ctx, current)
        args += env
        argv = command_with_umask(_resolve_command(ctx, command, env), ctx.umask)
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
    if state:
        (state_dir() / "setup" / f"{sandbox_id}.json").unlink(missing_ok=True)
        secretfiles.forget_rotated(sandbox_id)
    return removed
