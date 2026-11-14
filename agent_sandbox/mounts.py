"""Mount specifications, mount safety checks and file ownership for bind mounts."""

from __future__ import annotations

import os
import shutil
import stat
import subprocess
import time
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

from .config import PROJECT_DIR, MountSpec
from .util import SandboxError, config_dir, runtime_dir, state_dir

ACL_BATCH = 200
# How much of an extra mount's tree the socket and secret file scans look at, each.
SCAN_MAX_ENTRIES = 50_000
SCAN_MAX_SECONDS = 5.0


@dataclass(frozen=True)
class BindMount:
    source: str
    target: str
    readonly: bool = True
    # False skips the unix socket scan of the source (a `check_sockets = false` extra mount).
    scan_sockets: bool = True

    def engine_args(self, *, relabel: bool = False) -> list[str]:
        for part in (self.source, self.target):
            if "," in part or '"' in part:
                raise SandboxError(f"Mount path {part!r} contains a comma or quote; not supported.")
        spec = f"type=bind,src={self.source},dst={self.target}"
        if self.readonly:
            spec += ",readonly"
        if relabel:
            spec += ",relabel=shared"
        return ["--mount", spec]


@dataclass(frozen=True)
class VolumeMount:
    name: str
    target: str

    def engine_args(self) -> list[str]:
        return ["--mount", f"type=volume,src={self.name},dst={self.target}"]


def sensitive_paths(home: Path) -> list[Path]:
    """Trees that must stay unreachable; mounting one, a part of it or a parent is refused."""
    fixed = ["/proc", "/sys", "/dev", "/run", "/var/run", "/etc/shadow"]
    under_home = [".ssh", ".gnupg", ".aws", ".kube", ".docker", ".netrc", ".config/gcloud",
                  ".config/gh", ".config/agent-sandbox", ".local/state/agent-sandbox"]  # fmt: skip
    paths = [Path(p) for p in fixed] + [home / rel for rel in under_home]
    paths += [config_dir(), state_dir(), runtime_dir()]
    resolved = []
    for path in paths:
        try:
            resolved.append(path.resolve())
        except OSError:
            resolved.append(path)
    return resolved


def expand_home(target: str, container_home: str) -> str:
    """`~` and `{home}` at the start of a mount target mean the container user's home."""
    for prefix in ("~", "{home}"):
        if target == prefix or target.startswith(prefix + "/"):
            return str(PurePosixPath(container_home + target[len(prefix) :]))
    return target


def validate_extra_mounts(
    specs: Iterable[MountSpec], home: Path, *, workspace: Path, container_home: str
) -> list[BindMount]:
    sensitive = sensitive_paths(home)
    root = PurePosixPath(workspace)
    mounts: list[BindMount] = []
    for spec in specs:
        source = Path(spec.source)
        if not source.exists():
            raise SandboxError(f"Mount source {spec.source} does not exist on this host.")
        resolved = source.resolve()
        mode = resolved.stat().st_mode
        if stat.S_ISSOCK(mode) or stat.S_ISBLK(mode) or stat.S_ISCHR(mode):
            raise SandboxError(f"Mount source {spec.source} is a socket or device; refusing.")
        for protected in sensitive:
            if (
                resolved == protected
                or protected in resolved.parents
                or resolved in protected.parents
            ):
                raise SandboxError(
                    f"Mount source {spec.source} would expose {protected} to the sandbox; refusing."
                )
        target = PurePosixPath(expand_home(spec.target, container_home))
        if target == root or root in target.parents:
            raise SandboxError(f"Mount target {target} is inside the workspace {root}; refusing.")
        if target in root.parents:
            raise SandboxError(f"Mount target {target} would cover the workspace {root}; refusing.")
        mounts.append(
            BindMount(str(resolved), str(target), readonly=True, scan_sockets=spec.check_sockets)
        )
    return mounts


def workspace_path(root: Path, rel: str) -> Path:
    """`root/rel`, refusing symlinks on the way: a mount there would leave the workspace."""
    path = root
    for part in PurePosixPath(rel).parts:
        path /= part
        if path.is_symlink():
            raise SandboxError(f"{path} is a symlink; refusing to mount over it.")
    return path


def ensure_mountpoint(root: Path, rel: str, *, file_ok: bool) -> Path:
    """`root/rel`, created as an empty directory when missing."""
    path = workspace_path(root, rel)
    if not path.exists():
        path.mkdir(parents=True)
    elif not path.is_dir() and not file_ok:
        raise SandboxError(f"{path} exists but is not a directory.")
    return path


# --- sockets ----------------------------------------------------------------------------


@dataclass
class ScanResult:
    sockets: list[Path] = field(default_factory=list)
    complete: bool = True
    entries: int = 0


def scan_for_sockets(
    root: Path, *, max_entries: int = SCAN_MAX_ENTRIES, max_seconds: float = SCAN_MAX_SECONDS
) -> ScanResult:
    """Find unix sockets below `root` without following symlinks, within a budget."""
    result = ScanResult()
    deadline = time.monotonic() + max_seconds
    stack = [root]
    while stack:
        current = stack.pop()
        try:
            if stat.S_ISSOCK(current.lstat().st_mode):
                result.sockets.append(current)
                continue
            if not current.is_dir() or current.is_symlink():
                continue
            with os.scandir(current) as entries:
                for entry in entries:
                    result.entries += 1
                    if result.entries >= max_entries or (
                        result.entries % 256 == 0 and time.monotonic() > deadline
                    ):
                        result.complete = False
                        return result
                    path = Path(entry.path)
                    try:
                        mode = entry.stat(follow_symlinks=False).st_mode
                    except OSError:
                        continue
                    if stat.S_ISSOCK(mode):
                        result.sockets.append(path)
                    elif stat.S_ISDIR(mode):
                        stack.append(path)
        except OSError:
            continue
    return result


@dataclass
class RootFileScan:
    root_owned: list[Path] = field(default_factory=list)  # directories and files, not symlinks
    set_id: list[Path] = field(default_factory=list)  # regular files with setuid or setgid
    complete: bool = True
    entries: int = 0


def scan_for_root_files(
    root: Path,
    exclude: Iterable[str] = (),
    *,
    owner: int = 0,
    max_entries: int = SCAN_MAX_ENTRIES,
    max_seconds: float = SCAN_MAX_SECONDS,
) -> RootFileScan:
    """Paths below `root` (minus `exclude`, relative to it) owned by `owner` (root), and regular
    files with setuid/setgid, within a budget; symlinks are not followed. Setgid directories are
    left out: shared project directories use them to keep their group."""
    skipped = frozenset(exclude)
    result = RootFileScan()
    deadline = time.monotonic() + max_seconds
    stack = [root]
    while stack:
        current = stack.pop()
        try:
            with os.scandir(current) as entries:
                for entry in entries:
                    result.entries += 1
                    if result.entries >= max_entries or (
                        result.entries % 256 == 0 and time.monotonic() > deadline
                    ):
                        result.complete = False
                        return result
                    path = Path(entry.path)
                    if path.relative_to(root).as_posix() in skipped:
                        continue
                    try:
                        info = entry.stat(follow_symlinks=False)
                    except OSError:
                        continue
                    if stat.S_ISLNK(info.st_mode):
                        continue
                    if info.st_uid == owner:
                        result.root_owned.append(path)
                    if stat.S_ISREG(info.st_mode) and info.st_mode & (stat.S_ISUID | stat.S_ISGID):
                        result.set_id.append(path)
                    elif stat.S_ISDIR(info.st_mode):
                        stack.append(path)
        except OSError:
            continue
    return result


SOCKET_RISK = (
    "Unix sockets inside a mounted directory stay connectable from the sandbox even when the "
    "mount is read-only. A socket can be an SSH agent, a docker or desktop session, an IDE or "
    "editor server - anything that grants capabilities beyond the files themselves."
)


# --- ownership --------------------------------------------------------------------------


def acl_tools_available() -> bool:
    return shutil.which("setfacl") is not None


def _walk_for_acls(root: Path, exclude: frozenset[str]) -> tuple[list[str], list[str]]:
    """Directories and regular files below `root`, minus `exclude` (paths relative to root).

    Symlinks are neither listed nor followed. A directory that cannot be read is listed (its
    owner may still change its ACL) but its contents are not.
    """
    dirs: list[str] = [str(root)]
    files: list[str] = []
    for current, dirnames, filenames in os.walk(root, followlinks=False):
        rel = os.path.relpath(current, root)
        prefix = "" if rel == "." else rel + "/"
        dirnames[:] = [
            d
            for d in dirnames
            if prefix + d not in exclude and not os.path.islink(os.path.join(current, d))
        ]
        dirs.extend(os.path.join(current, d) for d in dirnames)
        for name in filenames:
            if prefix + name in exclude:
                continue
            path = os.path.join(current, name)
            try:
                if stat.S_ISREG(os.lstat(path).st_mode):
                    files.append(path)
            except OSError:
                continue
    return dirs, files


def foreign_paths(root: Path, exclude: frozenset[str], uid: int, gid: int) -> list[str]:
    """Directories and regular files below `root` not owned by `uid` or not in group `gid`.

    Same selection as the ACL walk (`exclude` relative to root, symlinks never followed).
    """
    dirs, files = _walk_for_acls(root, exclude)
    found: list[str] = []
    for path in [*dirs, *files]:
        try:
            info = os.lstat(path)
        except OSError:
            continue
        if info.st_uid != uid or info.st_gid != gid:
            found.append(path)
    return found


def batches(items: list[str]) -> Iterator[list[str]]:
    for start in range(0, len(items), ACL_BATCH):
        yield items[start : start + ACL_BATCH]


def apply_acls(
    root: Path,
    container_host_uid: int,
    *,
    skip: Iterable[str] = (".git", PROJECT_DIR),
    my_uid: int | None = None,
) -> int:
    """Give the container user (as a host uid) access to the workspace through ACLs.

    Rootless docker maps container uid N to a sub-uid, so plain ownership cannot work.
    The ACLs are symmetric: both users are named in the access ACL of every path and in the
    default ACL of every directory. Files created later by either side inherit both, and a
    file the sandbox replaces (temp file + copied ACL + rename, as `sed -i` does) still names
    the host user although the sub-uid owns it now. `.git` and the config directory are
    skipped by default: they stay owned by the host user, which makes them read-only for the
    container user. `skip` holds paths relative to `root`.

    Returns the number of paths setfacl could not change (e.g. files you do not own).
    """
    me = os.getuid() if my_uid is None else my_uid
    if not acl_tools_available():
        raise SandboxError(
            "setfacl is not installed. Rootless docker needs it to share the workspace with "
            "the container user (apt install acl), or use podman with --userns=keep-id."
        )
    dirs, files = _walk_for_acls(root, frozenset(skip))
    failed = 0
    users = (container_host_uid, me)
    dir_spec = ",".join([*(f"u:{u}:rwX" for u in users), *(f"d:u:{u}:rwX" for u in users)])
    # Files get an explicit mask. Files created after the first run inherit the default
    # entries above as `rwx` (masked to `rw-` at creation); letting setfacl recalculate the
    # mask would then widen it to `rwx` and make them group-executable. `X` cannot decide
    # either, as it reads the group bits, which are the (possibly already widened) mask.
    # The owner's execute bit is the one that says whether a file is meant to run.
    executable: list[str] = []
    plain: list[str] = []
    for path in files:
        (executable if os.lstat(path).st_mode & stat.S_IXUSR else plain).append(path)
    exec_spec = ",".join([*(f"u:{u}:rwx" for u in users), "m::rwx"])
    plain_spec = ",".join([*(f"u:{u}:rw-" for u in users), "m::rw-"])
    for spec, paths in ((dir_spec, dirs), (exec_spec, executable), (plain_spec, plain)):
        for batch in batches(paths):
            result = subprocess.run(
                ["setfacl", "-m", spec, "--", *batch], capture_output=True, text=True, check=False
            )
            if result.returncode != 0:
                if "not supported" in result.stderr.lower():
                    raise SandboxError(
                        f"The filesystem holding {root} does not support ACLs; the sandbox user "
                        "could not write to the workspace."
                    )
                failed += len([line for line in result.stderr.splitlines() if line.strip()])
    return failed


def has_workspace_acl(root: Path, container_host_uid: int, *, my_uid: int | None = None) -> bool:
    """Whether `root` carries the symmetric ACLs `apply_acls` sets."""
    me = os.getuid() if my_uid is None else my_uid
    result = subprocess.run(
        ["getfacl", "-n", "-p", "-c", str(root)], capture_output=True, text=True, check=False
    )
    lines = {line.split("#", 1)[0].strip() for line in result.stdout.splitlines()}
    return {
        f"default:user:{container_host_uid}:rwx",
        f"user:{container_host_uid}:rwx",
        f"user:{me}:rwx",
    } <= lines
