"""Mount specifications, mount safety checks and file ownership for bind mounts."""

from __future__ import annotations

import os
import shutil
import stat
import subprocess
import time
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from pathlib import Path

from .config import PROJECT_DIR, WORKSPACE_TARGET, MountSpec
from .util import SandboxError, config_dir, runtime_dir, state_dir

ACL_BATCH = 200


@dataclass(frozen=True)
class BindMount:
    source: str
    target: str
    readonly: bool = True

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


def validate_extra_mounts(specs: Iterable[MountSpec], home: Path) -> list[BindMount]:
    sensitive = sensitive_paths(home)
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
        if spec.target == WORKSPACE_TARGET or spec.target.startswith(WORKSPACE_TARGET + "/"):
            raise SandboxError(
                f"Mount target {spec.target} is inside {WORKSPACE_TARGET}; refusing."
            )
        mounts.append(BindMount(str(resolved), spec.target, readonly=True))
    return mounts


# --- sockets ----------------------------------------------------------------------------


@dataclass
class ScanResult:
    sockets: list[Path] = field(default_factory=list)
    complete: bool = True
    entries: int = 0


def scan_for_sockets(
    root: Path, *, max_entries: int = 50_000, max_seconds: float = 5.0
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


SOCKET_RISK = (
    "Unix sockets inside a mounted directory stay connectable from the sandbox even when the "
    "mount is read-only. A socket can be an SSH agent, a docker or desktop session, an IDE or "
    "editor server - anything that grants capabilities beyond the files themselves."
)


# --- ownership --------------------------------------------------------------------------


def acl_tools_available() -> bool:
    return shutil.which("setfacl") is not None


def _walk_for_acls(root: Path, exclude: frozenset[str]) -> tuple[list[str], list[str]]:
    dirs: list[str] = []
    files: list[str] = []
    for current, dirnames, filenames in os.walk(root, followlinks=False):
        if Path(current) == root:
            dirnames[:] = [d for d in dirnames if d not in exclude]
            filenames[:] = [f for f in filenames if f not in exclude]
        dirs.append(current)
        for name in filenames:
            path = os.path.join(current, name)
            if stat.S_ISREG(os.lstat(path).st_mode):
                files.append(path)
        dirnames[:] = [d for d in dirnames if not os.path.islink(os.path.join(current, d))]
    return dirs, files


def _batches(items: list[str]) -> Iterator[list[str]]:
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
    Default ACLs keep access symmetric for files created later by either side. `.git` and
    the config directory are skipped by default: they stay owned by the host user, which
    makes them read-only for the container user.

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
    dir_spec = f"u:{container_host_uid}:rwX,d:u:{container_host_uid}:rwX,d:u:{me}:rwX"
    file_spec = f"u:{container_host_uid}:rwX"
    for spec, paths in ((dir_spec, dirs), (file_spec, files)):
        for batch in _batches(paths):
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


def has_workspace_acl(root: Path, container_host_uid: int) -> bool:
    result = subprocess.run(
        ["getfacl", "-n", "-p", "-c", str(root)], capture_output=True, text=True, check=False
    )
    return f"default:user:{container_host_uid}:rwx" in result.stdout
