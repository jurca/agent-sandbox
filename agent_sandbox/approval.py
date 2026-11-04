"""Host-side approval of the committed configuration (trust on first use).

Anything that arrives through git (a clone, a pull) could widen mounts or allowlists or change
what goes into the image, so the files are shown as a diff and must be accepted once before the
toolkit acts on them. Approved are the whole `.agent-sandbox/` tree (its Dockerfile is built
with that directory as the context) and, when the project builds from a devcontainer, the whole
`.devcontainer/` tree.
"""

from __future__ import annotations

import difflib
import hashlib
import shutil
import tomllib
from pathlib import Path

from .config import DEVCONTAINER_DIR, PROJECT_DIR
from .project import Project
from .util import SandboxError, confirm, eprint, is_tty, state_dir

# Snapshot subdirectories per approved tree. Older versions stored the four `.agent-sandbox`
# files directly in the project's approval directory; that layout is still read.
_SNAPSHOTS = {PROJECT_DIR: "agent-sandbox", DEVCONTAINER_DIR: "devcontainer"}


def _approved_dir(project: Project) -> Path:
    return state_dir() / "approved" / project.id


def tree_files(root: Path) -> dict[str, bytes]:
    """Regular files below `root` by relative path; a symlink is recorded as its target."""
    files: dict[str, bytes] = {}
    if not root.is_dir() or root.is_symlink():
        return files
    for path in sorted(root.rglob("*")):
        rel = path.relative_to(root).as_posix()
        if path.is_symlink():
            files[rel] = f"symlink -> {path.readlink()}\n".encode()
        elif path.is_file():
            files[rel] = path.read_bytes()
    return files


def tree_hash(files: dict[str, bytes]) -> str:
    digest = hashlib.sha256()
    for rel, data in sorted(files.items()):
        digest.update(rel.encode() + b"\0" + hashlib.sha256(data).digest())
    return digest.hexdigest()


def devcontainer_enabled(project: Project) -> bool:
    """Read from config.toml directly: approval comes before the configuration is trusted."""
    try:
        with (project.root / PROJECT_DIR / "config.toml").open("rb") as handle:
            data = tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError):
        return False
    table = data.get("devcontainer")
    return isinstance(table, dict) and table.get("enabled") is True


def approved_trees(project: Project) -> list[str]:
    trees = [PROJECT_DIR]
    if devcontainer_enabled(project):
        trees.append(DEVCONTAINER_DIR)
    return trees


def _snapshot(project: Project, tree: str) -> dict[str, bytes]:
    approved = _approved_dir(project)
    snapshot = approved / _SNAPSHOTS[tree]
    if snapshot.is_dir():
        return tree_files(snapshot)
    if tree == PROJECT_DIR and approved.is_dir():  # the flat layout of older versions
        return {p.name: p.read_bytes() for p in sorted(approved.iterdir()) if p.is_file()}
    return {}


def _text(data: bytes) -> list[str] | None:
    try:
        text = data.decode()
    except UnicodeDecodeError:
        return None
    return [line if line.endswith("\n") else line + "\n" for line in text.splitlines(True)]


def _file_diff(rel: str, old: bytes | None, new: bytes | None) -> str:
    old_lines, new_lines = _text(old or b""), _text(new or b"")
    if old_lines is None or new_lines is None:
        state = "added" if old is None else "removed" if new is None else "changed"
        return f"Binary file {rel} {state} ({len(new or old or b'')} bytes)\n"
    name = rel.split("/", 1)[1]
    diff = difflib.unified_diff(
        old_lines, new_lines, fromfile=f"approved/{name}", tofile=rel
    )  # fmt: skip
    return "".join(diff)


def pending_diff(project: Project) -> str:
    """A unified diff between the approved snapshot and the files on disk ('' if unchanged)."""
    chunks: list[str] = []
    for tree in approved_trees(project):
        old = _snapshot(project, tree)
        new = tree_files(project.root / tree)
        for rel in sorted(set(old) | set(new)):
            if old.get(rel) != new.get(rel):
                chunks.append(_file_diff(f"{tree}/{rel}", old.get(rel), new.get(rel)))
    return "".join(chunks)


def record(project: Project) -> None:
    """Remember the current files as approved."""
    approved = _approved_dir(project)
    if approved.exists():
        shutil.rmtree(approved)
    approved.mkdir(parents=True, mode=0o700)
    for tree in approved_trees(project):
        target = approved / _SNAPSHOTS[tree]
        target.mkdir(mode=0o700)
        for rel, data in tree_files(project.root / tree).items():
            path = target / rel
            path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            path.write_bytes(data)


def is_approved(project: Project) -> bool:
    return not pending_diff(project)


def ensure_approved(project: Project) -> None:
    diff = pending_diff(project)
    if not diff:
        return
    trees = " and ".join(f"{project.root}/{tree}" for tree in approved_trees(project))
    eprint(f"The configuration in {trees} changed since you approved it.")
    eprint(
        "It controls mounts, network access, environment and what goes into the image, so check "
        "it before continuing:\n"
    )
    eprint(diff)
    if not is_tty():
        raise SandboxError("Not approved. Re-run in an interactive terminal to review and approve.")
    if not confirm("Approve this configuration?"):
        raise SandboxError("Configuration not approved; nothing was changed.")
    record(project)
