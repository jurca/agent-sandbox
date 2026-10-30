"""Host-side approval of the committed `.agent-sandbox/` configuration (trust on first use).

Anything that arrives through git (a clone, a pull) could widen mounts or allowlists, so the
files are shown as a diff and must be accepted once before the toolkit acts on them.
"""

from __future__ import annotations

import difflib
import shutil
from pathlib import Path

from .config import APPROVED_FILES, PROJECT_DIR
from .project import Project
from .util import SandboxError, confirm, eprint, is_tty, state_dir


def _approved_dir(project: Project) -> Path:
    return state_dir() / "approved" / project.id


def _read(path: Path) -> str:
    try:
        return path.read_text()
    except FileNotFoundError:
        return ""


def pending_diff(project: Project) -> str:
    """A unified diff between the approved snapshot and the files on disk ('' if unchanged)."""
    config_dir = project.root / PROJECT_DIR
    approved = _approved_dir(project)
    chunks: list[str] = []
    for name in APPROVED_FILES:
        old, new = _read(approved / name), _read(config_dir / name)
        if old == new:
            continue
        diff = difflib.unified_diff(
            old.splitlines(keepends=True),
            new.splitlines(keepends=True),
            fromfile=f"approved/{name}",
            tofile=f"{PROJECT_DIR}/{name}",
        )
        chunks.append("".join(line if line.endswith("\n") else line + "\n" for line in diff))
    return "".join(chunks)


def record(project: Project) -> None:
    """Remember the current files as approved."""
    config_dir = project.root / PROJECT_DIR
    approved = _approved_dir(project)
    if approved.exists():
        shutil.rmtree(approved)
    approved.mkdir(parents=True, mode=0o700)
    for name in APPROVED_FILES:
        source = config_dir / name
        if source.is_file():
            shutil.copyfile(source, approved / name)


def is_approved(project: Project) -> bool:
    return not pending_diff(project)


def ensure_approved(project: Project) -> None:
    diff = pending_diff(project)
    if not diff:
        return
    eprint(f"The configuration in {project.root}/{PROJECT_DIR} changed since you approved it.")
    eprint("It controls mounts, network access and environment, so check it before continuing:\n")
    eprint(diff)
    if not is_tty():
        raise SandboxError("Not approved. Re-run in an interactive terminal to review and approve.")
    if not confirm("Approve this configuration?"):
        raise SandboxError("Configuration not approved; nothing was changed.")
    record(project)
