"""Workspace identity: which repository, and the names of everything created for it."""

from __future__ import annotations

import hashlib
import os
import subprocess
from dataclasses import dataclass
from pathlib import Path

from .util import SandboxError, slugify

PREFIX = "agent-sandbox"
LABEL_MANAGED = "agent-sandbox.managed"
LABEL_ROLE = "agent-sandbox.role"
LABEL_ID = "agent-sandbox.id"
LABEL_WORKSPACE = "agent-sandbox.workspace"
LABEL_VERSION = "agent-sandbox.version"
LABEL_SPEC = "agent-sandbox.spec"
LABEL_SPEC_JSON = "agent-sandbox.spec-json"
LABEL_HOME = "agent-sandbox.home"
LABEL_BASE_ID = "agent-sandbox.base-id"
LABEL_KIND = "agent-sandbox.kind"
LABEL_STATE_SCOPE = "agent-sandbox.state-scope"
VERSION = "1.0.0"


class NotARepositoryError(SandboxError):
    pass


@dataclass(frozen=True)
class GitLayout:
    """Where git keeps its data for the workspace, as far as mounts are concerned."""

    git_path: Path
    is_file: bool
    external_dirs: tuple[Path, ...] = ()


@dataclass(frozen=True)
class Project:
    root: Path
    id: str

    @property
    def workspace_container(self) -> str:
        return f"{PREFIX}-{self.id}"

    @property
    def proxy_container(self) -> str:
        return f"{PREFIX}-{self.id}-proxy"

    @property
    def network(self) -> str:
        return f"{PREFIX}-{self.id}-net"

    @property
    def hostname(self) -> str:
        return slugify(self.root.name, limit=30)

    def state_volume(self, scope: str, rel_path: str) -> str:
        suffix = slugify(rel_path.replace("/", "-"), limit=40)
        if scope == "per-workspace":
            return f"{PREFIX}-state-{self.id}-{suffix}"
        return f"{PREFIX}-state-shared-{scope}-{suffix}"

    def isolated_volume(self, rel_path: str) -> str:
        # The digest keeps `.venv` and `venv` apart; slugify maps both to the same name.
        digest = hashlib.sha256(rel_path.encode()).hexdigest()[:6]
        return f"{PREFIX}-isolated-{self.id}-{slugify(rel_path.replace('/', '-'))}-{digest}"

    def labels(self, role: str) -> dict[str, str]:
        return {
            LABEL_MANAGED: "true",
            LABEL_ROLE: role,
            LABEL_ID: self.id,
            LABEL_WORKSPACE: str(self.root),
            LABEL_VERSION: VERSION,
        }


def make_id(root: Path) -> str:
    digest = hashlib.sha256(str(root).encode()).hexdigest()[:8]
    return f"{slugify(root.name)}-{digest}"


def project_for(root: Path) -> Project:
    root = root.resolve()
    return Project(root=root, id=make_id(root))


def _git(cwd: Path, *args: str) -> subprocess.CompletedProcess[str]:
    env = {**os.environ, "GIT_OPTIONAL_LOCKS": "0"}
    return subprocess.run(
        ["git", "-c", "core.fsmonitor=false", "-C", str(cwd), *args],
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )


def git_toplevel(cwd: Path) -> Path | None:
    result = _git(cwd, "rev-parse", "--show-toplevel")
    if result.returncode != 0:
        return None
    return Path(result.stdout.strip()).resolve()


def find_project(cwd: Path) -> Project:
    """The project for `cwd`, which must be the root of a git working tree."""
    cwd = cwd.resolve()
    top = git_toplevel(cwd)
    if top is None:
        raise NotARepositoryError(f"{cwd} is not inside a git repository.")
    if top != cwd:
        raise SandboxError(
            "Run agent-sandbox at the repository root, not in a subdirectory.\n"
            f"  root: {top}\n  here: {cwd}"
        )
    return project_for(top)


def git_layout(root: Path) -> GitLayout:
    """`.git` is a directory for ordinary clones and a file for linked worktrees/submodules."""
    git_path = root / ".git"
    if git_path.is_symlink():
        raise SandboxError(f"{git_path} is a symlink; refusing to mount it.")
    if git_path.is_dir():
        return GitLayout(git_path, is_file=False)
    if not git_path.is_file():
        raise SandboxError(f"{root} has no .git entry.")
    dirs: list[Path] = []
    for flag in ("--absolute-git-dir", "--git-common-dir"):
        args = ["rev-parse", flag]
        if flag == "--git-common-dir":
            args.insert(1, "--path-format=absolute")
        result = _git(root, *args)
        if result.returncode != 0:
            raise SandboxError(f"git could not resolve {flag} for {root}: {result.stderr.strip()}")
        path = Path(result.stdout.strip()).resolve()
        if path not in dirs:
            dirs.append(path)
    # A per-worktree git dir lives inside the common dir, so one mount covers both.
    common = dirs[-1]
    outside = tuple(d for d in dirs if d != common and common not in d.parents)
    return GitLayout(git_path, is_file=True, external_dirs=(common, *outside))
