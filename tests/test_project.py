from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from agent_sandbox import project
from agent_sandbox.project import find_project, git_layout, make_id, project_for
from agent_sandbox.util import SandboxError

from .conftest import git, make_repo


def test_make_id() -> None:
    root = Path("/home/u/My Repo")
    digest = hashlib.sha256(b"/home/u/My Repo").hexdigest()[:8]
    assert make_id(root) == f"my-repo-{digest}"


def test_resource_names(repo: Path) -> None:
    p = project_for(repo)
    assert p.workspace_container == f"agent-sandbox-{p.id}"
    assert p.proxy_container == f"agent-sandbox-{p.id}-proxy"
    assert p.network == f"agent-sandbox-{p.id}-net"
    assert p.state_volume("per-workspace", ".claude") == f"agent-sandbox-state-{p.id}-claude"
    assert p.state_volume("per-workspace", ".config/x") == f"agent-sandbox-state-{p.id}-config-x"
    assert p.state_volume("login", ".claude") == "agent-sandbox-state-shared-login-claude"
    labels = p.labels("workspace")
    assert labels[project.LABEL_ROLE] == "workspace"
    assert labels[project.LABEL_WORKSPACE] == str(repo)


def test_find_project(repo: Path, tmp_path: Path) -> None:
    assert find_project(repo).root == repo
    (repo / "sub").mkdir()
    with pytest.raises(SandboxError, match="repository root"):
        find_project(repo / "sub")
    outside = tmp_path / "plain"
    outside.mkdir()
    with pytest.raises(project.NotARepositoryError):
        find_project(outside)


def test_git_layout_plain_clone(repo: Path) -> None:
    layout = git_layout(repo)
    assert layout.git_path == repo / ".git" and not layout.is_file
    assert layout.external_dirs == ()


def test_git_layout_linked_worktree(repo: Path, tmp_path: Path) -> None:
    tree = tmp_path / "tree"
    git(repo, "worktree", "add", "-q", str(tree))
    layout = git_layout(tree.resolve())
    assert layout.is_file
    assert layout.external_dirs == (repo / ".git",)


def test_git_layout_worktree_with_separate_git_dir(tmp_path: Path) -> None:
    main = tmp_path / "main"
    git(tmp_path, "init", "-q", "--separate-git-dir", str(tmp_path / "store.git"), str(main))
    layout = git_layout(main.resolve())
    assert layout.is_file
    assert layout.external_dirs == ((tmp_path / "store.git").resolve(),)


def test_git_layout_submodule(repo: Path, tmp_path: Path) -> None:
    make_repo(tmp_path / "lib")
    git(repo, "-c", "protocol.file.allow=always", "submodule", "add", "-q",
        str(tmp_path / "lib"), "lib")  # fmt: skip
    layout = git_layout(repo / "lib")
    assert layout.is_file
    assert layout.external_dirs == (repo / ".git" / "modules" / "lib",)


def test_git_layout_rejects_symlink(tmp_path: Path, repo: Path) -> None:
    other = tmp_path / "other"
    other.mkdir()
    (other / ".git").symlink_to(repo / ".git")
    with pytest.raises(SandboxError, match="symlink"):
        git_layout(other)
