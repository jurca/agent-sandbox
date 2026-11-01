from __future__ import annotations

import os
import shutil
import socket
import subprocess
from collections.abc import Iterator
from pathlib import Path

import pytest

from agent_sandbox import mounts
from agent_sandbox.config import MountSpec
from agent_sandbox.mounts import BindMount, VolumeMount, scan_for_sockets, validate_extra_mounts
from agent_sandbox.util import SandboxError


@pytest.fixture
def home(tmp_path: Path) -> Path:
    path = tmp_path / "home"
    for rel in (".ssh", ".config/gh", "projects/data"):
        (path / rel).mkdir(parents=True)
    return path


@pytest.fixture
def unix_socket(tmp_path: Path) -> Iterator[Path]:
    path = tmp_path / "home" / "projects" / "data" / "agent.sock"
    path.parent.mkdir(parents=True, exist_ok=True)
    sock = socket.socket(socket.AF_UNIX)
    sock.bind(str(path))
    yield path
    sock.close()


def test_bind_mount_args() -> None:
    assert BindMount("/a", "/b").engine_args() == ["--mount", "type=bind,src=/a,dst=/b,readonly"]
    assert BindMount("/a", "/b", readonly=False).engine_args(relabel=True) == [
        "--mount",
        "type=bind,src=/a,dst=/b,relabel=shared",
    ]
    with pytest.raises(SandboxError, match="comma"):
        BindMount("/a,b", "/b").engine_args()
    assert VolumeMount("v", "/home/u/.claude").engine_args() == [
        "--mount",
        "type=volume,src=v,dst=/home/u/.claude",
    ]


def validate(specs: list[MountSpec], home: Path) -> list[BindMount]:
    return validate_extra_mounts(specs, home, workspace=Path("/w/proj"), container_home="/home/dev")


def test_validate_extra_mounts_accepts_ordinary_dirs(home: Path) -> None:
    data = home / "projects" / "data"
    (home / "link").symlink_to(data)
    result = validate([MountSpec(str(data), "/data"), MountSpec(str(home / "link"), "/link")], home)
    assert result == [BindMount(str(data), "/data"), BindMount(str(data), "/link")]
    assert all(m.readonly for m in result)


@pytest.mark.parametrize(
    "rel", [".ssh", ".ssh/keys", ".config/gh", ".config", ".", "..", ".local/state/agent-sandbox"]
)
def test_validate_extra_mounts_refuses_sensitive_trees(home: Path, rel: str) -> None:
    source = home / rel
    source.mkdir(parents=True, exist_ok=True)
    with pytest.raises(SandboxError, match="would expose"):
        validate([MountSpec(str(source), "/x")], home)


@pytest.mark.parametrize("source", ["/proc", "/sys/kernel", "/run", "/var/run", "/", "/etc/shadow"])
def test_validate_extra_mounts_refuses_system_trees(home: Path, source: str) -> None:
    with pytest.raises(SandboxError):
        validate([MountSpec(source, "/x")], home)


def test_validate_extra_mounts_refuses_symlink_into_sensitive(home: Path) -> None:
    (home / "projects" / "innocent").symlink_to(home / ".ssh")
    with pytest.raises(SandboxError, match="would expose"):
        validate([MountSpec(str(home / "projects" / "innocent"), "/x")], home)


def test_validate_extra_mounts_refuses_toolkit_dirs(home: Path, isolated_dirs: Path) -> None:
    (isolated_dirs / "state" / "approved").mkdir(parents=True)
    with pytest.raises(SandboxError, match="would expose"):
        validate([MountSpec(str(isolated_dirs / "state" / "approved"), "/x")], home)


def test_validate_extra_mounts_refuses_missing_socket_device(home: Path, unix_socket: Path) -> None:
    with pytest.raises(SandboxError, match="does not exist"):
        validate([MountSpec(str(home / "nope"), "/x")], home)
    with pytest.raises(SandboxError, match="socket or device"):
        validate([MountSpec(str(unix_socket), "/x")], home)
    with pytest.raises(SandboxError):
        validate([MountSpec("/dev/null", "/x")], home)


@pytest.mark.parametrize("target", ["/w/proj", "/w/proj/sub"])
def test_validate_extra_mounts_refuses_targets_in_workspace(home: Path, target: str) -> None:
    with pytest.raises(SandboxError, match="inside the workspace /w/proj"):
        validate([MountSpec(str(home / "projects"), target)], home)


@pytest.mark.parametrize("target", ["/w", "/"])
def test_validate_extra_mounts_refuses_targets_above_workspace(home: Path, target: str) -> None:
    with pytest.raises(SandboxError, match="would cover the workspace"):
        validate([MountSpec(str(home / "projects"), target)], home)


def test_validate_extra_mounts_allows_similar_target(home: Path) -> None:
    assert validate([MountSpec(str(home / "projects"), "/w/proj2")], home)


@pytest.mark.parametrize(
    ("target", "expanded"),
    [("~", "/home/dev"), ("~/.agents/skills", "/home/dev/.agents/skills"),
     ("{home}/x", "/home/dev/x"), ("/abs/~", "/abs/~"), ("~other", "~other")],
)  # fmt: skip
def test_expand_home(target: str, expanded: str) -> None:
    assert mounts.expand_home(target, "/home/dev") == expanded


def test_validate_extra_mounts_expands_home_target(home: Path) -> None:
    data = home / "projects"
    result = validate([MountSpec(str(data), "~/.agents/skills")], home)
    assert result == [BindMount(str(data), "/home/dev/.agents/skills")]


def test_workspace_path_refuses_symlinks(tmp_path: Path) -> None:
    (tmp_path / "real").mkdir()
    (tmp_path / "sub").symlink_to(tmp_path / "real")
    assert mounts.workspace_path(tmp_path, "a/b") == tmp_path / "a" / "b"
    with pytest.raises(SandboxError, match="symlink"):
        mounts.workspace_path(tmp_path, "sub/.venv")
    with pytest.raises(SandboxError, match="symlink"):
        mounts.workspace_path(tmp_path, "sub")


def test_ensure_mountpoint(tmp_path: Path) -> None:
    assert mounts.ensure_mountpoint(tmp_path, "a/.venv", file_ok=False).is_dir()
    (tmp_path / ".envrc").write_text("")
    assert mounts.ensure_mountpoint(tmp_path, ".envrc", file_ok=True).is_file()
    with pytest.raises(SandboxError, match="not a directory"):
        mounts.ensure_mountpoint(tmp_path, ".envrc", file_ok=False)


def test_scan_finds_sockets_without_following_symlinks(tmp_path: Path, unix_socket: Path) -> None:
    root = tmp_path / "home" / "projects"
    outside = tmp_path / "outside"
    outside.mkdir()
    s2 = socket.socket(socket.AF_UNIX)
    s2.bind(str(outside / "hidden.sock"))
    (root / "to-outside").symlink_to(outside)
    try:
        result = scan_for_sockets(root)
    finally:
        s2.close()
    assert result.complete
    assert result.sockets == [unix_socket]
    assert scan_for_sockets(unix_socket).sockets == [unix_socket]


def test_scan_budget(tmp_path: Path) -> None:
    for i in range(30):
        (tmp_path / f"f{i}").touch()
    result = scan_for_sockets(tmp_path, max_entries=10)
    assert not result.complete and result.entries == 10
    assert scan_for_sockets(tmp_path).complete


def test_scan_skips_unreadable_dirs(tmp_path: Path) -> None:
    locked = tmp_path / "locked"
    locked.mkdir()
    locked.chmod(0)
    try:
        assert scan_for_sockets(tmp_path).complete
    finally:
        locked.chmod(0o700)


needs_acl = pytest.mark.skipif(shutil.which("setfacl") is None, reason="setfacl not installed")


@needs_acl
def test_apply_acls_skips_git_and_config(repo: Path) -> None:
    (repo / ".agent-sandbox").mkdir()
    (repo / ".agent-sandbox" / "config.toml").write_text("")
    (repo / "src").mkdir()
    (repo / "src" / "a.py").write_text("")
    (repo / "link").symlink_to("/etc/hostname")
    other = os.getuid() + 12345
    assert mounts.apply_acls(repo, other) == 0
    assert mounts.has_workspace_acl(repo, other)

    def acl(path: Path) -> str:
        return subprocess.run(
            ["getfacl", "-n", "-p", "-c", str(path)], capture_output=True, text=True, check=True
        ).stdout

    assert f"user:{other}:rw" in acl(repo / "src" / "a.py")

    assert f"default:user:{other}:rwx" in acl(repo / "src")
    assert f"default:user:{os.getuid()}:rwx" in acl(repo / "src")
    for skipped in (repo / ".git", repo / ".git" / "HEAD", repo / ".agent-sandbox" / "config.toml"):
        assert str(other) not in acl(skipped), skipped
    assert str(other) not in acl(Path("/etc/hostname"))


@needs_acl
def test_apply_acls_again_keeps_files_not_executable(tmp_path: Path) -> None:
    other = os.getuid() + 12345
    script = tmp_path / "run.sh"
    script.write_text("")
    script.chmod(0o755)
    assert mounts.apply_acls(tmp_path, other) == 0
    # Created after the first run: inherits the directory's default entries as rwx.
    (tmp_path / "README.md").write_text("")
    (tmp_path / "docs").mkdir()
    (tmp_path / "docs" / "kb.md").write_text("")
    assert mounts.apply_acls(tmp_path, other) == 0
    for name in ("README.md", "docs/kb.md"):
        assert (tmp_path / name).stat().st_mode & 0o111 == 0, name
    assert (tmp_path / "run.sh").stat().st_mode & 0o110 == 0o110

    # A mask already widened by an earlier version is narrowed again.
    subprocess.run(["setfacl", "-m", "m::rwx", str(tmp_path / "README.md")], check=True)
    assert mounts.apply_acls(tmp_path, other) == 0
    assert (tmp_path / "README.md").stat().st_mode & 0o111 == 0


def test_walk_for_acls_skips_relative_paths(tmp_path: Path) -> None:
    for rel in (".venv/lib", "backend/.venv/lib", "backend/src", "src"):
        (tmp_path / rel).mkdir(parents=True)
    (tmp_path / "backend" / ".venv" / "lib" / "x.py").write_text("")
    (tmp_path / "backend" / "src" / "a.py").write_text("")
    dirs, files = mounts._walk_for_acls(tmp_path, frozenset({".venv", "backend/.venv"}))
    assert sorted(Path(d).relative_to(tmp_path).as_posix() for d in dirs) == [
        ".",
        "backend",
        "backend/src",
        "src",
    ]
    assert files == [str(tmp_path / "backend" / "src" / "a.py")]
