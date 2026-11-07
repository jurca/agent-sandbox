from __future__ import annotations

import subprocess
from pathlib import Path

import pytest


def pytest_addoption(parser: pytest.Parser) -> None:
    parser.addoption(
        "--integration",
        action="store_true",
        help="run tests that create real containers (see tests/test_integration.py)",
    )


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    if config.getoption("--integration"):
        return
    skip = pytest.mark.skip(reason="needs --integration")
    for item in items:
        if "integration" in item.keywords:
            item.add_marker(skip)


@pytest.fixture(autouse=True)
def isolated_dirs(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Keep every test away from the real config, state and runtime directories."""
    base = tmp_path / "asb"
    for name in ("CONFIG", "STATE", "RUNTIME"):
        monkeypatch.setenv(f"AGENT_SANDBOX_{name}_DIR", str(base / name.lower()))
    for name in ("HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "http_proxy", "https_proxy", "no_proxy"):
        monkeypatch.delenv(name, raising=False)
    return base


def git(cwd: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(cwd), *args], capture_output=True, text=True, check=True
    )
    return result.stdout


def make_repo(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    git(path, "init", "-q", "-b", "main")
    git(path, "config", "user.email", "test@example.invalid")
    git(path, "config", "user.name", "Test")
    (path / "README").write_text("hello\n")
    (path / ".gitignore").write_text(".env\n.env.*\n*.env\n")
    git(path, "add", "README", ".gitignore")
    git(path, "commit", "-q", "-m", "initial")
    return path.resolve()


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    return make_repo(tmp_path / "repo")
