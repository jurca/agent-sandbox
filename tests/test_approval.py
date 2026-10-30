from __future__ import annotations

from pathlib import Path

import pytest

from agent_sandbox import approval, util
from agent_sandbox.project import project_for
from agent_sandbox.util import SandboxError


@pytest.fixture
def configured(repo: Path) -> Path:
    cfg = repo / ".agent-sandbox"
    cfg.mkdir()
    (cfg / "config.toml").write_text('image = "a"\n')
    (cfg / "allow.base").write_text("api.anthropic.com\n")
    return repo


def test_first_run_needs_approval(configured: Path) -> None:
    p = project_for(configured)
    diff = approval.pending_diff(p)
    assert '+image = "a"' in diff and "+api.anthropic.com" in diff
    assert not approval.is_approved(p)
    approval.record(p)
    assert approval.is_approved(p)


def test_changes_show_as_diff(configured: Path, isolated_dirs: Path) -> None:
    p = project_for(configured)
    approval.record(p)
    snapshot = isolated_dirs / "state" / "approved" / p.id
    assert (snapshot / "config.toml").read_text() == 'image = "a"\n'
    assert snapshot.stat().st_mode & 0o777 == 0o700

    (configured / ".agent-sandbox" / "allow.extra").write_text("pypi.org")  # no newline
    (configured / ".agent-sandbox" / "allow.base").unlink()
    diff = approval.pending_diff(p)
    assert "-api.anthropic.com" in diff
    assert "+pypi.org\n" in diff
    assert "tofile" not in diff and "+++ .agent-sandbox/allow.extra" in diff


def test_untracked_files_are_ignored(configured: Path) -> None:
    p = project_for(configured)
    approval.record(p)
    (configured / ".agent-sandbox" / "notes.txt").write_text("x")
    assert approval.is_approved(p)


def test_ensure_approved_refuses_without_tty(
    configured: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(approval, "is_tty", lambda: False)
    with pytest.raises(SandboxError, match="Not approved"):
        approval.ensure_approved(project_for(configured))


@pytest.mark.parametrize(("answer", "approved"), [("y", True), ("n", False), ("", False)])
def test_ensure_approved_asks(
    configured: Path, monkeypatch: pytest.MonkeyPatch, answer: str, approved: bool
) -> None:
    monkeypatch.setattr(approval, "is_tty", lambda: True)
    monkeypatch.setattr(util, "is_tty", lambda: True)
    monkeypatch.setattr("builtins.input", lambda _prompt: answer)
    p = project_for(configured)
    if approved:
        approval.ensure_approved(p)
    else:
        with pytest.raises(SandboxError, match="not approved"):
            approval.ensure_approved(p)
    assert approval.is_approved(p) is approved
