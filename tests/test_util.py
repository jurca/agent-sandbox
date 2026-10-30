from __future__ import annotations

from pathlib import Path

import pytest

from agent_sandbox import util
from agent_sandbox.util import SandboxError, format_duration, parse_duration, slugify


@pytest.mark.parametrize(
    ("text", "seconds"),
    [
        ("90", 90),
        ("1", 1),
        ("45s", 45),
        ("15m", 900),
        ("2h", 7200),
        ("1h30m", 5400),
        ("1h30m15s", 5415),
        ("30m1h", 5400),
        (" 10M ", 600),
    ],
)
def test_parse_duration(text: str, seconds: int) -> None:
    assert parse_duration(text) == seconds


@pytest.mark.parametrize("text", ["", "0", "0m", "-5", "1.5h", "h", "10x", "1h 30m", "m5"])
def test_parse_duration_rejects(text: str) -> None:
    with pytest.raises(SandboxError):
        parse_duration(text)


@pytest.mark.parametrize(
    ("seconds", "text"),
    [(0, "00:00"), (-3, "00:00"), (59.2, "01:00"), (61, "01:01"), (3600, "1:00:00"),
     (5415, "1:30:15")],
)  # fmt: skip
def test_format_duration(seconds: float, text: str) -> None:
    assert format_duration(seconds) == text


def test_slugify() -> None:
    assert slugify("My Repo!") == "my-repo"
    assert slugify("...") == "workspace"
    assert slugify("a" * 50, limit=10) == "a" * 10
    assert slugify("abc-def", limit=4) == "abc"


def test_dirs_follow_environment(isolated_dirs: Path) -> None:
    assert util.config_dir() == isolated_dirs / "config"
    assert util.state_dir() == isolated_dirs / "state"
    assert util.runtime_dir() == isolated_dirs / "runtime"


def test_dirs_default_to_xdg(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    for name in ("CONFIG", "STATE", "RUNTIME"):
        monkeypatch.delenv(f"AGENT_SANDBOX_{name}_DIR")
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "c"))
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "s"))
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(tmp_path / "r"))
    assert util.config_dir() == tmp_path / "c" / "agent-sandbox"
    assert util.state_dir() == tmp_path / "s" / "agent-sandbox"
    assert util.runtime_dir() == tmp_path / "r" / "agent-sandbox"


def test_atomic_write(tmp_path: Path) -> None:
    target = tmp_path / "sub" / "file"
    util.atomic_write(target, "one", mode=0o600)
    util.atomic_write(target, "two", mode=0o600)
    assert target.read_text() == "two"
    assert target.stat().st_mode & 0o777 == 0o600
    assert [p.name for p in target.parent.iterdir()] == ["file"]


def test_confirm_refuses_without_tty(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(util, "is_tty", lambda: False)
    with pytest.raises(SandboxError, match="interactive"):
        util.confirm("Go?")
    with pytest.raises(SandboxError, match="interactive"):
        util.require_phrase("I understand the risks")


@pytest.mark.parametrize(
    ("answer", "default", "expected"),
    [("y", False, True), ("YES", False, True), ("", False, False), ("", True, True),
     ("n", True, False), ("maybe", False, False)],
)  # fmt: skip
def test_confirm_answers(
    monkeypatch: pytest.MonkeyPatch, answer: str, default: bool, expected: bool
) -> None:
    monkeypatch.setattr(util, "is_tty", lambda: True)
    monkeypatch.setattr("builtins.input", lambda _prompt: answer)
    assert util.confirm("Go?", default=default) is expected


def test_require_phrase(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(util, "is_tty", lambda: True)
    monkeypatch.setattr("builtins.input", lambda _prompt: "I understand the risks")
    util.require_phrase("I understand the risks")
    monkeypatch.setattr("builtins.input", lambda _prompt: "yes")
    with pytest.raises(SandboxError, match="Not confirmed"):
        util.require_phrase("I understand the risks")
