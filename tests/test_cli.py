from __future__ import annotations

from pathlib import Path

import pytest

from agent_sandbox import cli


@pytest.mark.parametrize("topic", ["", "config", "network", "security"])
def test_help_topics(topic: str, capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["help", topic] if topic else ["help"]) == 0
    assert capsys.readouterr().out.strip()


def test_help_for_command(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as info:
        cli.main(["help", "net"])
    assert info.value.code == 0
    assert "--allow-all" in capsys.readouterr().out


def test_unknown_help_topic(capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["help", "nope"]) == 1
    assert "No help topic" in capsys.readouterr().err


def test_every_command_is_documented() -> None:
    for command in cli.COMMANDS:
        assert f"  {command}" in cli.OVERVIEW, command


def test_parser() -> None:
    parser = cli.build_parser()
    args = parser.parse_args(["net", "1h30m", "--allow", "a.com", "--allow", ".b.com", "--extend"])
    assert (args.duration, args.allow, args.extend, args.allow_all) == (
        "1h30m", ["a.com", ".b.com"], True, False,
    )  # fmt: skip
    args = parser.parse_args(["exec", "--", "ls", "-la", "--state"])
    assert args.cmd == ["--", "ls", "-la", "--state"]
    args = parser.parse_args(["exec", cli.UNSAFE_FLAG, "--", "tmux"])
    assert args.unsafe and args.cmd == ["--", "tmux"]
    assert parser.parse_args(["rm", "abc", "--state"]).name == "abc"
    assert parser.parse_args(["net", "--stop"]).stop
    with pytest.raises(SystemExit):
        parser.parse_args(["init"])


def test_outside_a_repository(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.chdir(tmp_path)
    assert cli.main([]) == 1
    assert "Not inside a git repository" in capsys.readouterr().err
    assert cli.main(["status"]) == 1
    assert "not inside a git repository" in capsys.readouterr().err


def test_subdirectory_and_url_in_repo(
    repo: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    (repo / "sub").mkdir()
    monkeypatch.chdir(repo / "sub")
    assert cli.main(["init", "--image", "x"]) == 1
    assert "repository root" in capsys.readouterr().err
    monkeypatch.chdir(repo)
    assert cli.main(["https://example.com/x.git"]) == 1
    assert "only used outside a git repository" in capsys.readouterr().err


def test_init_command(
    repo: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.chdir(repo)
    assert cli.main(["init", "--image", "img:1"]) == 0
    assert "wrote .agent-sandbox/config.toml" in capsys.readouterr().out


def test_net_needs_duration(repo: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from agent_sandbox import manage
    from agent_sandbox.project import project_for

    from .fakes import FakeEngine

    manage.init_project(project_for(repo), "img")
    monkeypatch.chdir(repo)
    monkeypatch.setattr("agent_sandbox.sandbox.detect_engine", lambda user: FakeEngine())
    assert cli.main(["net"]) == 1
    assert cli.main(["net", "0"]) == 1


def test_refuses_root(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    monkeypatch.setattr(cli.os, "getuid", lambda: 0)
    assert cli.main(["ls"]) == 1
    assert "root" in capsys.readouterr().err
