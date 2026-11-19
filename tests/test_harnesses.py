from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

from agent_sandbox import harnesses
from agent_sandbox.engine import EngineError

from .fakes import FakeEngine

# Stands in for curl: "downloads" an installer that reports which URL it came from.
FAKE_CURL = """#!/bin/sh
while [ $# -gt 0 ]; do
    case $1 in
        -o) out=$2; shift ;;
        -*) ;;
        *) url=$1 ;;
    esac
    shift
done
if [ -e "$FAIL_ONCE" ]; then rm "$FAIL_ONCE"; exit 7; fi
echo "echo installer from $url" > "$out"
"""


RAW = "raw.githubusercontent.com"
RELEASES = "release-assets.githubusercontent.com"
ASK = "  1. Add to .agent-sandbox/allow.extra:"


def asked_hosts(out: str) -> list[str]:
    """The hosts the helper asks to add to allow.extra, in order."""
    lines = out.splitlines()
    if ASK not in lines:
        return []
    hosts = []
    for line in lines[lines.index(ASK) + 1 :]:
        if not line.startswith("       "):
            break
        hosts.append(line.strip())
    return hosts


def run_helper(
    tmp_path: Path, answers: str, *, fail_once: bool = False, cwd: Path | None = None
) -> str:
    script = tmp_path / "install-harness"
    script.write_text(harnesses.INSTALL_HARNESS_SH)
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    (bin_dir / "curl").write_text(FAKE_CURL)
    (bin_dir / "curl").chmod(0o755)
    flag = tmp_path / "fail-once"
    if fail_once:
        flag.touch()
    env = {**os.environ, "PATH": f"{bin_dir}:{os.environ['PATH']}", "FAIL_ONCE": str(flag)}
    result = subprocess.run(
        ["sh", str(script)],
        input=answers,
        env=env,
        cwd=cwd or tmp_path,
        capture_output=True,
        text=True,
        check=True,
    )
    return result.stdout


@pytest.mark.parametrize(
    ("choice", "url", "hosts"),
    [
        ("1", "https://claude.ai/install.sh", []),
        ("2", "https://gh.io/copilot-install", [RAW, RELEASES]),
        ("3", "https://opencode.ai/v2/install", ["registry.npmjs.org"]),
    ],
)
def test_installs_the_chosen_harness(
    tmp_path: Path, choice: str, url: str, hosts: list[str]
) -> None:
    out = run_helper(tmp_path, f"{choice}\n\n")
    assert "agent-sandbox net 10m" in out
    assert asked_hosts(out) == hosts
    assert f"installer from {url}" in out


@pytest.mark.parametrize(
    ("files", "asked"),
    [
        ({"allow.extra": f"pypi.org\n{RAW}  # copilot\n{RELEASES}\n"}, []),
        ({"allow.extra": "pypi.org RAW.githubusercontent.com\n"}, [RELEASES]),
        ({"allow.base": ".githubusercontent.com\n"}, []),
        ({"allow.base": RELEASES, "allow.extra": RAW}, []),
        ({"allow.extra": f"#   {RAW}\n"}, [RAW, RELEASES]),
        ({"allow.extra": f"{RELEASES}\n"}, [RAW]),
        ({"allow.extra": "githubusercontent.com\n"}, [RAW, RELEASES]),
        ({}, [RAW, RELEASES]),
    ],
)
def test_asks_to_allowlist_only_missing_hosts(
    tmp_path: Path, files: dict[str, str], asked: list[str]
) -> None:
    workspace = tmp_path / "ws"
    (workspace / ".agent-sandbox").mkdir(parents=True)
    (workspace / "src").mkdir()
    for name, text in files.items():
        (workspace / ".agent-sandbox" / name).write_text(text)
    out = run_helper(tmp_path, "2\n\n", cwd=workspace / "src")
    assert asked_hosts(out) == asked
    assert "agent-sandbox net 10m" in out


def test_asks_again_after_an_invalid_choice(tmp_path: Path) -> None:
    out = run_helper(tmp_path, "4\n\nclaude\n1\n\n")
    assert out.count("Enter 1, 2 or 3: ") == 4
    assert "installer from https://claude.ai/install.sh" in out


def test_retries_when_the_download_fails(tmp_path: Path) -> None:
    out = run_helper(tmp_path, "1\n\n\n", fail_once=True)
    assert "failed. Is the network open?" in out
    assert "installer from https://claude.ai/install.sh" in out


def test_add_helper_only_warns_on_failure(capsys: pytest.CaptureFixture[str]) -> None:
    class Failing(FakeEngine):
        def copy_in(self, *args: object, **kwargs: object) -> None:
            raise EngineError("no such directory")

    harnesses.add_helper(Failing(), "ws")
    assert "install-harness could not be added" in capsys.readouterr().err
