"""Shared helpers: errors, paths, prompts and duration handling."""

from __future__ import annotations

import os
import re
import sys
from pathlib import Path


class SandboxError(Exception):
    """A user-facing error: printed without a traceback."""


def eprint(*parts: object) -> None:
    print(*parts, file=sys.stderr, flush=True)


def is_tty() -> bool:
    return sys.stdin.isatty() and sys.stderr.isatty()


def confirm(question: str, *, default: bool = False) -> bool:
    """Ask a y/N question on the terminal; refuse to guess when not interactive."""
    if not is_tty():
        raise SandboxError(f"{question}\nThis needs an interactive terminal to answer.")
    suffix = " [Y/n] " if default else " [y/N] "
    try:
        answer = input(question + suffix).strip().lower()
    except EOFError:
        return False
    if not answer:
        return default
    return answer in ("y", "yes")


def require_phrase(phrase: str) -> None:
    if not is_tty():
        raise SandboxError("Confirming this needs an interactive terminal.")
    try:
        answer = input(f'Type "{phrase}" to continue: ').strip()
    except EOFError:
        answer = ""
    if answer != phrase:
        raise SandboxError("Not confirmed; nothing was changed.")


def config_dir() -> Path:
    if env := os.environ.get("AGENT_SANDBOX_CONFIG_DIR"):
        return Path(env)
    base = os.environ.get("XDG_CONFIG_HOME") or str(Path.home() / ".config")
    return Path(base) / "agent-sandbox"


def state_dir() -> Path:
    if env := os.environ.get("AGENT_SANDBOX_STATE_DIR"):
        return Path(env)
    base = os.environ.get("XDG_STATE_HOME") or str(Path.home() / ".local" / "state")
    return Path(base) / "agent-sandbox"


def runtime_dir() -> Path:
    if env := os.environ.get("AGENT_SANDBOX_RUNTIME_DIR"):
        return Path(env)
    if base := os.environ.get("XDG_RUNTIME_DIR"):
        return Path(base) / "agent-sandbox"
    return Path(f"/tmp/agent-sandbox-{os.getuid()}")


_DURATION = re.compile(r"(\d+)|((?:\d+[smh])+)")
_DURATION_UNITS = {"s": 1, "m": 60, "h": 3600}


def parse_duration(text: str) -> int:
    """Seconds by default; `m` and `h` suffixes, and sums such as `1h30m`, are accepted."""
    text = text.strip().lower()
    total = 0
    if match := _DURATION.fullmatch(text):
        if match.group(1):
            total = int(match.group(1))
        else:
            total = sum(
                int(count) * _DURATION_UNITS[unit]
                for count, unit in re.findall(r"(\d+)([smh])", match.group(2))
            )
    if total <= 0:
        raise SandboxError(
            f"Invalid duration {text!r}: use seconds, or a number with an m or h suffix "
            "(for example 90, 15m, 2h, 1h30m); it must be greater than zero."
        )
    return total


def format_duration(seconds: float) -> str:
    seconds = max(0, int(seconds + 0.999))
    hours, rest = divmod(seconds, 3600)
    minutes, secs = divmod(rest, 60)
    if hours:
        return f"{hours}:{minutes:02d}:{secs:02d}"
    return f"{minutes:02d}:{secs:02d}"


def atomic_write(path: Path, data: str, mode: int = 0o644) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(data)
    tmp.chmod(mode)
    os.replace(tmp, path)


def slugify(text: str, *, limit: int = 40) -> str:
    slug = re.sub(r"[^a-z0-9_.-]+", "-", text.lower()).strip("-.")
    return slug[:limit].strip("-.") or "workspace"
