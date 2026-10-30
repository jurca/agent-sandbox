from __future__ import annotations

import json
import subprocess
from collections.abc import Callable, Mapping
from typing import Any

from agent_sandbox.engine import Engine, EngineError

Handler = Callable[[tuple[str, ...]], "subprocess.CompletedProcess[str] | str | int | None"]


class FakeEngine(Engine):
    """Records engine invocations; `objects` answers `inspect`, `handlers` script the rest."""

    def __init__(self, kind: str = "docker", *, rootless: bool = True) -> None:
        super().__init__(kind, rootless=rootless)
        self.calls: list[tuple[str, ...]] = []
        self.objects: dict[tuple[str, str], dict[str, Any]] = {}
        self.handlers: list[tuple[tuple[str, ...], Handler]] = []
        self.files: dict[tuple[str, str], str] = {}  # (container, path) -> content
        self.copies: list[tuple[str, list[str]]] = []  # (container, names) per copy_in

    def copy_in(
        self, container: str, directory: str, files: Mapping[str, str], *, uid: int, gid: int
    ) -> None:
        self.calls.append(("cp", container, *files))
        self.copies.append((container, list(files)))
        for name, text in files.items():
            self.files[(container, f"{directory}/{name}")] = text

    def on(self, prefix: tuple[str, ...], handler: Handler) -> None:
        self.handlers.append((prefix, handler))

    def add(self, kind: str, name: str, labels: dict[str, str], **extra: Any) -> None:
        info: dict[str, Any] = {"Name": name, **extra}
        if kind in ("container", "image"):
            info.setdefault("Config", {})["Labels"] = labels
        else:
            info["Labels"] = labels
        self.objects[(kind, name)] = info

    def run(
        self,
        *args: str,
        check: bool = True,
        capture: bool = True,
        input: str | None = None,
    ) -> subprocess.CompletedProcess[str]:
        self.calls.append(args)
        result = self._answer(args)
        if check and result.returncode != 0:
            raise EngineError(f"fake {' '.join(args[:3])} failed: {result.stderr}")
        return result

    def _answer(self, args: tuple[str, ...]) -> subprocess.CompletedProcess[str]:
        for prefix, handler in reversed(self.handlers):
            if args[: len(prefix)] == prefix:
                value = handler(args)
                if isinstance(value, subprocess.CompletedProcess):
                    return value
                if isinstance(value, int):
                    return done(args, "", value)
                return done(args, value or "")
        if len(args) >= 3 and args[1] == "inspect" and args[0] in (
            "container", "network", "volume", "image"
        ):  # fmt: skip
            info = self.objects.get((args[0], args[-1]))
            if info is None:
                return done(args, "", 1)
            return done(args, json.dumps([info]))
        if args[:1] == ("ps",) or args[1:2] == ("ls",):
            kind = "container" if args[0] == "ps" else args[0]
            label = args[args.index("--filter") + 1].removeprefix("label=")
            key, _, value = label.partition("=")
            names = [
                name
                for (k, name), info in self.objects.items()
                if k == kind and _labels(k, info).get(key) == value
            ]
            return done(args, "".join(f"{n}\n" for n in names))
        if args[:1] == ("rm",) or args[1:2] == ("rm",):
            kind = "container" if args[0] == "rm" else args[0]
            self.objects.pop((kind, args[-1]), None)
        return done(args, "")


def _labels(kind: str, info: dict[str, Any]) -> dict[str, str]:
    if kind in ("container", "image"):
        return info.get("Config", {}).get("Labels", {})
    return info.get("Labels", {})


def done(args: tuple[str, ...], stdout: str, code: int = 0) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(list(args), code, stdout, "" if code == 0 else "boom")
