"""Thin wrapper around the docker/podman command line."""

from __future__ import annotations

import io
import json
import os
import shutil
import subprocess
import sys
import tarfile
import time
from collections.abc import Mapping
from typing import Any

from .config import UserConfig
from .util import SandboxError

ENGINE_ENV_ROOTFUL = "AGENT_SANDBOX_ALLOW_ROOTFUL"


class EngineError(SandboxError):
    pass


class Engine:
    def __init__(
        self,
        kind: str,
        *,
        rootless: bool,
        context: str | None = None,
        selinux: bool = False,
    ) -> None:
        self.kind = kind
        self.rootless = rootless
        self.context = context
        self.selinux = selinux

    @property
    def mode(self) -> str:
        return f"{self.kind} ({'rootless' if self.rootless else 'rootful'})"

    def base_cmd(self) -> list[str]:
        cmd = [self.kind]
        if self.context and self.kind == "docker":
            cmd += ["--context", self.context]
        return cmd

    def run(
        self,
        *args: str,
        check: bool = True,
        capture: bool = True,
        input: str | None = None,
    ) -> subprocess.CompletedProcess[str]:
        cmd = [*self.base_cmd(), *args]
        # Uncaptured output (pull, build) is shown on stderr so stdout stays machine-readable.
        streams: dict[str, Any] = {"capture_output": True} if capture else {"stdout": 2}
        try:
            result = subprocess.run(cmd, text=True, input=input, check=False, **streams)
        except FileNotFoundError as exc:
            raise EngineError(f"{self.kind} is not installed: {exc}") from exc
        if check and result.returncode != 0:
            detail = (result.stderr or "").strip() if capture else ""
            raise EngineError(
                f"`{' '.join(cmd[:4])}...` failed with exit code {result.returncode}"
                + (f":\n{detail}" if detail else ".")
            )
        return result

    def copy_in(
        self, container: str, directory: str, files: Mapping[str, str], *, uid: int, gid: int
    ) -> None:
        """Write files into a (possibly stopped) container; owner and mode come from the tar."""
        cmd = [*self.base_cmd(), "cp", "-", f"{container}:{directory}"]
        archive = tar_archive(files, uid=uid, gid=gid)
        result = subprocess.run(cmd, input=archive, capture_output=True, check=False)
        if result.returncode != 0:
            detail = result.stderr.decode("utf-8", "replace").strip()
            raise EngineError(f"Copying into {container} failed: {detail}")

    def exec_replace(self, args: list[str]) -> None:
        """Replace this process with the engine, so the terminal and exit code pass through."""
        cmd = [*self.base_cmd(), *args]
        sys.stdout.flush()
        sys.stderr.flush()
        os.execvp(cmd[0], cmd)

    def inspect(self, kind: str, name: str) -> dict[str, Any] | None:
        result = self.run(kind, "inspect", name, check=False)
        if result.returncode != 0:
            return None
        try:
            data = json.loads(result.stdout)
        except json.JSONDecodeError:
            return None
        return data[0] if data else None

    def labels(self, kind: str, name: str) -> dict[str, str] | None:
        info = self.inspect(kind, name)
        return None if info is None else labels_of(kind, info)

    def exists(self, kind: str, name: str) -> bool:
        return self.run(kind, "inspect", name, check=False).returncode == 0

    def image_id(self, ref: str) -> str | None:
        result = self.run("image", "inspect", "--format", "{{.Id}}", ref, check=False)
        return result.stdout.strip() or None if result.returncode == 0 else None

    def container_status(self, name: str) -> str | None:
        info = self.inspect("container", name)
        return None if info is None else info.get("State", {}).get("Status")

    def list_names(self, kind: str, label: str) -> list[str]:
        if kind == "container":
            args = ["ps", "-a", "--filter", f"label={label}", "--format", "{{.Names}}"]
        else:
            args = [kind, "ls", "--filter", f"label={label}", "--format", "{{.Name}}"]
        result = self.run(*args, check=False)
        return [line for line in result.stdout.splitlines() if line.strip()]

    def pull_if_missing(self, ref: str) -> str:
        if image_id := self.image_id(ref):
            return image_id
        print(f"Pulling {ref} ...", file=sys.stderr, flush=True)
        self.run("pull", ref, capture=False)
        if not (image_id := self.image_id(ref)):
            raise EngineError(f"Image {ref} is not available after pulling.")
        return image_id

    def security_modules(self) -> set[str]:
        """The Linux security modules ("apparmor", "selinux") the engine can confine with, as
        it reports them (so a remote docker context reports its own host)."""
        if self.kind == "docker":
            result = self.run("info", "--format", "{{json .SecurityOptions}}", check=False)
            options = _json_or(result.stdout if result.returncode == 0 else "", [])
            if not isinstance(options, list):
                options = []
            names = {
                part.removeprefix("name=")
                for option in options if isinstance(option, str)
                for part in option.split(",") if part.startswith("name=")
            }  # fmt: skip
        else:
            result = self.run("info", "--format", "{{json .Host.Security}}", check=False)
            security = _json_or(result.stdout if result.returncode == 0 else "", {})
            if not isinstance(security, dict):
                security = {}
            names = {
                name
                for name, key in (("apparmor", "apparmorEnabled"), ("selinux", "selinuxEnabled"))
                if security.get(key) is True
            }
        return names & {"apparmor", "selinux"}

    def resource_support(self) -> set[str] | None:
        """The limits ("pids", "memory", "cpus"; for docker also "swap") the engine can enforce,
        or None if it cannot tell. Docker only warns about (and drops) a limit whose cgroup
        controller is missing, as on a rootless engine without cgroup v2 delegation."""
        if self.kind == "docker":
            result = self.run("info", "--format", "{{json .}}", check=False)
            info = _json_or(result.stdout if result.returncode == 0 else "", None)
            if not isinstance(info, dict):
                return None
            keys = {
                "pids": "PidsLimit", "memory": "MemoryLimit", "cpus": "CpuCfsQuota",
                "swap": "SwapLimit",
            }  # fmt: skip
            return {name for name, key in keys.items() if info.get(key) is True}
        result = self.run("info", "--format", "{{json .Host.CgroupControllers}}", check=False)
        controllers = _json_or(result.stdout if result.returncode == 0 else "", None)
        if not isinstance(controllers, list):
            return None
        keys = {"pids": "pids", "memory": "memory", "cpus": "cpu"}
        return {name for name, controller in keys.items() if controller in controllers}

    def cpu_count(self) -> int | None:
        """CPUs of the engine's host (a remote docker context reports its own), if it says."""
        field = "{{.NCPU}}" if self.kind == "docker" else "{{.Host.CPUs}}"
        result = self.run("info", "--format", field, check=False)
        try:
            count = int(result.stdout.strip()) if result.returncode == 0 else 0
        except ValueError:
            return None
        return count if count > 0 else None

    def network_subnet(self, name: str) -> str | None:
        info = self.inspect("network", name)
        if not info:
            return None
        configs = (info.get("IPAM") or {}).get("Config") or []
        if configs and configs[0].get("Subnet"):
            return configs[0]["Subnet"]
        subnets = info.get("subnets") or info.get("Subnets") or []
        if subnets:
            return subnets[0].get("subnet") or subnets[0].get("Subnet")
        return None


def _json_or(text: str, default: Any) -> Any:
    try:
        return json.loads(text)
    except ValueError:
        return default


def tar_archive(files: Mapping[str, str], *, uid: int, gid: int, mode: int = 0o600) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w", format=tarfile.PAX_FORMAT) as tar:
        for name, text in files.items():
            data = text.encode()
            info = tarfile.TarInfo(name)
            info.size, info.uid, info.gid, info.mode = len(data), uid, gid, mode
            info.mtime = int(time.time())
            tar.addfile(info, io.BytesIO(data))
    return buffer.getvalue()


def labels_of(kind: str, info: dict[str, Any]) -> dict[str, str]:
    if kind in ("container", "image"):
        labels = (info.get("Config") or {}).get("Labels") or info.get("Labels") or {}
    else:
        labels = info.get("Labels") or {}
    return dict(labels)


def _probe(kind: str, context: str | None) -> Engine | None:
    if shutil.which(kind) is None:
        return None
    engine = Engine(kind, rootless=False, context=context)
    if kind == "docker":
        result = engine.run("info", "--format", "{{json .SecurityOptions}}", check=False)
        if result.returncode != 0:
            return None
        engine.rootless = "rootless" in result.stdout
    else:
        result = engine.run("info", "--format", "{{.Host.Security.Rootless}}", check=False)
        if result.returncode != 0:
            return None
        engine.rootless = result.stdout.strip() == "true"
    if shutil.which("selinuxenabled"):
        engine.selinux = subprocess.run(["selinuxenabled"], check=False).returncode == 0
    return engine


def probe_engines(user: UserConfig) -> list[Engine]:
    """Every usable engine, regardless of the rootful policy (for listing and cleanup)."""
    kinds = ["podman", "docker"] if user.engine == "auto" else [user.engine]
    return [engine for kind in kinds if (engine := _probe(kind, user.docker_context))]


def detect_engine(user: UserConfig) -> Engine:
    candidates = ["podman", "docker"] if user.engine == "auto" else [user.engine]
    for kind in candidates:
        if engine := _probe(kind, user.docker_context):
            break
    else:
        wanted = "podman or docker" if user.engine == "auto" else user.engine
        raise EngineError(f"No usable container engine found (looked for {wanted}).")
    allowed = user.allow_rootful or os.environ.get(ENGINE_ENV_ROOTFUL) == "1"
    if not engine.rootless and not allowed:
        raise EngineError(
            f"{engine.kind} runs rootful: root inside the container is root on this host.\n"
            "If you accept that, set `allow_rootful = true` in "
            "~/.config/agent-sandbox/config.toml."
        )
    return engine
