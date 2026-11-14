"""Project (`.agent-sandbox/config.toml`) and user-level configuration."""

from __future__ import annotations

import re
import shlex
import tomllib
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any

from .util import SandboxError, config_dir

PROJECT_DIR = ".agent-sandbox"
CONFIG_FILE = "config.toml"
PROXY_CONF_FILE = "tinyproxy.conf"
ALLOW_BASE_FILE = "allow.base"
ALLOW_EXTRA_FILE = "allow.extra"
STANDARD_FILES = (CONFIG_FILE, PROXY_CONF_FILE, ALLOW_BASE_FILE, ALLOW_EXTRA_FILE)
DOCKERFILE = "Dockerfile"
DEVCONTAINER_DIR = ".devcontainer"
DEFAULT_DEVCONTAINER_CONFIG = f"{DEVCONTAINER_DIR}/devcontainer.json"
DEFAULT_DEVCONTAINER_CLI = ("devcontainer",)

DEFAULT_HARNESS = ("claude", "copilot", "bash", "sh")
DEFAULT_ENV_PASS = ("TERM", "COLORTERM", "LANG", "LC_ALL", "TZ")
DEFAULT_STATE_PATHS = (".claude", ".copilot", ".cache/pre-commit")
DEFAULT_PROTECTED = (".claude", ".agents", ".vscode", ".idea", ".devcontainer")
DEFAULT_ISOLATED = (".venv", "node_modules")
DEFAULT_SECRETS = (".env", ".env.*", "*.env")
DEFAULT_SECRETS_EXCEPT = (".env.example", ".env.sample", ".env.template")
DEFAULT_PROXY_BASE_IMAGE = "alpine:3"

_ENV_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*$")
_VOLUME_NAME = re.compile(r"[a-z0-9][a-z0-9_.-]*$")


@dataclass(frozen=True)
class MountSpec:
    """An extra read-only bind mount.

    `source` is an absolute host path (`~` already expanded). `target` is absolute, or starts
    with `~` / `{home}` for the container user's home directory, which is only known once the
    image is built. `check_secrets` false skips the secret file check of this mount,
    `check_sockets` false the unix socket check.
    """

    source: str
    target: str
    check_secrets: bool = True
    check_sockets: bool = True


@dataclass
class ProjectConfig:
    image: str | None = None
    # devcontainer.json (relative to the workspace root) when the devcontainer is the base.
    devcontainer: str | None = None
    # Candidate command lines (already split), tried in order; the first one installed runs.
    harness: list[list[str]] = field(default_factory=lambda: _default_harness())
    env_pass: list[str] = field(default_factory=lambda: list(DEFAULT_ENV_PASS))
    env_set: dict[str, str] = field(default_factory=dict)
    mounts: list[MountSpec] = field(default_factory=list)
    state_paths: list[str] = field(default_factory=lambda: list(DEFAULT_STATE_PATHS))
    protected: list[str] = field(default_factory=lambda: list(DEFAULT_PROTECTED))
    isolated: list[str] = field(default_factory=lambda: list(DEFAULT_ISOLATED))
    secrets: list[str] = field(default_factory=lambda: list(DEFAULT_SECRETS))
    secrets_except: list[str] = field(default_factory=lambda: list(DEFAULT_SECRETS_EXCEPT))
    secrets_history_depth: int | None = None
    proxy_base_image: str | None = None
    setup_create: list[str] = field(default_factory=list)
    setup_start: list[str] = field(default_factory=list)


# Used for the limits a `[resources]` table leaves out: enough for a harness plus parallel unit
# tests on a laptop. Machines for large data simply do not opt in.
DEFAULT_RESOURCES: dict[str, int | str | float] = {"pids": 4096, "memory": "4g", "cpus": 4}
_MEMORY = re.compile(r"^[0-9]+(\.[0-9]+)?[bkmgt]?$", re.IGNORECASE)


@dataclass
class UserConfig:
    engine: str = "auto"
    docker_context: str | None = None
    allow_rootful: bool = False
    git: str = "ro"
    state_volume: str = "per-workspace"
    # Tried before the project's harness list: a personal preference among installed harnesses.
    harness: list[list[str]] = field(default_factory=list)
    workspaces: dict[str, dict[str, Any]] = field(default_factory=dict)
    proxy_base_image: str | None = None
    devcontainer_cli: list[str] = field(default_factory=lambda: list(DEFAULT_DEVCONTAINER_CLI))
    # None: no limits (the default); a table, even an empty one, opts in.
    resources: dict[str, int | str | float | bool] | None = None

    def resource_limits(self, workspace: Path) -> dict[str, str]:
        """The limits for this workspace, as engine argument values; `false` lifts one."""
        override = self.workspaces.get(str(workspace), {}).get("resources")
        if override is False or (self.resources is None and override is None):
            return {}
        merged = {**DEFAULT_RESOURCES, **(self.resources or {}), **(override or {})}
        return {key: str(value) for key, value in merged.items() if value is not False}

    def git_mode(self, workspace: Path) -> str:
        return self.workspaces.get(str(workspace), {}).get("git", self.git)

    def state_scope(self, workspace: Path) -> str:
        return self.workspaces.get(str(workspace), {}).get("state_volume", self.state_volume)

    def harness_preference(self, workspace: Path) -> list[list[str]]:
        return self.workspaces.get(str(workspace), {}).get("harness", self.harness)


def _default_harness() -> list[list[str]]:
    return [[command] for command in DEFAULT_HARNESS]


def _harness(value: Any, where: str) -> list[list[str]]:
    """A command line or a list of them, each split like a shell would (no expansion)."""
    lines = [value] if isinstance(value, str) else value
    if not isinstance(lines, list) or not lines or not all(isinstance(v, str) for v in lines):
        raise SandboxError(
            f"{where}: `harness` must be a command line or a non-empty list of command lines."
        )
    commands: list[list[str]] = []
    for line in lines:
        try:
            words = shlex.split(line)
        except ValueError as exc:
            raise SandboxError(f"{where}: cannot parse harness {line!r}: {exc}") from None
        if not words:
            raise SandboxError(f"{where}: harness command lines must not be empty.")
        commands.append(words)
    return commands


def _table(data: dict[str, Any], key: str, where: str) -> dict[str, Any]:
    value = data.get(key, {})
    if not isinstance(value, dict):
        raise SandboxError(f"{where}: [{key}] must be a table.")
    return value


def _only(table: dict[str, Any], allowed: set[str], where: str) -> None:
    unknown = sorted(set(table) - allowed)
    if unknown:
        raise SandboxError(
            f"{where}: unknown key(s) {', '.join(unknown)}. "
            f"Allowed here: {', '.join(sorted(allowed))}."
        )


def _string_list(value: Any, where: str) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise SandboxError(f"{where} must be a list of strings.")
    return list(value)


def _secret_settings(
    workspace: dict[str, Any], where: str
) -> tuple[list[str], list[str], int | None]:
    """A project adds to the defaults. It can exempt a name, but not switch the rules off."""
    patterns = list(DEFAULT_SECRETS)
    for pattern in _string_list(workspace.get("secrets", []), f"{where} [workspace] secrets"):
        if "/" in pattern or "[" in pattern or not pattern.strip("*?"):
            raise SandboxError(
                f"{where}: [workspace] secrets {pattern!r} must be a file name in which only `*` "
                "and `?` are special, and must not match every name."
            )
        if pattern not in patterns:
            patterns.append(pattern)
    exempt = list(DEFAULT_SECRETS_EXCEPT)
    where_except = f"{where} [workspace] secrets_except"
    for name in _string_list(workspace.get("secrets_except", []), where_except):
        if not name or any(char in name for char in "*?[/"):
            raise SandboxError(f"{where_except}: {name!r} must be one exact file name.")
        if name in patterns:
            raise SandboxError(f"{where_except}: {name!r} cannot be exempted.")
        if name not in exempt:
            exempt.append(name)
    depth = workspace.get("secrets_history_depth")
    if depth is not None and (not isinstance(depth, int) or isinstance(depth, bool) or depth < 1):
        raise SandboxError(
            f"{where}: [workspace] secrets_history_depth must be a positive integer."
        )
    return patterns, exempt, depth


def _workspace_paths(value: Any, where: str) -> list[str]:
    """Normalised paths relative to the workspace root, outside `.git` and the config dir."""
    paths: list[str] = []
    for raw in _string_list(value, where):
        path = PurePosixPath(raw)
        if not raw or path.is_absolute() or ".." in path.parts or str(path) == ".":
            raise SandboxError(f"{where}: {raw!r} must be a path inside the workspace.")
        if path.parts[0] in (".git", PROJECT_DIR):
            raise SandboxError(f"{where}: {raw!r} is already read-only in the sandbox.")
        paths.append(str(path))
    return paths


def _overlaps(a: str, b: str) -> bool:
    pa, pb = PurePosixPath(a), PurePosixPath(b)
    return pa == pb or pa in pb.parents or pb in pa.parents


def _mount_source(raw: str) -> str:
    if raw == "~" or raw.startswith("~/"):
        return str(Path.home()) + raw[1:]
    return raw


def _is_home_relative(target: str) -> bool:
    return any(target == p or target.startswith(p + "/") for p in ("~", "{home}"))


def _load_toml(path: Path) -> dict[str, Any]:
    try:
        with path.open("rb") as handle:
            return tomllib.load(handle)
    except FileNotFoundError:
        raise
    except tomllib.TOMLDecodeError as exc:
        raise SandboxError(f"{path}: invalid TOML: {exc}") from exc


def _devcontainer_config(data: dict[str, Any], where: str) -> str | None:
    table = _table(data, "devcontainer", where)
    _only(table, {"enabled", "config"}, f"{where} [devcontainer]")
    enabled = table.get("enabled", False)
    if not isinstance(enabled, bool):
        raise SandboxError(f"{where}: [devcontainer] enabled must be true or false.")
    raw = table.get("config", DEFAULT_DEVCONTAINER_CONFIG)
    if not enabled:
        if "config" in table:
            raise SandboxError(f"{where}: [devcontainer] config needs `enabled = true`.")
        return None
    path = PurePosixPath(raw) if isinstance(raw, str) else None
    if (
        path is None
        or path.is_absolute()
        or ".." in path.parts
        or len(path.parts) not in (2, 3)
        or path.parts[0] != DEVCONTAINER_DIR
        or path.name != "devcontainer.json"
    ):
        raise SandboxError(
            f"{where}: [devcontainer] config must be {DEFAULT_DEVCONTAINER_CONFIG} or "
            f"{DEVCONTAINER_DIR}/<name>/devcontainer.json: everything the image build reads "
            f"has to be in {DEVCONTAINER_DIR}/, which the agent cannot write."
        )
    return str(path)


def parse_project_config(data: dict[str, Any], where: str = CONFIG_FILE) -> ProjectConfig:
    _only(
        data,
        {
            "image",
            "devcontainer",
            "harness",
            "env",
            "workspace",
            "mounts",
            "state",
            "proxy",
            "setup",
        },
        where,
    )
    image = data.get("image")
    devcontainer = _devcontainer_config(data, where)
    if image is not None and (not isinstance(image, str) or not image.strip()):
        raise SandboxError(f"{where}: `image` must be a non-empty string.")
    if image is not None and devcontainer is not None:
        raise SandboxError(
            f"{where}: set either `image` or `[devcontainer] enabled = true`, not both."
        )
    if image is None and devcontainer is None:
        raise SandboxError(
            f"{where}: `image` is required (or `[devcontainer] enabled = true`). "
            "Run `agent-sandbox init --image IMAGE` or set it."
        )
    harness = _harness(data["harness"], where) if "harness" in data else _default_harness()

    env = _table(data, "env", where)
    _only(env, {"pass", "set"}, f"{where} [env]")
    env_pass = (
        _string_list(env["pass"], f"{where} [env] pass")
        if "pass" in env
        else list(DEFAULT_ENV_PASS)
    )
    env_set_raw = env.get("set", {})
    if not isinstance(env_set_raw, dict) or not all(
        isinstance(v, str) for v in env_set_raw.values()
    ):
        raise SandboxError(f"{where}: [env.set] must map variable names to strings.")
    for name in [*env_pass, *env_set_raw]:
        if not _ENV_NAME.match(name):
            raise SandboxError(f"{where}: invalid environment variable name {name!r}.")

    mounts: list[MountSpec] = []
    raw_mounts = data.get("mounts", [])
    if not isinstance(raw_mounts, list):
        raise SandboxError(f"{where}: `mounts` must be an array of tables ([[mounts]]).")
    for index, entry in enumerate(raw_mounts, start=1):
        if not isinstance(entry, dict):
            raise SandboxError(f"{where}: mounts entry {index} must be a table.")
        _only(
            entry,
            {"source", "target", "check_secrets", "check_sockets"},
            f"{where} [[mounts]] #{index}",
        )
        source, target = entry.get("source"), entry.get("target", entry.get("source"))
        if not isinstance(source, str) or not isinstance(target, str):
            raise SandboxError(f"{where}: mounts entry {index} needs string `source` and `target`.")
        source = _mount_source(source)
        if not source.startswith("/"):
            raise SandboxError(
                f"{where}: mounts entry {index}: source must be absolute or start with `~`."
            )
        if not target.startswith("/") and not _is_home_relative(target):
            raise SandboxError(
                f"{where}: mounts entry {index}: target must be absolute or start with "
                "`~` or `{home}`."
            )
        checks = {}
        for key in ("check_secrets", "check_sockets"):
            checks[key] = entry.get(key, True)
            if not isinstance(checks[key], bool):
                raise SandboxError(f"{where}: mounts entry {index}: {key} must be true or false.")
        mounts.append(MountSpec(source.rstrip("/") or "/", target.rstrip("/") or "/", **checks))

    workspace = _table(data, "workspace", where)
    _only(
        workspace,
        {"protected", "isolated", "secrets", "secrets_except", "secrets_history_depth"},
        f"{where} [workspace]",
    )
    secrets, secrets_except, secrets_history_depth = _secret_settings(workspace, where)
    protected = (
        _workspace_paths(workspace["protected"], f"{where} [workspace] protected")
        if "protected" in workspace
        else list(DEFAULT_PROTECTED)
    )
    isolated = (
        _workspace_paths(workspace["isolated"], f"{where} [workspace] isolated")
        if "isolated" in workspace
        else list(DEFAULT_ISOLATED)
    )
    if devcontainer is not None and DEVCONTAINER_DIR not in protected:
        protected.append(DEVCONTAINER_DIR)  # the image build reads it; the agent must not write it
    for a in protected:
        for b in isolated:
            if _overlaps(a, b):
                raise SandboxError(
                    f"{where}: [workspace] {a!r} cannot be both protected and isolated."
                )

    state = _table(data, "state", where)
    _only(state, {"paths"}, f"{where} [state]")
    state_paths = (
        _string_list(state["paths"], f"{where} [state] paths")
        if "paths" in state
        else list(DEFAULT_STATE_PATHS)
    )
    for rel in state_paths:
        parts = Path(rel).parts
        if not rel or rel.startswith("/") or ".." in parts or rel in (".", "~"):
            raise SandboxError(
                f"{where}: state path {rel!r} must be relative to the home directory."
            )

    proxy = _table(data, "proxy", where)
    _only(proxy, {"base_image"}, f"{where} [proxy]")
    base = proxy.get("base_image")
    if base is not None and (not isinstance(base, str) or not base.strip()):
        raise SandboxError(f"{where}: [proxy] base_image must be a non-empty string.")

    setup = _table(data, "setup", where)
    _only(setup, {"create", "start"}, f"{where} [setup]")
    setup_create = _string_list(setup.get("create", []), f"{where} [setup] create")
    setup_start = _string_list(setup.get("start", []), f"{where} [setup] start")
    for command in [*setup_create, *setup_start]:
        if not command.strip():
            raise SandboxError(f"{where}: [setup] commands must not be empty.")

    return ProjectConfig(
        image=image.strip() if image is not None else None,
        devcontainer=devcontainer,
        harness=harness,
        env_pass=env_pass,
        env_set=dict(env_set_raw),
        mounts=mounts,
        state_paths=state_paths,
        protected=protected,
        isolated=isolated,
        secrets=secrets,
        secrets_except=secrets_except,
        secrets_history_depth=secrets_history_depth,
        proxy_base_image=base,
        setup_create=setup_create,
        setup_start=setup_start,
    )


def load_project_config(workspace: Path) -> ProjectConfig:
    path = workspace / PROJECT_DIR / CONFIG_FILE
    try:
        data = _load_toml(path)
    except FileNotFoundError:
        raise SandboxError(
            f"No {PROJECT_DIR}/{CONFIG_FILE} in {workspace}.\n"
            "Create it with: agent-sandbox init --image IMAGE"
        ) from None
    return parse_project_config(data, f"{PROJECT_DIR}/{CONFIG_FILE}")


def parse_user_config(data: dict[str, Any], where: str = "user config") -> UserConfig:
    _only(
        data,
        {
            "engine",
            "docker_context",
            "allow_rootful",
            "git",
            "state_volume",
            "workspaces",
            "proxy",
            "devcontainer_cli",
            "harness",
            "resources",
        },
        where,
    )
    config = UserConfig()
    if "resources" in data:
        config.resources = _resources(data["resources"], f"{where} [resources]")
    if "harness" in data:
        config.harness = _harness(data["harness"], where)
    if "devcontainer_cli" in data:
        command = _string_list(data["devcontainer_cli"], f"{where}: devcontainer_cli")
        if not command or not command[0]:
            raise SandboxError(f"{where}: devcontainer_cli must name a command.")
        config.devcontainer_cli = command
    if "engine" in data:
        if data["engine"] not in ("auto", "docker", "podman"):
            raise SandboxError(f"{where}: engine must be auto, docker or podman.")
        config.engine = data["engine"]
    if "docker_context" in data:
        if not isinstance(data["docker_context"], str):
            raise SandboxError(f"{where}: docker_context must be a string.")
        config.docker_context = data["docker_context"] or None
    if "allow_rootful" in data:
        if not isinstance(data["allow_rootful"], bool):
            raise SandboxError(f"{where}: allow_rootful must be true or false.")
        config.allow_rootful = data["allow_rootful"]
    if "git" in data:
        config.git = _git_mode(data["git"], where)
    if "state_volume" in data:
        config.state_volume = _state_scope(data["state_volume"], where)
    for path, table in _table(data, "workspaces", where).items():
        if not isinstance(table, dict):
            raise SandboxError(f'{where}: [workspaces."{path}"] must be a table.')
        _only(
            table, {"git", "state_volume", "harness", "resources"}, f'{where} [workspaces."{path}"]'
        )
        override: dict[str, Any] = {}
        if "resources" in table:
            value = table["resources"]
            override["resources"] = (
                False
                if value is False
                else _resources(value, f'{where} [workspaces."{path}".resources]')
            )
        if "harness" in table:
            override["harness"] = _harness(table["harness"], f'{where} [workspaces."{path}"]')
        if "git" in table:
            override["git"] = _git_mode(table["git"], where)
        if "state_volume" in table:
            override["state_volume"] = _state_scope(table["state_volume"], where)
        config.workspaces[path] = override
    proxy = _table(data, "proxy", where)
    _only(proxy, {"base_image"}, f"{where} [proxy]")
    if isinstance(proxy.get("base_image"), str):
        config.proxy_base_image = proxy["base_image"]
    return config


def _resources(value: Any, where: str) -> dict[str, int | str | float | bool]:
    if not isinstance(value, dict):
        raise SandboxError(f"{where} must be a table (or `resources = false` for a workspace).")
    _only(value, set(DEFAULT_RESOURCES), where)
    limits: dict[str, int | str | float | bool] = {}
    for key, limit in value.items():
        if limit is False:
            limits[key] = False
        elif key == "pids" and type(limit) is int and limit > 0:
            limits[key] = limit
        elif key == "memory" and isinstance(limit, str) and _MEMORY.match(limit):
            limits[key] = limit.lower()
        elif key == "cpus" and type(limit) in (int, float) and limit > 0:
            limits[key] = limit
        else:
            expected = {
                "pids": "a positive integer",
                "memory": 'a size such as "4g" or "512m"',
                "cpus": "a positive number such as 4 or 1.5",
            }[key]
            raise SandboxError(f"{where}: {key} must be {expected}, or false for no limit.")
    return limits


def _git_mode(value: Any, where: str) -> str:
    if value not in ("ro", "rw"):
        raise SandboxError(f'{where}: git must be "ro" or "rw".')
    return value


def _state_scope(value: Any, where: str) -> str:
    if value != "per-workspace" and not (isinstance(value, str) and _VOLUME_NAME.match(value)):
        raise SandboxError(
            f'{where}: state_volume must be "per-workspace" or a volume name '
            "(lowercase letters, digits, `_`, `.`, `-`)."
        )
    return value


def user_config_path() -> Path:
    return config_dir() / "config.toml"


def load_user_config() -> UserConfig:
    path = user_config_path()
    try:
        data = _load_toml(path)
    except FileNotFoundError:
        return UserConfig()
    return parse_user_config(data, str(path))
