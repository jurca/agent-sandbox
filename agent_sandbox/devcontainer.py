"""A devcontainer configuration as the workspace base (opt-in, `[devcontainer] enabled`).

The devcontainers CLI only builds the image (`devcontainer build --frozen-lockfile`), so
Features install exactly as they do for people using the dev container. Nothing it would apply
to a container is taken from it: the container is created as for any other image, and what
devcontainer.json asks of a container is read from the image's metadata label and either mapped
(environment, lifecycle commands, remote user) or reported as not applied.
"""

from __future__ import annotations

import json
import os
import re
import shlex
import shutil
import subprocess
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, TypeGuard

from .approval import tree_files, tree_hash
from .config import DEVCONTAINER_DIR, UserConfig
from .engine import Engine
from .images import project_tag
from .project import LABEL_KIND, Project
from .util import SandboxError, eprint

LABEL_METADATA = "devcontainer.metadata"
LOCKFILE = "devcontainer-lock.json"
CREATE_HOOKS = ("onCreateCommand", "updateContentCommand", "postCreateCommand")
CONFIG_ORIGIN = "devcontainer.json"

# Keys of devcontainer.json that only take effect when the CLI creates the container. They are
# not in the image metadata, so `read-configuration` is the only place to see them.
_CONFIG_ONLY = {
    "initializeCommand": "runs on the host",
    "runArgs": "extra engine arguments",
    "workspaceMount": "the workspace is always mounted at its host path",
    "appPort": "ports are not published",
}
# Container settings that the metadata may carry (from devcontainer.json or a Feature).
_NOT_APPLIED = ("privileged", "capAdd", "securityOpt", "mounts", "entrypoint")

Command = str | list[str] | dict[str, str | list[str]]


@dataclass(frozen=True)
class Step:
    """One lifecycle command: from config.toml, devcontainer.json or a Feature (its id)."""

    origin: str
    hook: str
    command: Command


# --- the CLI ----------------------------------------------------------------------------


def cli_command(user: UserConfig) -> list[str]:
    command = list(user.devcontainer_cli)
    if shutil.which(command[0]) is None:
        raise SandboxError(
            f"The devcontainers CLI ({shlex.join(command)}) is not installed; it builds the image "
            "of a project with `[devcontainer] enabled = true`.\nInstall it (for example "
            "`npm install -g @devcontainers/cli`) or point `devcontainer_cli` in "
            '~/.config/agent-sandbox/config.toml at it (for example ["npx", "@devcontainers/cli"]).'
        )
    return command


def _cli_env(engine: Engine) -> dict[str, str]:
    env = dict(os.environ)
    if engine.context and engine.kind == "docker":
        env["DOCKER_CONTEXT"] = engine.context
    return env


def _result(stdout: str) -> dict[str, Any]:
    """The CLI prints one JSON object (its result) as the last line of stdout."""
    for line in reversed(stdout.splitlines()):
        line = line.strip()
        if line.startswith("{"):
            try:
                value = json.loads(line)
            except json.JSONDecodeError:
                break
            if isinstance(value, dict):
                return value
    return {"outcome": "error", "message": "no result from the devcontainers CLI"}


def run_cli(
    command: list[str], engine: Engine, *args: str, show_progress: bool = False
) -> dict[str, Any]:
    """Run a CLI subcommand; its log goes to the terminal only when asked or when it fails."""
    process = subprocess.run(
        [*command, *args, "--docker-path", engine.kind],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=None if show_progress else subprocess.PIPE,
        text=True,
        errors="replace",
        env=_cli_env(engine),
        check=False,
    )
    result = _result(process.stdout)
    if result.get("outcome") == "error" and not show_progress and process.stderr:
        eprint(process.stderr.rstrip()[-4000:])
    return result


def upgrade_hint(user: UserConfig, config_rel: str) -> str:
    return f"{shlex.join(user.devcontainer_cli)} upgrade --workspace-folder . --config {config_rel}"


def build_error(result: dict[str, Any], user: UserConfig, config_rel: str) -> SandboxError:
    message = str(result.get("message") or result.get("description") or "unknown error")
    lockfile = str(PurePosixPath(config_rel).parent / LOCKFILE)
    upgrade = upgrade_hint(user, config_rel)
    after = (
        "Review the lockfile, commit it, and run agent-sandbox again (it asks you to approve "
        "the change)."
    )
    if "Lockfile does not exist" in message:
        return SandboxError(
            f"{config_rel} has no lockfile ({lockfile}), so its Features are not pinned and "
            f"cannot be reviewed. Create it on the host:\n  {upgrade}\n{after}"
        )
    if "Lockfile does not match" in message:
        return SandboxError(
            f"{lockfile} does not match the Features in {config_rel}.\n"
            f"See the lockfile it would write (nothing is changed):\n  {upgrade} --dry-run\n"
            f"then update it:\n  {upgrade}\n{after}"
        )
    return SandboxError(f"The devcontainer build failed: {message}")


# --- checking the configuration ---------------------------------------------------------


def _inside(path: Path, root: Path) -> bool:
    return path.resolve() == root.resolve() or path.resolve().is_relative_to(root.resolve())


def _build_paths(configuration: dict[str, Any]) -> tuple[str | None, str | None]:
    build = configuration.get("build")
    build = build if isinstance(build, dict) else {}
    dockerfile = (
        build.get("dockerfile") or build.get("dockerFile") or configuration.get("dockerFile")
    )
    context = build.get("context") or configuration.get("context")
    return (
        dockerfile if isinstance(dockerfile, str) else None,
        context if isinstance(context, str) else None,
    )


def check_configuration(
    root: Path, config_rel: str, configuration: dict[str, Any]
) -> tuple[list[str], Path | None]:
    """Refuse what would let agent-written files steer the build; returns (warnings, Dockerfile).

    `configuration` is `read-configuration`'s result: parsed JSONC with host variables already
    substituted, used for these checks only.
    """
    config_dir = (root / config_rel).parent
    allowed = root / DEVCONTAINER_DIR
    if "dockerComposeFile" in configuration:
        raise SandboxError(f"{config_rel}: Docker Compose devcontainers are not supported.")
    warnings: list[str] = []
    dockerfile_rel, context_rel = _build_paths(configuration)
    dockerfile = None
    if dockerfile_rel:
        dockerfile = config_dir / dockerfile_rel
        if not _inside(dockerfile, allowed):
            raise SandboxError(
                f"{config_rel}: the Dockerfile {dockerfile_rel} is outside {DEVCONTAINER_DIR}/, "
                "so the agent could change how the image is built. Move it into "
                f"{DEVCONTAINER_DIR}/."
            )
        if context_rel and not _inside(config_dir / context_rel, allowed):
            warnings.append(
                f"the build context {context_rel} reaches outside {DEVCONTAINER_DIR}/: files "
                "the agent wrote can be copied into the image (the Dockerfile decides which)"
            )
    features = configuration.get("features")
    for ref in features if isinstance(features, dict) else {}:
        local = isinstance(ref, str) and ref.startswith(("./", "../", "/"))
        if local and not _inside(config_dir / ref, allowed):
            raise SandboxError(
                f"{config_rel}: the local Feature {ref} is outside {DEVCONTAINER_DIR}/, so "
                "the agent could change what it installs."
            )
    for key, why in _CONFIG_ONLY.items():
        if configuration.get(key):
            warnings.append(f"{key} is not applied ({why})")
    folder = configuration.get("workspaceFolder")
    if isinstance(folder, str) and folder and folder != str(root):
        warnings.append(
            f"workspaceFolder {folder} is not used: the workspace is at {root} in the sandbox"
        )
    return warnings, dockerfile


_FROM = re.compile(r"^\s*FROM\s+(.+)$", re.IGNORECASE)


def dockerfile_bases(text: str) -> list[str]:
    """External images named by FROM lines (stage references and `scratch` excluded)."""
    stages: set[str] = set()
    bases: list[str] = []
    for line in text.replace("\\\n", " ").splitlines():
        match = _FROM.match(line)
        if not match:
            continue
        words = [w for w in match.group(1).split() if not w.startswith("--")]
        if not words:
            continue
        image = words[0]
        if len(words) >= 3 and words[1].lower() == "as":
            stages.add(words[2].lower())
        if image.lower() not in stages and image != "scratch":
            bases.append(image)
    return bases


def unpinned_bases(configuration: dict[str, Any], dockerfile: Path | None) -> list[str]:
    refs: list[str] = []
    image = configuration.get("image")
    if isinstance(image, str) and image:
        refs.append(image)
    if dockerfile is not None and dockerfile.is_file():
        refs += dockerfile_bases(dockerfile.read_text(errors="replace"))
    return [ref for ref in refs if "@sha256:" not in ref]


def unpinned_warning(ref: str) -> str:
    if "$" in ref:
        return f"base image {ref} comes from a build argument; check that it is pinned by digest"
    return (
        f"base image {ref} is not pinned by digest (@sha256:...); a changed image is noticed, "
        "but you cannot review what changed"
    )


# --- building ---------------------------------------------------------------------------


def image_tag(project: Project, user: str) -> str:
    """Named after the approved `.devcontainer/` tree, so any change builds a new image.

    Per user: `${localEnv:...}` in the configuration can carry the user's environment into it.
    """
    digest = tree_hash(tree_files(project.root / DEVCONTAINER_DIR))[:12]
    return project_tag(user, project.id, "devcontainer", digest)


def config_file(root: Path, config_rel: str) -> Path:
    path = root / config_rel
    if not path.is_file():
        hint = ""
        if (root / ".devcontainer.json").is_file():
            hint = (
                "\n.devcontainer.json in the workspace root is not used: the agent can write "
                f"there. Move it to {DEVCONTAINER_DIR}/devcontainer.json (VS Code and the "
                "devcontainers CLI find it there as well)."
            )
        raise SandboxError(f"{config_rel} does not exist.{hint}")
    return path


def ensure_image(
    engine: Engine,
    user: UserConfig,
    project: Project,
    config_rel: str,
    *,
    username: str,
    rebuild: bool = False,
    pull: bool = False,
) -> str:
    """Check the configuration, warn about what will not apply, and build the image if needed."""
    root = project.root
    config_file(root, config_rel)
    command = cli_command(user)
    common = ["--workspace-folder", str(root), "--config", str(root / config_rel)]
    result = run_cli(command, engine, "read-configuration", *common)
    if result.get("outcome") == "error":
        raise SandboxError(
            f"Could not read {config_rel}: {result.get('message') or result.get('description')}"
        )
    configuration = result.get("configuration") or {}
    warnings, dockerfile = check_configuration(root, config_rel, configuration)
    warnings += [unpinned_warning(ref) for ref in unpinned_bases(configuration, dockerfile)]
    for warning in warnings:
        eprint(f"warning: {config_rel}: {warning}")
    tag = image_tag(project, username)
    if engine.image_id(tag) and not rebuild:
        return tag
    image = configuration.get("image")
    if pull and isinstance(image, str) and image:
        engine.run("pull", image, capture=False)
    eprint(f"Building {tag} from {config_rel} (devcontainers CLI) ...")
    args = [*common, "--frozen-lockfile", "--image-name", tag]
    args += ["--label", f"{LABEL_KIND}=devcontainer"]
    if rebuild:
        args.append("--no-cache")
    result = run_cli(command, engine, "build", *args, show_progress=True)
    if result.get("outcome") != "success":
        raise build_error(result, user, config_rel)
    if not engine.image_id(tag):
        raise SandboxError(f"The devcontainers CLI reported success, but {tag} does not exist.")
    return tag


# --- the image metadata -----------------------------------------------------------------


def parse_metadata(labels: dict[str, str]) -> list[dict[str, Any]]:
    """Feature entries (with their `id`) in install order, then the devcontainer.json entry."""
    raw = labels.get(LABEL_METADATA)
    if not raw:
        return []
    try:
        value = json.loads(raw)
    except json.JSONDecodeError:
        return []
    entries = value if isinstance(value, list) else [value]
    return [entry for entry in entries if isinstance(entry, dict)]


def origin(entry: dict[str, Any]) -> str:
    return str(entry.get("id") or CONFIG_ORIGIN)


def remote_user(metadata: list[dict[str, Any]], image_user: str | None) -> str | None:
    """The user the CLI would run things as, or None for root (or a bare uid).

    Resolved like the CLI does: the last `remoteUser`, else the last `containerUser`, else the
    image's USER.
    """
    name = None
    for key in ("remoteUser", "containerUser"):
        values = [e[key] for e in metadata if isinstance(e.get(key), str) and e[key]]
        if values:
            name = values[-1]
            break
    if name is None:
        name = (image_user or "").partition(":")[0]
    if not name or name == "root" or name.isdigit():
        return None
    return name


def not_applied(metadata: list[dict[str, Any]]) -> list[str]:
    messages: list[str] = []
    for entry in metadata:
        found = [key for key in _NOT_APPLIED if entry.get(key)]
        if not found:
            continue
        what = ", ".join(found)
        if "id" in entry:
            messages.append(
                f"Feature {entry['id']} asks for {what}, which the sandbox does not apply; "
                "it is installed, but what needs them (a daemon, a mount) will not work"
            )
        else:
            messages.append(f"{CONFIG_ORIGIN}: {what} is not applied in the sandbox")
    return messages


def remote_env(metadata: list[dict[str, Any]]) -> dict[str, str | None]:
    merged: dict[str, str | None] = {}
    for entry in metadata:
        env = entry.get("remoteEnv")
        if isinstance(env, dict):
            for key, value in env.items():
                if isinstance(key, str) and (value is None or isinstance(value, str)):
                    merged[key] = value
    return merged


def steps(metadata: list[dict[str, Any]], hook: str) -> list[Step]:
    found: list[Step] = []
    for entry in metadata:
        command = entry.get(hook)
        if _valid_command(command):
            found.append(Step(origin(entry), hook, command))
    return found


def _valid_command(command: Any) -> TypeGuard[Command]:
    if isinstance(command, str):
        return bool(command.strip())
    if isinstance(command, list):
        return bool(command) and all(isinstance(word, str) for word in command)
    if isinstance(command, dict):
        return bool(command) and all(
            isinstance(name, str) and _valid_command(value) and not isinstance(value, dict)
            for name, value in command.items()
        )
    return False


# --- variables --------------------------------------------------------------------------

_VARIABLE = re.compile(r"\$\{([^}]+)\}")


@dataclass
class Substitution:
    """What `${...}` in metadata resolves to. Anything else is left for the shell."""

    workspace: Path
    devcontainer_id: str
    env_pass: list[str]
    container_env: dict[str, str]
    warn: Callable[[str], None] = eprint

    def text(self, value: str) -> str:
        return _VARIABLE.sub(self._replace, value)

    def words(self, command: str | list[str]) -> str | list[str]:
        if isinstance(command, str):
            return self.text(command)
        return [self.text(word) for word in command]

    def command(self, command: Command) -> Command:
        if isinstance(command, dict):
            return {name: self.words(value) for name, value in command.items()}
        return self.words(command)

    def _replace(self, match: re.Match[str]) -> str:
        expr = match.group(1)
        if expr in ("localWorkspaceFolder", "containerWorkspaceFolder"):
            return str(self.workspace)
        if expr in ("localWorkspaceFolderBasename", "containerWorkspaceFolderBasename"):
            return self.workspace.name
        if expr == "devcontainerId":
            return self.devcontainer_id
        kind, _, rest = expr.partition(":")
        name, _, default = rest.partition(":")
        if kind == "containerEnv" and name:
            return self.container_env.get(name, default)
        if kind in ("localEnv", "env") and name:
            if name in self.env_pass:
                return os.environ.get(name, default)
            self.warn(
                f"warning: ${{{expr}}} reads host variable {name}, which is not in [env] pass; "
                + (f"using its default {default!r}" if default else "using an empty value")
            )
            return default
        return match.group(0)
