from __future__ import annotations

import tomllib
from pathlib import Path
from typing import Any

import pytest

from agent_sandbox import config, templates
from agent_sandbox.config import (
    DEFAULT_ENV_PASS,
    DEFAULT_STATE_PATHS,
    MountSpec,
    parse_project_config,
    parse_user_config,
)
from agent_sandbox.util import SandboxError


def test_minimal_project_config_gets_defaults() -> None:
    cfg = parse_project_config({"image": " ubuntu:24.04 "})
    assert cfg.image == "ubuntu:24.04"
    assert cfg.harness == [["claude"], ["copilot"], ["bash"], ["sh"]]
    assert cfg.env_pass == list(DEFAULT_ENV_PASS)
    assert cfg.env_set == {}
    assert cfg.mounts == []
    assert cfg.state_paths == list(DEFAULT_STATE_PATHS)
    assert cfg.protected == [".claude", ".agents", ".vscode", ".idea", ".devcontainer"]
    assert cfg.isolated == [".venv", "node_modules"]
    assert cfg.proxy_base_image is None


def test_full_project_config() -> None:
    cfg = parse_project_config(
        {
            "image": "img",
            "harness": "claude --verbose",
            "env": {"pass": ["TERM"], "set": {"A": "{home}/x"}},
            "mounts": [
                {"source": "/data/", "target": "/mnt/data"},
                {"source": "/opt", "check_secrets": False},
            ],
            "state": {"paths": [".claude", ".config/foo"]},
            "workspace": {"protected": [".claude/", "./.envrc"], "isolated": ["web/node_modules"]},
            "proxy": {"base_image": "mirror/alpine:3"},
        }
    )
    assert cfg.protected == [".claude", ".envrc"]
    assert cfg.isolated == ["web/node_modules"]
    assert cfg.harness == [["claude", "--verbose"]]
    assert cfg.env_pass == ["TERM"]
    assert cfg.env_set == {"A": "{home}/x"}
    assert cfg.mounts == [MountSpec("/data", "/mnt/data"), MountSpec("/opt", "/opt", False)]
    assert cfg.state_paths == [".claude", ".config/foo"]
    assert cfg.proxy_base_image == "mirror/alpine:3"


@pytest.mark.parametrize(
    ("data", "message"),
    [
        ({}, "`image` is required"),
        ({"image": "  "}, "non-empty string"),
        ({"image": "i", "devcontainer": {"enabled": True}}, "not both"),
        ({"devcontainer": {"enabled": False}}, "`image` is required"),
        ({"devcontainer": {"enabled": "yes"}}, "true or false"),
        ({"devcontainer": {"config": ".devcontainer/x/devcontainer.json"}}, "needs `enabled"),
        ({"devcontainer": {"enabled": True, "build": True}}, "unknown key"),
        ({"devcontainer": {"enabled": True, "config": ".devcontainer.json"}}, "must be"),
        ({"devcontainer": {"enabled": True, "config": "dc/devcontainer.json"}}, "must be"),
        (
            {"devcontainer": {"enabled": True, "config": ".devcontainer/a/b/devcontainer.json"}},
            "must be",
        ),
        (
            {"devcontainer": {"enabled": True, "config": ".devcontainer/../devcontainer.json"}},
            "must be",
        ),
        ({"devcontainer": {"enabled": True, "config": ".devcontainer/x/other.json"}}, "must be"),
        (
            {"devcontainer": {"enabled": True}, "workspace": {"isolated": [".devcontainer/x"]}},
            "both",
        ),
        ({"image": "i", "setup": {"create": "uv sync"}}, "list of strings"),
        ({"image": "i", "setup": {"start": [" "]}}, "must not be empty"),
        ({"image": "i", "setup": {"stop": []}}, "unknown key"),
        ({"image": "i", "colour": "red"}, "unknown key"),
        ({"image": "i", "harness": ""}, "must not be empty"),
        ({"image": "i", "harness": []}, "non-empty list"),
        ({"image": "i", "harness": ["claude", 1]}, "non-empty list"),
        ({"image": "i", "harness": ["claude", " "]}, "must not be empty"),
        ({"image": "i", "harness": ["claude", "'unterminated"]}, "cannot parse harness"),
        ({"image": "i", "env": []}, r"\[env\] must be a table"),
        ({"image": "i", "env": {"keep": []}}, "unknown key"),
        ({"image": "i", "env": {"pass": "TERM"}}, "list of strings"),
        ({"image": "i", "env": {"pass": ["BAD-NAME"]}}, "invalid environment variable"),
        ({"image": "i", "env": {"set": {"X": 1}}}, "map variable names to strings"),
        ({"image": "i", "env": {"set": {"1X": "v"}}}, "invalid environment variable"),
        ({"image": "i", "mounts": {"source": "/a"}}, "array of tables"),
        ({"image": "i", "mounts": ["/a"]}, "must be a table"),
        ({"image": "i", "mounts": [{"source": "/a", "mode": "rw"}]}, "unknown key"),
        ({"image": "i", "mounts": [{"source": "/a", "check_secrets": "no"}]}, "true or false"),
        ({"image": "i", "mounts": [{"target": "/a"}]}, "string `source`"),
        ({"image": "i", "mounts": [{"source": "rel"}]}, "absolute"),
        ({"image": "i", "mounts": [{"source": "{home}/x"}]}, "source must be absolute"),
        ({"image": "i", "mounts": [{"source": "/a", "target": "~x"}]}, "target must be"),
        ({"image": "i", "workspace": {"protected": "x"}}, "list of strings"),
        ({"image": "i", "workspace": {"isolated": ["/abs"]}}, "inside the workspace"),
        ({"image": "i", "workspace": {"isolated": ["a/../.."]}}, "inside the workspace"),
        ({"image": "i", "workspace": {"protected": ["."]}}, "inside the workspace"),
        ({"image": "i", "workspace": {"protected": [".git/hooks"]}}, "already read-only"),
        ({"image": "i", "workspace": {"isolated": [".agent-sandbox"]}}, "already read-only"),
        ({"image": "i", "workspace": {"protected": ["a"], "isolated": ["a/b"]}}, "both"),
        ({"image": "i", "workspace": {"hidden": []}}, "unknown key"),
        ({"image": "i", "mounts": [{"source": "/a", "target": "rel"}]}, "absolute"),
        ({"image": "i", "state": {"paths": ["/abs"]}}, "relative to the home"),
        ({"image": "i", "state": {"paths": ["../up"]}}, "relative to the home"),
        ({"image": "i", "state": {"paths": ["."]}}, "relative to the home"),
        ({"image": "i", "state": {"paths": [""]}}, "relative to the home"),
        ({"image": "i", "state": {"dirs": []}}, "unknown key"),
        ({"image": "i", "proxy": {"base_image": ""}}, "base_image"),
        ({"image": "i", "proxy": {"image": "x"}}, "unknown key"),
    ],
)
def test_project_config_errors(data: dict[str, Any], message: str) -> None:
    with pytest.raises(SandboxError, match=message):
        parse_project_config(data)


def test_devcontainer_config() -> None:
    cfg = parse_project_config({"devcontainer": {"enabled": True}})
    assert (cfg.image, cfg.devcontainer) == (None, ".devcontainer/devcontainer.json")
    named = {"enabled": True, "config": "./.devcontainer/py/devcontainer.json"}
    assert parse_project_config({"devcontainer": named}).devcontainer == (
        ".devcontainer/py/devcontainer.json"
    )


def test_devcontainer_dir_is_always_protected_when_used() -> None:
    cfg = parse_project_config(
        {"devcontainer": {"enabled": True}, "workspace": {"protected": [".claude"]}}
    )
    assert cfg.protected == [".claude", ".devcontainer"]
    plain = parse_project_config({"image": "i", "workspace": {"protected": [".claude"]}})
    assert plain.protected == [".claude"]


def test_setup_commands() -> None:
    cfg = parse_project_config(
        {"image": "i", "setup": {"create": ["uv sync", "pre-commit install-hooks"], "start": ["x"]}}
    )
    assert cfg.setup_create == ["uv sync", "pre-commit install-hooks"]
    assert cfg.setup_start == ["x"]
    assert parse_project_config({"image": "i"}).setup_create == []


def test_user_config_devcontainer_cli() -> None:
    assert parse_user_config({}).devcontainer_cli == ["devcontainer"]
    cfg = parse_user_config({"devcontainer_cli": ["npx", "@devcontainers/cli"]})
    assert cfg.devcontainer_cli == ["npx", "@devcontainers/cli"]
    for bad in ([], [""], "devcontainer"):
        with pytest.raises(SandboxError, match="devcontainer_cli"):
            parse_user_config({"devcontainer_cli": bad})


def test_harness_list() -> None:
    cfg = parse_project_config({"image": "i", "harness": ["claude -c", "opencode", "sh"]})
    assert cfg.harness == [["claude", "-c"], ["opencode"], ["sh"]]


def test_user_config_harness() -> None:
    assert parse_user_config({}).harness_preference(Path("/w")) == []
    cfg = parse_user_config(
        {"harness": "copilot", "workspaces": {"/w/a": {"harness": ["claude -c", "claude"]}}}
    )
    assert cfg.harness_preference(Path("/w/a")) == [["claude", "-c"], ["claude"]]
    assert cfg.harness_preference(Path("/w/b")) == [["copilot"]]
    with pytest.raises(SandboxError, match="harness"):
        parse_user_config({"workspaces": {"/w": {"harness": []}}})


def test_init_template_parses_and_escapes() -> None:
    data = tomllib.loads(templates.render_config('reg/img:"tag"\\x'))
    cfg = parse_project_config(data)
    assert cfg.image == 'reg/img:"tag"\\x'
    assert cfg.env_set["CLAUDE_CONFIG_DIR"] == "{home}/.claude"
    assert cfg.state_paths == list(DEFAULT_STATE_PATHS)
    assert cfg.mounts == []
    assert cfg.harness == [["claude"], ["copilot"], ["bash"], ["sh"]]


def test_load_project_config(repo: Path) -> None:
    with pytest.raises(SandboxError, match="agent-sandbox init"):
        config.load_project_config(repo)
    (repo / ".agent-sandbox").mkdir()
    (repo / ".agent-sandbox" / "config.toml").write_text("image = [")
    with pytest.raises(SandboxError, match="invalid TOML"):
        config.load_project_config(repo)
    (repo / ".agent-sandbox" / "config.toml").write_text('image = "x"\n')
    assert config.load_project_config(repo).image == "x"


def test_user_config_defaults() -> None:
    cfg = parse_user_config({})
    assert (cfg.engine, cfg.allow_rootful, cfg.git, cfg.state_volume) == (
        "auto",
        False,
        "ro",
        "per-workspace",
    )
    assert cfg.docker_context is None


def test_user_config_overrides() -> None:
    cfg = parse_user_config(
        {
            "engine": "docker",
            "docker_context": "rootless",
            "allow_rootful": True,
            "git": "rw",
            "state_volume": "shared-login",
            "workspaces": {"/w/a": {"git": "ro"}, "/w/b": {"state_volume": "per-workspace"}},
            "proxy": {"base_image": "mirror/alpine:3"},
        }
    )
    assert cfg.engine == "docker" and cfg.docker_context == "rootless" and cfg.allow_rootful
    assert cfg.git_mode(Path("/w/a")) == "ro"
    assert cfg.git_mode(Path("/w/b")) == "rw"
    assert cfg.git_mode(Path("/other")) == "rw"
    assert cfg.state_scope(Path("/w/a")) == "shared-login"
    assert cfg.state_scope(Path("/w/b")) == "per-workspace"
    assert cfg.proxy_base_image == "mirror/alpine:3"


@pytest.mark.parametrize(
    "data",
    [
        {"engine": "lxc"},
        {"allow_rootful": "yes"},
        {"git": "readonly"},
        {"state_volume": "Bad Name"},
        {"workspaces": {"/w": {"image": "x"}}},
        {"workspaces": {"/w": "ro"}},
        {"docker_context": 1},
        {"unknown": 1},
    ],
)
def test_user_config_errors(data: dict[str, Any]) -> None:
    with pytest.raises(SandboxError):
        parse_user_config(data)


def test_load_user_config(isolated_dirs: Path) -> None:
    assert config.load_user_config().engine == "auto"
    path = config.user_config_path()
    assert path == isolated_dirs / "config" / "config.toml"
    path.parent.mkdir(parents=True)
    path.write_text('engine = "docker"\n')
    assert config.load_user_config().engine == "docker"


def test_mount_paths_with_home(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    cfg = parse_project_config(
        {
            "image": "i",
            "mounts": [{"source": "~/.agents/skills"}, {"source": "/a", "target": "{home}/a"}],
        }
    )
    assert cfg.mounts == [
        MountSpec(f"{tmp_path}/.agents/skills", "~/.agents/skills"),
        MountSpec("/a", "{home}/a"),
    ]
