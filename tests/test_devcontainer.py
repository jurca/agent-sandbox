from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from agent_sandbox import devcontainer
from agent_sandbox.config import UserConfig
from agent_sandbox.devcontainer import Step, Substitution
from agent_sandbox.project import project_for
from agent_sandbox.util import SandboxError

from .fakes import FakeEngine

# Shaped like the label a prototype build with CLI 0.90.0 produced.
METADATA = [
    {"id": "ghcr.io/devcontainers/features/github-cli:1", "customizations": {"vscode": {}}},
    {
        "id": "ghcr.io/devcontainers/features/docker-in-docker:2",
        "privileged": True,
        "entrypoint": "/usr/local/share/docker-init.sh",
        "mounts": [{"source": "dind-${devcontainerId}", "target": "/var/lib/docker"}],
        "postStartCommand": "echo feature-start",
    },
    {
        "onCreateCommand": "echo oncreate ${containerWorkspaceFolder}",
        "postCreateCommand": {"a": "echo a ${localWorkspaceFolder}", "b": ["echo", "b"]},
        "postAttachCommand": "echo attach",
        "containerEnv": {"FROM_CONFIG": "yes"},
        "remoteUser": "dev",
        "remoteEnv": {"HOST_HOME": "${localEnv:HOME}", "DROP": None},
    },
]


def labels() -> dict[str, str]:
    return {devcontainer.LABEL_METADATA: json.dumps(METADATA)}


def test_parse_metadata() -> None:
    assert devcontainer.parse_metadata(labels()) == METADATA
    assert devcontainer.parse_metadata({}) == []
    assert devcontainer.parse_metadata({devcontainer.LABEL_METADATA: "{bad"}) == []
    single = {devcontainer.LABEL_METADATA: json.dumps({"remoteUser": "x"})}
    assert devcontainer.parse_metadata(single) == [{"remoteUser": "x"}]


@pytest.mark.parametrize(
    ("metadata", "image_user", "expected"),
    [
        (METADATA, "root", "dev"),
        ([{"remoteUser": "a"}, {"remoteUser": "b"}], None, "b"),  # the last one wins
        ([{"containerUser": "c"}], "vscode", "c"),
        ([{}], "vscode:vscode", "vscode"),
        ([{}], "", None),
        ([{}], "root", None),
        ([{"remoteUser": "root"}], "vscode", None),
        ([{}], "1000", None),  # a bare uid names nobody to remap
    ],
)
def test_remote_user(
    metadata: list[dict[str, Any]], image_user: str | None, expected: str | None
) -> None:
    assert devcontainer.remote_user(metadata, image_user) == expected


def test_not_applied_names_the_feature() -> None:
    messages = devcontainer.not_applied(METADATA)
    assert len(messages) == 1
    assert "docker-in-docker:2 asks for privileged, mounts, entrypoint" in messages[0]
    own = devcontainer.not_applied([{"capAdd": ["SYS_PTRACE"], "privileged": False}])
    assert own == ["devcontainer.json: capAdd is not applied in the sandbox"]


def test_remote_env_merges_in_order() -> None:
    merged = devcontainer.remote_env(
        [{"remoteEnv": {"A": "1", "B": "x"}}, {"remoteEnv": {"A": "2"}}]
    )
    assert merged == {"A": "2", "B": "x"}
    assert devcontainer.remote_env(METADATA) == {"HOST_HOME": "${localEnv:HOME}", "DROP": None}


def test_user_env_probe_takes_the_last_valid_value() -> None:
    assert devcontainer.user_env_probe([]) == "loginInteractiveShell"
    metadata = [{"userEnvProbe": "none"}, {"userEnvProbe": "interactiveShell"}, {"userEnvProbe": 1}]
    assert devcontainer.user_env_probe(metadata) == "interactiveShell"


def test_steps_keep_origin_and_order() -> None:
    assert devcontainer.steps(METADATA, "postStartCommand") == [
        Step(
            "ghcr.io/devcontainers/features/docker-in-docker:2",
            "postStartCommand",
            "echo feature-start",
        )
    ]
    created = devcontainer.steps(METADATA, "postCreateCommand")
    assert created == [
        Step(
            "devcontainer.json",
            "postCreateCommand",
            {"a": "echo a ${localWorkspaceFolder}", "b": ["echo", "b"]},
        )
    ]
    broken = [
        {"onCreateCommand": ""},
        {"onCreateCommand": [1]},
        {"onCreateCommand": {"x": {"y": "z"}}},
    ]
    assert devcontainer.steps(broken, "onCreateCommand") == []


def test_substitution(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TERM", "xterm")
    monkeypatch.setenv("SECRET", "s3cr3t")
    warnings: list[str] = []
    subst = Substitution(
        workspace=Path("/work/proj"),
        devcontainer_id="proj-1234",
        env_pass=["TERM", "UNSET"],
        container_env={"PATH": "/usr/bin"},
        warn=warnings.append,
    )
    assert (
        subst.text("${localWorkspaceFolder}|${containerWorkspaceFolderBasename}")
        == "/work/proj|proj"
    )
    assert subst.text("${localEnv:TERM}|${env:TERM}|${localEnv:UNSET:dflt}") == "xterm|xterm|dflt"
    assert subst.text("${containerEnv:PATH}:/x|${containerEnv:NOPE:d}") == "/usr/bin:/x|d"
    assert subst.text("${devcontainerId}") == "proj-1234"
    assert warnings == []
    assert subst.text("${localEnv:SECRET}|${localEnv:SECRET:fallback}") == "|fallback"
    assert len(warnings) == 2 and "not in [env] pass" in warnings[0]
    assert subst.text("echo ${HOME} $USER ${unknownThing}") == "echo ${HOME} $USER ${unknownThing}"
    assert subst.command({"a": ["x", "${localWorkspaceFolder}"], "b": "${devcontainerId}"}) == {
        "a": ["x", "/work/proj"],
        "b": "proj-1234",
    }


# --- configuration checks ---------------------------------------------------------------


@pytest.fixture
def dc_root(tmp_path: Path) -> Path:
    (tmp_path / ".devcontainer" / "py").mkdir(parents=True)
    return tmp_path


def test_check_configuration_accepts_files_inside(dc_root: Path) -> None:
    conf = {
        "build": {"dockerfile": "Dockerfile", "context": ".."},
        "features": {"./local-feature": {}, "ghcr.io/x/y:1": {}},
    }
    warnings, dockerfile = devcontainer.check_configuration(
        dc_root, ".devcontainer/py/devcontainer.json", conf
    )
    assert dockerfile == dc_root / ".devcontainer" / "py" / "Dockerfile"
    assert warnings == []  # `..` from py/ is still inside .devcontainer/


@pytest.mark.parametrize(
    ("conf", "message"),
    [
        ({"dockerComposeFile": "c.yml"}, "Docker Compose"),
        ({"build": {"dockerfile": "../Dockerfile"}}, "outside .devcontainer/"),
        ({"dockerFile": "../../x/Dockerfile"}, "outside .devcontainer/"),
        ({"features": {"../../feature": {}}}, "local Feature"),
    ],
)
def test_check_configuration_refuses(dc_root: Path, conf: dict[str, Any], message: str) -> None:
    with pytest.raises(SandboxError, match=message):
        devcontainer.check_configuration(dc_root, ".devcontainer/devcontainer.json", conf)


def test_check_configuration_warnings(dc_root: Path) -> None:
    conf = {
        "build": {"dockerfile": "Dockerfile", "context": ".."},
        "initializeCommand": "touch /tmp/x",
        "runArgs": ["--privileged"],
        "workspaceFolder": "/workspaces/x",
    }
    warnings, _ = devcontainer.check_configuration(dc_root, ".devcontainer/devcontainer.json", conf)
    assert any("build context .. reaches outside" in w for w in warnings)
    assert any(
        w.startswith("initializeCommand is not applied (runs on the host)") for w in warnings
    )
    assert any(w.startswith("runArgs is not applied") for w in warnings)
    assert any("workspaceFolder /workspaces/x is not used" in w for w in warnings)


def test_dockerfile_bases() -> None:
    text = (
        "ARG V=1\nFROM --platform=linux/amd64 debian:12 AS build\nRUN x\n"
        "FROM build AS second\nfrom scratch\nFROM \\\n  python@sha256:abc\nFROM ${BASE}\n"
    )
    assert devcontainer.dockerfile_bases(text) == ["debian:12", "python@sha256:abc", "${BASE}"]


def test_unpinned_bases(tmp_path: Path) -> None:
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text("FROM python@sha256:abc\nFROM node:22\n")
    assert devcontainer.unpinned_bases({"image": "debian:12"}, dockerfile) == [
        "debian:12",
        "node:22",
    ]
    assert devcontainer.unpinned_bases({"image": "debian@sha256:1"}, None) == []
    assert "build argument" in devcontainer.unpinned_warning("${BASE}")
    assert "not pinned by digest" in devcontainer.unpinned_warning("node:22")


# --- the CLI ----------------------------------------------------------------------------


def test_result_takes_the_last_json_line() -> None:
    out = 'noise\n{"outcome":"success","imageName":["x"]}\n'
    assert devcontainer._result(out)["outcome"] == "success"
    assert devcontainer._result("nothing")["outcome"] == "error"


def test_lockfile_errors_explain_what_to_do() -> None:
    user = UserConfig(devcontainer_cli=["npx", "@devcontainers/cli"])
    missing = devcontainer.build_error(
        {"outcome": "error", "message": "Lockfile does not exist."},
        user,
        ".devcontainer/devcontainer.json",
    )
    text = str(missing)
    assert ".devcontainer/devcontainer-lock.json" in text
    upgrade = "npx @devcontainers/cli upgrade --workspace-folder . --config "
    assert upgrade + ".devcontainer/devcontainer.json" in text
    outdated = str(
        devcontainer.build_error(
            {"outcome": "error", "message": "Lockfile does not match."},
            user,
            ".devcontainer/py/devcontainer.json",
        )
    )
    assert (
        "--dry-run" in outdated
        and ".devcontainer/py/devcontainer-lock.json does not match" in outdated
    )
    other = devcontainer.build_error({"outcome": "error", "description": "boom"}, user, "x")
    assert str(other) == "The devcontainer build failed: boom"


def test_cli_must_be_installed() -> None:
    with pytest.raises(SandboxError, match="npm install -g @devcontainers/cli"):
        devcontainer.cli_command(UserConfig(devcontainer_cli=["no-such-devcontainer-cli"]))


def test_config_file_refuses_root_devcontainer_json(dc_root: Path) -> None:
    (dc_root / ".devcontainer.json").write_text("{}")
    with pytest.raises(SandboxError, match=r"Move it to \.devcontainer/devcontainer\.json"):
        devcontainer.config_file(dc_root, ".devcontainer/devcontainer.json")


def test_image_tag_follows_the_tree(repo: Path) -> None:
    (repo / ".devcontainer").mkdir()
    (repo / ".devcontainer" / "devcontainer.json").write_text("{}")
    project = project_for(repo)
    first = devcontainer.image_tag(project, "martin")
    assert first.startswith(f"localhost/agent-sandbox/martin-{project.id}-devcontainer:")
    (repo / ".devcontainer" / "devcontainer-lock.json").write_text("{}")
    assert devcontainer.image_tag(project, "martin") != first


def test_ensure_image_builds_with_frozen_lockfile(
    repo: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    (repo / ".devcontainer").mkdir()
    (repo / ".devcontainer" / "devcontainer.json").write_text("{}")
    project = project_for(repo)
    engine = FakeEngine()
    built: set[str] = set()
    engine.on(
        ("image", "inspect", "--format"), lambda args: "sha256:dc" if args[-1] in built else 1
    )
    calls: list[tuple[str, ...]] = []

    def run_cli(
        command: list[str], eng: FakeEngine, *args: str, show_progress: bool = False
    ) -> dict[str, Any]:
        calls.append(args)
        if args[0] == "read-configuration":
            return {
                "outcome": "success",
                "configuration": {"image": "debian:12", "runArgs": ["-x"]},
            }
        built.add(args[args.index("--image-name") + 1])
        return {"outcome": "success"}

    monkeypatch.setattr(devcontainer, "run_cli", run_cli)
    monkeypatch.setattr(devcontainer, "cli_command", lambda user: ["devcontainer"])
    tag = devcontainer.ensure_image(
        engine, UserConfig(), project, ".devcontainer/devcontainer.json", username="dev"
    )
    assert tag == devcontainer.image_tag(project, "dev")
    build = calls[1]
    assert build[0] == "build" and "--frozen-lockfile" in build and "--no-cache" not in build
    assert build[build.index("--config") + 1] == str(repo / ".devcontainer" / "devcontainer.json")
    err = capsys.readouterr().err
    assert "runArgs is not applied" in err and "debian:12 is not pinned" in err
    calls.clear()
    devcontainer.ensure_image(
        engine, UserConfig(), project, ".devcontainer/devcontainer.json", username="dev"
    )
    assert [c[0] for c in calls] == ["read-configuration"]  # built already: checks only
    devcontainer.ensure_image(
        engine,
        UserConfig(),
        project,
        ".devcontainer/devcontainer.json",
        username="dev",
        rebuild=True,
    )
    assert "--no-cache" in calls[-1]
