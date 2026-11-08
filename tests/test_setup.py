from __future__ import annotations

import contextlib
import io
import json
from collections.abc import Callable, Generator
from pathlib import Path
from typing import Any

import pytest

from agent_sandbox import devcontainer, net, sandbox, setup, util
from agent_sandbox.config import ProjectConfig
from agent_sandbox.devcontainer import Step
from agent_sandbox.net import Observed
from agent_sandbox.project import LABEL_HOME, LABEL_WORKSPACE
from agent_sandbox.util import SandboxError

from .fakes import FakeEngine
from .test_sandbox import IMAGE, make_ctx

METADATA: list[dict[str, Any]] = [
    {"id": "feature/x:1", "onCreateCommand": "feature-oncreate", "postStartCommand": "f-start"},
    {
        "postCreateCommand": {"one": "echo ${localWorkspaceFolder}", "two": ["true"]},
        "postAttachCommand": "attach-cmd",
        "remoteEnv": {"FROM_DC": "1"},
    },
]


class FakeProcess:
    def __init__(self, code: int, output: str = "") -> None:
        self.code = code
        self.stdout = io.StringIO(output)

    def wait(self) -> int:
        return self.code


class Runner:
    """Stands in for `engine exec`: records each command and answers with an exit code."""

    def __init__(self) -> None:
        self.commands: list[list[str]] = []
        self.argvs: list[list[str]] = []
        self.fail: Callable[[list[str]], bool] = lambda _command: False

    def __call__(self, argv: list[str]) -> FakeProcess:
        self.argvs.append(argv)
        # [..., container, "sh", "-c", 'umask "$0"; exec "$@"', "0022", *command]
        inner = argv[argv.index("0022") + 1 :]
        self.commands.append(inner)
        return FakeProcess(1 if self.fail(inner) else 0, f"out of {inner[-1]}\n")


@pytest.fixture
def runner(monkeypatch: pytest.MonkeyPatch) -> Runner:
    fake = Runner()
    monkeypatch.setattr(setup, "spawn", fake)
    return fake


@pytest.fixture
def opened(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Replaces the proxy lease; records when it is open."""
    events: list[str] = []

    @contextlib.contextmanager
    def fake_network(ctx: Any) -> Generator[Observed]:
        events.append("open")
        yield Observed([], False)
        events.append("close")

    monkeypatch.setattr(net, "setup_network", fake_network)
    return events


def container(engine: FakeEngine, ctx: Any, *, cid: str = "c1", started: str = "t1",
              metadata: list[dict[str, Any]] | None = None) -> None:  # fmt: skip
    labels = {LABEL_WORKSPACE: str(ctx.project.root), LABEL_HOME: "/home/dev"}
    if metadata is not None:
        labels[devcontainer.LABEL_METADATA] = json.dumps(metadata)
    engine.add(
        "container", ctx.project.workspace_container, labels,
        Id=cid, State={"StartedAt": started, "Status": "running"},
    )  # fmt: skip
    engine.objects[("container", ctx.project.workspace_container)]["Config"]["Env"] = ["PATH=/bin"]


def plain_ctx(repo: Path, **config: Any) -> tuple[Any, FakeEngine]:
    engine = FakeEngine()
    ctx = make_ctx(repo, engine, config=ProjectConfig(image=IMAGE, **config))
    return ctx, engine


def test_plan_orders_config_then_features_then_devcontainer(repo: Path) -> None:
    ctx, engine = plain_ctx(repo, devcontainer=".devcontainer/devcontainer.json",
                            setup_create=["uv sync"], setup_start=["s"])  # fmt: skip
    container(engine, ctx, metadata=METADATA)
    plan = setup.plan_for(ctx, setup.session(ctx))
    assert plan.create == [
        Step("config.toml", "create", "uv sync"),
        Step("feature/x:1", "onCreateCommand", "feature-oncreate"),
        Step("devcontainer.json", "postCreateCommand", METADATA[1]["postCreateCommand"]),
    ]
    assert [s.command for s in plan.start] == ["s", "f-start"]
    assert [s.command for s in plan.attach] == ["attach-cmd"]


def test_plan_ignores_metadata_without_devcontainer(repo: Path) -> None:
    ctx, engine = plain_ctx(repo, setup_create=["a"])
    container(engine, ctx, metadata=METADATA)  # e.g. an image that happens to carry the label
    plan = setup.plan_for(ctx, setup.session(ctx))
    assert [s.command for s in plan.create] == ["a"] and not plan.start and not plan.attach


def test_create_runs_once_with_the_network_open(
    repo: Path, runner: Runner, opened: list[str]
) -> None:
    ctx, engine = plain_ctx(repo, setup_create=["uv sync", "pre-commit install-hooks"])
    container(engine, ctx)
    setup.ensure_setup(ctx)
    assert runner.commands == [["sh", "-c", "uv sync"], ["sh", "-c", "pre-commit install-hooks"]]
    assert opened == ["open", "close"]
    argv = runner.argvs[0]
    assert argv[:4] == ["docker", "exec", "--user", "1000:1000"]
    assert f"--workdir {repo}" in " ".join(argv) and "HTTPS_PROXY=http://proxy:8888" in argv
    setup.ensure_setup(ctx)
    assert len(runner.commands) == 2  # recorded: not again
    setup.ensure_setup(ctx, force=True)
    assert len(runner.commands) == 4


def test_create_runs_again_for_a_new_container_or_changed_commands(
    repo: Path, runner: Runner, opened: list[str]
) -> None:
    ctx, engine = plain_ctx(repo, setup_create=["a"])
    container(engine, ctx, cid="c1")
    setup.ensure_setup(ctx)
    container(engine, ctx, cid="c2")  # recreated
    setup.ensure_setup(ctx)
    ctx.config.setup_create = ["a", "b"]
    setup.ensure_setup(ctx)
    assert runner.commands == [["sh", "-c", c] for c in ("a", "a", "a", "b")]


def test_failed_create_stops_and_is_not_recorded(
    repo: Path, runner: Runner, opened: list[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(setup, "is_tty", lambda: False)
    ctx, engine = plain_ctx(repo, setup_create=["bad", "never"])
    container(engine, ctx)
    runner.fail = lambda command: command[-1] == "bad"
    with pytest.raises(SandboxError, match="agent-sandbox setup"):
        setup.ensure_setup(ctx)
    assert runner.commands == [["sh", "-c", "bad"]]
    assert not setup.create_done(ctx, setup.session(ctx), setup.plan_for(ctx, setup.session(ctx)))
    runner.fail = lambda _command: False
    setup.ensure_setup(ctx)
    assert runner.commands[-2:] == [["sh", "-c", "bad"], ["sh", "-c", "never"]]


def test_failed_create_can_be_retried_at_once(
    repo: Path, runner: Runner, opened: list[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(setup, "is_tty", lambda: True)
    monkeypatch.setattr(util, "is_tty", lambda: True)
    answers = iter(["y"])
    monkeypatch.setattr("builtins.input", lambda _prompt: next(answers))
    attempts = iter([True, False])
    ctx, engine = plain_ctx(repo, setup_create=["flaky"])
    container(engine, ctx)
    runner.fail = lambda _command: next(attempts)
    setup.ensure_setup(ctx)
    assert runner.commands == [["sh", "-c", "flaky"]] * 2
    assert opened == ["open", "close", "open", "close"]


def test_start_runs_per_container_start_on_the_base_tier(
    repo: Path, runner: Runner, opened: list[str]
) -> None:
    ctx, engine = plain_ctx(repo, setup_start=["svc"])
    container(engine, ctx, started="t1")
    setup.ensure_setup(ctx)
    setup.ensure_setup(ctx)
    assert runner.commands == [["sh", "-c", "svc"]] and opened == []
    container(engine, ctx, started="t2")
    setup.ensure_setup(ctx)
    assert len(runner.commands) == 2


def test_failed_start_only_warns(
    repo: Path, runner: Runner, opened: list[str], capsys: pytest.CaptureFixture[str]
) -> None:
    ctx, engine = plain_ctx(repo, setup_start=["svc"])
    container(engine, ctx)
    runner.fail = lambda _command: True
    setup.ensure_setup(ctx)
    assert "a start command failed" in capsys.readouterr().err


def test_devcontainer_commands_get_variables_and_remote_env(
    repo: Path, runner: Runner, opened: list[str], capsys: pytest.CaptureFixture[str]
) -> None:
    ctx, engine = plain_ctx(repo, devcontainer=".devcontainer/devcontainer.json")
    ctx.config.image = None
    container(engine, ctx, metadata=METADATA)
    setup.before_harness(ctx)
    assert runner.commands == [
        ["sh", "-c", "feature-oncreate"],
        ["sh", "-c", f"echo {repo}"],
        ["true"],
        ["sh", "-c", "f-start"],
        ["sh", "-c", "attach-cmd"],
    ]
    assert "FROM_DC=1" in runner.argvs[0]
    err = capsys.readouterr().err
    assert "==> postCreateCommand from devcontainer.json (one): echo" in err
    setup.before_harness(ctx)
    assert runner.commands[-1] == ["sh", "-c", "attach-cmd"] and len(runner.commands) == 6


def test_commands_get_the_probed_environment(repo: Path, runner: Runner, opened: list[str]) -> None:
    ctx, engine = plain_ctx(repo, setup_create=["poetry sync"])
    container(engine, ctx)

    def probe(args: tuple[str, ...]) -> str:
        marker = sandbox.PROBE_MARKER
        return f"{marker}PATH=/bin:/usr/local/py-utils/bin\0PIPX_HOME=/usr/local/py-utils\0{marker}"

    engine.on(("exec", "--user", "1000:1000", "--workdir", str(repo)), probe)
    setup.ensure_setup(ctx)
    argv = runner.argvs[0]
    assert "PATH=/home/dev/.local/bin:/bin:/usr/local/py-utils/bin" in argv
    assert "PIPX_HOME=/usr/local/py-utils" in argv


def test_config_commands_are_not_substituted(repo: Path, runner: Runner, opened: list[str]) -> None:
    ctx, engine = plain_ctx(repo, setup_create=["echo ${localWorkspaceFolder} ${HOME}"])
    container(engine, ctx)
    setup.ensure_setup(ctx)
    assert runner.commands == [["sh", "-c", "echo ${localWorkspaceFolder} ${HOME}"]]


def test_nothing_to_run_is_recorded_without_opening_the_network(
    repo: Path, runner: Runner, opened: list[str]
) -> None:
    ctx, engine = plain_ctx(repo)
    container(engine, ctx)
    setup.before_harness(ctx)
    assert runner.commands == [] and opened == []
    assert setup.load_record(ctx)["container"] == "c1"


def test_parallel_commands_prefix_their_output(
    repo: Path, runner: Runner, capsys: pytest.CaptureFixture[str]
) -> None:
    ctx, engine = plain_ctx(repo)
    container(engine, ctx)
    step = Step("devcontainer.json", "postCreateCommand", {"one": "a", "two": ["b"]})
    assert setup.run_step(ctx, step, [])
    out = capsys.readouterr().out
    assert "[one] out of a\n" in out and "[two] out of b\n" in out
    runner.fail = lambda command: command[-1] == "b"
    assert not setup.run_step(ctx, step, [])
