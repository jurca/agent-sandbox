from __future__ import annotations

import json
import os
import socket
from pathlib import Path

import pytest

from agent_sandbox import manage, sandbox, util
from agent_sandbox.config import MountSpec, ProjectConfig, UserConfig, load_project_config
from agent_sandbox.engine import EngineError
from agent_sandbox.images import UserImage
from agent_sandbox.mounts import BindMount
from agent_sandbox.project import (
    LABEL_SPEC,
    LABEL_SPEC_JSON,
    LABEL_STATE_SCOPE,
    LABEL_WORKSPACE,
    project_for,
)
from agent_sandbox.sandbox import Context, compute_spec, make_plan, spec_differences, spec_hash
from agent_sandbox.util import SandboxError

from .conftest import git
from .fakes import FakeEngine

IMAGE = "example/dev:1"


def make_ctx(
    root: Path,
    engine: FakeEngine | None = None,
    *,
    config: ProjectConfig | None = None,
    user: UserConfig | None = None,
) -> Context:
    return Context(
        project=project_for(root),
        config=config or ProjectConfig(image=IMAGE),
        user=user or UserConfig(),
        engine=engine or FakeEngine(),
        uid=1000,
        gid=1000,
        username="dev",
        groupname="dev",
        umask=0o022,
    )


@pytest.fixture
def configured(repo: Path) -> Path:
    manage.init_project(project_for(repo), IMAGE)
    return repo


def test_plan_for_plain_clone(configured: Path) -> None:
    plan = make_plan(make_ctx(configured))
    assert plan.mounts == [
        BindMount(str(configured), "/workspace", readonly=False),
        BindMount(str(configured / ".git"), "/workspace/.git", readonly=True),
        BindMount(str(configured / ".agent-sandbox"), "/workspace/.agent-sandbox", readonly=True),
    ]
    p = project_for(configured)
    assert plan.volumes == [
        (f"agent-sandbox-state-{p.id}-claude", ".claude"),
        (f"agent-sandbox-state-{p.id}-copilot", ".copilot"),
    ]
    assert plan.ownership == "acl"


def test_plan_for_worktree_mounts_common_dir_at_host_path(repo: Path, tmp_path: Path) -> None:
    tree = tmp_path / "tree"
    git(repo, "worktree", "add", "-q", str(tree))
    plan = make_plan(make_ctx(tree.resolve()))
    assert plan.mounts[1] == BindMount(str(tree.resolve() / ".git"), "/workspace/.git")
    assert BindMount(str(repo / ".git"), str(repo / ".git"), readonly=True) in plan.mounts


def test_plan_git_rw_only_from_user_config(configured: Path) -> None:
    user = UserConfig(workspaces={str(configured): {"git": "rw"}})
    plan = make_plan(make_ctx(configured, user=user))
    assert not plan.mounts[1].readonly
    assert plan.mounts[2].readonly  # .agent-sandbox stays read-only regardless


def test_plan_shared_state_volume(configured: Path) -> None:
    plan = make_plan(make_ctx(configured, user=UserConfig(state_volume="login")))
    assert plan.volumes[0] == ("agent-sandbox-state-shared-login-claude", ".claude")


def test_plan_validates_extra_mounts(configured: Path, tmp_path: Path) -> None:
    data = tmp_path / "data"
    data.mkdir()
    config = ProjectConfig(image=IMAGE, mounts=[MountSpec(str(data), "/data")])
    assert make_plan(make_ctx(configured, config=config)).mounts[3] == BindMount(str(data), "/data")
    config.mounts = [MountSpec(str(Path.home() / ".ssh"), "/k")]
    with pytest.raises(SandboxError):
        make_plan(make_ctx(configured, config=config))


@pytest.mark.parametrize(
    ("kind", "rootless", "mode"),
    [("docker", True, "acl"), ("podman", True, "keep-id"), ("docker", False, "none"),
     ("podman", False, "none")],
)  # fmt: skip
def test_ownership_mode(kind: str, rootless: bool, mode: str) -> None:
    assert sandbox.ownership_mode(FakeEngine(kind, rootless=rootless)) == mode


def test_spec_hash_and_differences(configured: Path) -> None:
    ctx = make_ctx(configured)
    plan = make_plan(ctx)
    spec = compute_spec(ctx, plan, "sha256:1")
    reversed_plan = sandbox.Plan(plan.layout, plan.mounts[::-1], plan.volumes, plan.ownership)
    reordered = compute_spec(ctx, reversed_plan, "sha256:1")
    assert spec_hash(spec) == spec_hash(reordered)
    changed_plan = make_plan(make_ctx(configured, user=UserConfig(git="rw")))
    rw_ctx = make_ctx(configured, user=UserConfig(git="rw"))
    changed = compute_spec(rw_ctx, changed_plan, "sha256:2")
    assert spec_differences(spec, changed) == ["base_id", "git", "mounts"]
    assert spec_hash(spec) != spec_hash(changed)
    assert compute_spec(ctx, plan, None)["base_id"] == "missing"


def test_command_with_umask() -> None:
    assert sandbox.command_with_umask(["claude", "--x"], 0o027) == [
        "sh", "-c", 'umask "$0"; exec "$@"', "0027", "claude", "--x",
    ]  # fmt: skip


def test_exec_env(configured: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TERM", "xterm")
    monkeypatch.delenv("TZ", raising=False)
    monkeypatch.setenv("HTTPS_PROXY", "http://corp:3128")
    config = load_project_config(configured)
    args = sandbox.exec_env(make_ctx(configured, config=config), "/home/dev")
    pairs = [args[i + 1] for i in range(0, len(args), 2)]
    assert all(args[i] == "-e" for i in range(0, len(args), 2))
    assert "HTTPS_PROXY=http://proxy:8888" in pairs
    assert "http_proxy=http://proxy:8888" in pairs
    assert "GIT_CONFIG_KEY_0=safe.directory" in pairs and "GIT_OPTIONAL_LOCKS=0" in pairs
    assert "AGENT_SANDBOX=1" in pairs
    assert "TERM" in pairs and "TZ" not in pairs
    assert "CLAUDE_CONFIG_DIR=/home/dev/.claude" in pairs
    assert not any("corp" in p for p in pairs)


def test_resolve_command(configured: Path) -> None:
    engine = FakeEngine()
    found = {"claude"}
    engine.on(("exec",), lambda args: 0 if args[-1] in found else 1)
    ctx = make_ctx(configured, engine, config=ProjectConfig(image=IMAGE, harness="claude -c"))
    assert sandbox._resolve_command(ctx, None, "/h") == ["claude", "-c"]
    assert sandbox._resolve_command(ctx, ["tmux"], "/h") == ["tmux"]
    ctx.config.harness = "copilot"
    assert sandbox._resolve_command(ctx, None, "/h") == sandbox.SHELL_FALLBACK
    ctx.config.harness = "bash"
    assert sandbox._resolve_command(ctx, None, "/h") == sandbox.SHELL_FALLBACK
    ctx.config.harness = "'unterminated"
    with pytest.raises(SandboxError, match="Cannot parse"):
        sandbox._resolve_command(ctx, None, "/h")


def test_check_sockets(configured: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    ctx = make_ctx(configured)
    plan = make_plan(ctx)
    sandbox.check_sockets(ctx, plan, unsafe=False)
    sock = socket.socket(socket.AF_UNIX)
    sock.bind(str(configured / "x.sock"))
    try:
        with pytest.raises(SandboxError, match=r"x\.sock"):
            sandbox.check_sockets(ctx, plan, unsafe=False)
        monkeypatch.setattr(util, "is_tty", lambda: True)
        monkeypatch.setattr("builtins.input", lambda _p: "I understand the risks")
        sandbox.check_sockets(ctx, plan, unsafe=True)
        monkeypatch.setattr("builtins.input", lambda _p: "y")
        with pytest.raises(SandboxError, match="Not confirmed"):
            sandbox.check_sockets(ctx, plan, unsafe=True)
    finally:
        sock.close()


def fake_image(home: str = "/home/dev") -> UserImage:
    return UserImage(IMAGE, "sha256:img", "sha256:base", "dev", 1000, 1000, home, False,
                     ((0, 1000, 1), (1, 100000, 65536)))  # fmt: skip


def test_create_rolls_back_on_failure(configured: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    engine = FakeEngine()
    ctx = make_ctx(configured, engine)
    monkeypatch.setattr(sandbox, "ensure_user_image", lambda *a, **k: fake_image())
    monkeypatch.setattr(sandbox, "ensure_proxy_image", lambda *a, **k: "proxy:1")
    monkeypatch.setattr(sandbox, "apply_acls", lambda root, uid: 0)
    monkeypatch.setattr(sandbox, "start_proxy", lambda ctx: None)
    engine.on(("create", "--name", ctx.project.workspace_container), lambda args: 1)
    with pytest.raises(EngineError):
        sandbox.create_sandbox(ctx)
    p = ctx.project
    removed = [c for c in engine.calls if "rm" in c[:2]]
    assert removed == [
        ("rm", "-f", p.proxy_container),
        ("volume", "rm", f"agent-sandbox-state-{p.id}-copilot"),
        ("volume", "rm", f"agent-sandbox-state-{p.id}-claude"),
        ("network", "rm", p.network),
    ]


def test_create_arguments(configured: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    engine = FakeEngine()
    ctx = make_ctx(configured, engine)
    acl_calls: list[int] = []
    monkeypatch.setattr(sandbox, "ensure_user_image", lambda *a, **k: fake_image())
    monkeypatch.setattr(sandbox, "ensure_proxy_image", lambda *a, **k: "proxy:1")
    monkeypatch.setattr(sandbox, "apply_acls", lambda root, uid: acl_calls.append(uid) or 0)
    monkeypatch.setattr(sandbox, "start_proxy", lambda ctx: None)
    sandbox.create_sandbox(ctx)
    assert acl_calls == [100999]
    workspace_create = ("create", "--name", ctx.project.workspace_container)
    create = next(c for c in engine.calls if c[:3] == workspace_create)
    joined = " ".join(create)
    assert "--network " + ctx.project.network in joined
    assert "--security-opt no-new-privileges" in joined and "--init" in joined
    assert "--user 1000:1000" in joined and "--privileged" not in joined
    assert f"type=bind,src={configured}/.git,dst=/workspace/.git,readonly" in joined
    assert "dst=/home/dev/.claude" in joined
    assert create[-2:] == (IMAGE, "infinity")
    assert "--network" not in " ".join(
        next(c for c in engine.calls if c[:3] == ("create", "--name", ctx.project.proxy_container))
    )
    chown = next(c for c in engine.calls if c[:3] == ("exec", "--user", "0"))
    assert chown[-2:] == ("/home/dev/.claude", "/home/dev/.copilot")


def test_ensure_ready_detects_drift(configured: Path) -> None:
    engine = FakeEngine()
    ctx = make_ctx(configured, engine)
    old = compute_spec(ctx, make_plan(ctx), "sha256:old")
    engine.add("container", ctx.project.workspace_container, {
        LABEL_WORKSPACE: str(configured),
        LABEL_SPEC: spec_hash(old),
        LABEL_SPEC_JSON: json.dumps(old),
    })  # fmt: skip
    engine.add("image", IMAGE, {}, Id="sha256:new")
    engine.on(("image", "inspect", "--format"), lambda args: "sha256:new")
    with pytest.raises(SandboxError, match=r"(?s)changed: base_id\).*recreate"):
        sandbox.ensure_ready(ctx)


def test_ensure_ready_refuses_foreign_container(configured: Path) -> None:
    engine = FakeEngine()
    ctx = make_ctx(configured, engine)
    engine.add("container", ctx.project.workspace_container, {LABEL_WORKSPACE: "/elsewhere"})
    with pytest.raises(SandboxError, match="belongs to /elsewhere"):
        sandbox.ensure_ready(ctx)


def test_remove_by_id_keeps_shared_volumes(isolated_dirs: Path) -> None:
    engine = FakeEngine()
    ident = {"agent-sandbox.id": "ws-1"}
    engine.add("container", "c1", ident)
    engine.add("container", "other", {"agent-sandbox.id": "ws-2"})
    engine.add("network", "n1", ident)
    engine.add("volume", "v1", {**ident, LABEL_STATE_SCOPE: "per-workspace"})
    engine.add("volume", "shared", {**ident, LABEL_STATE_SCOPE: "login"})
    runtime = isolated_dirs / "runtime" / "ws-1"
    runtime.mkdir(parents=True)
    assert sandbox.remove_by_id(engine, "ws-1", state=False) == ["container c1", "network n1"]
    assert not runtime.exists()
    assert sandbox.remove_by_id(engine, "ws-1", state=True) == ["volume v1"]
    assert ("volume", "shared") in engine.objects
    assert ("container", "other") in engine.objects


def test_stop_sandbox() -> None:
    engine = FakeEngine()
    p = project_for(Path("/w/x"))
    engine.add("container", p.workspace_container, {}, State={"Status": "running"})
    engine.add("container", p.proxy_container, {}, State={"Status": "exited"})
    assert sandbox.stop_sandbox(engine, p) == [p.workspace_container]


def test_share_workspace_includes_git_only_when_rw(
    repo: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    tree = tmp_path / "tree"
    git(repo, "worktree", "add", "-q", str(tree))
    calls: list[tuple[Path, tuple[str, ...]]] = []

    def fake_acls(root: Path, uid: int, *, skip: tuple[str, ...] = (".git", ".agent-sandbox")):
        calls.append((root, tuple(skip)))
        return 0

    monkeypatch.setattr(sandbox, "apply_acls", fake_acls)
    ctx = make_ctx(tree.resolve())
    assert sandbox.share_workspace(ctx, make_plan(ctx), os.getuid()) == 0
    assert calls == []  # same uid inside and outside: nothing to share
    sandbox.share_workspace(ctx, make_plan(ctx), 100999)
    assert calls == [(tree.resolve(), (".git", ".agent-sandbox"))]
    calls.clear()
    rw = make_ctx(tree.resolve(), user=UserConfig(git="rw"))
    sandbox.share_workspace(rw, make_plan(rw), 100999)
    assert calls == [(tree.resolve(), (".agent-sandbox",)), (repo / ".git", ())]


def test_proxy_is_unprivileged_and_configured_before_start(configured: Path) -> None:
    engine = FakeEngine()
    ctx = make_ctx(configured, engine)
    p = ctx.project
    engine.on(("exec", p.proxy_container, "cat"), lambda args: "base 1\n")
    assert sandbox.ensure_proxy_container(ctx, "proxy:1")
    sandbox.start_proxy(ctx)
    create = next(c for c in engine.calls if c[:3] == ("create", "--name", p.proxy_container))
    joined = " ".join(create)
    assert "--user 65534:65534" in joined and "--cap-drop ALL" in joined
    assert "--cap-add" not in joined and "--mount" not in joined and "--volume" not in joined
    assert "--security-opt no-new-privileges" in joined and "max-size=10m" in joined
    start = engine.calls.index(("start", p.proxy_container))
    connect = ("network", "connect", "--alias", "proxy", p.network, p.proxy_container)
    push = ("cp", p.proxy_container, "base.filter", "base.conf", "net.filter", "net.conf")
    assert engine.calls.index(connect) < engine.calls.index(push) < start


def test_outdated_proxy_is_replaced(configured: Path) -> None:
    engine = FakeEngine()
    ctx = make_ctx(configured, engine)
    p = ctx.project
    engine.add("container", p.proxy_container, {}, Image="sha256:old")
    engine.on(("image", "inspect", "--format"), lambda args: "sha256:new")
    assert sandbox.ensure_proxy_container(ctx, "proxy:2")
    assert ("rm", "-f", p.proxy_container) in engine.calls
    engine.calls.clear()
    engine.add("container", p.proxy_container, {}, Image="sha256:new")
    assert not sandbox.ensure_proxy_container(ctx, "proxy:2")
    assert not any(c[0] in ("rm", "create") for c in engine.calls)
