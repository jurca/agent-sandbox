from __future__ import annotations

import json
import os
import socket
import subprocess
from collections.abc import Callable
from pathlib import Path

import pytest

from agent_sandbox import manage, sandbox, util
from agent_sandbox.config import (
    DEFAULT_ISOLATED,
    DEFAULT_PROTECTED,
    MountSpec,
    ProjectConfig,
    UserConfig,
    load_project_config,
)
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


# Workspace paths that are mounted over by default (protected, isolated, toolkit config).
COVERED = (".agent-sandbox", *DEFAULT_PROTECTED, *DEFAULT_ISOLATED)


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
    ws = str(configured)
    assert plan.mounts == [
        BindMount(ws, ws, readonly=False),
        BindMount(f"{ws}/.git", f"{ws}/.git", readonly=True),
        BindMount(f"{ws}/.agent-sandbox", f"{ws}/.agent-sandbox", readonly=True),
        *(BindMount(f"{ws}/{rel}", f"{ws}/{rel}") for rel in (".claude", ".agents", ".vscode",
                                                                ".idea", ".devcontainer")),
    ]  # fmt: skip
    p = project_for(configured)
    assert plan.volumes == [
        (f"agent-sandbox-state-{p.id}-claude", ".claude"),
        (f"agent-sandbox-state-{p.id}-copilot", ".copilot"),
        (f"agent-sandbox-state-{p.id}-cache-pre-commit", ".cache/pre-commit"),
    ]
    assert plan.isolated == [
        (p.isolated_volume(".venv"), f"{ws}/.venv"),
        (p.isolated_volume("node_modules"), f"{ws}/node_modules"),
    ]
    assert plan.ownership == "acl"


def test_isolated_volume_names_do_not_collide() -> None:
    p = project_for(Path("/w/x"))
    assert p.isolated_volume(".venv") != p.isolated_volume("venv")
    assert p.isolated_volume("a/.venv").startswith(f"agent-sandbox-isolated-{p.id}-a-.venv-")


def test_plan_refuses_symlinked_workspace_paths(configured: Path, tmp_path: Path) -> None:
    (tmp_path / "elsewhere").mkdir()
    (configured / ".venv").symlink_to(tmp_path / "elsewhere")
    with pytest.raises(SandboxError, match="symlink"):
        make_plan(make_ctx(configured))


def test_plan_for_worktree_mounts_common_dir_at_host_path(repo: Path, tmp_path: Path) -> None:
    tree = tmp_path / "tree"
    git(repo, "worktree", "add", "-q", str(tree))
    plan = make_plan(make_ctx(tree.resolve()))
    git_file = str(tree.resolve() / ".git")
    assert plan.mounts[1] == BindMount(git_file, git_file)
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
    assert BindMount(str(data), "/data") in make_plan(make_ctx(configured, config=config)).mounts
    config.mounts = [MountSpec(str(data), "~/data")]
    plan = make_plan(make_ctx(configured, config=config), "/home/someone")
    assert BindMount(str(data), "/home/someone/data") in plan.mounts
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
    reversed_plan = sandbox.Plan(
        plan.layout, plan.mounts[::-1], plan.volumes, plan.isolated, plan.ownership
    )
    reordered = compute_spec(ctx, reversed_plan, "sha256:1")
    assert spec_hash(spec) == spec_hash(reordered)
    changed_plan = make_plan(make_ctx(configured, user=UserConfig(git="rw")))
    rw_ctx = make_ctx(configured, user=UserConfig(git="rw"))
    changed = compute_spec(rw_ctx, changed_plan, "sha256:2")
    assert spec_differences(spec, changed) == ["base_id", "git", "mounts"]
    assert spec_hash(spec) != spec_hash(changed)
    assert compute_spec(ctx, plan, None)["base_id"] == "missing"
    assert spec["tmp"] == "tmpfs"  # sandboxes created before the /tmp tmpfs drift
    assert spec_differences({k: v for k, v in spec.items() if k != "tmp"}, spec) == ["tmp"]


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


def test_exec_env_puts_local_bin_on_the_path(configured: Path) -> None:
    def path_of(args: list[str]) -> list[str]:
        return [args[i + 1] for i in range(0, len(args), 2) if args[i + 1].startswith("PATH=")]

    ctx = make_ctx(configured)
    assert path_of(sandbox.exec_env(ctx, "/home/dev")) == []  # root execs: left alone
    assert path_of(sandbox.exec_env(ctx, "/home/dev", path="/opt/go/bin:/usr/bin")) == [
        "PATH=/home/dev/.local/bin:/opt/go/bin:/usr/bin"
    ]
    assert path_of(sandbox.exec_env(ctx, "/home/dev", path="")) == [
        f"PATH=/home/dev/.local/bin:{sandbox.DEFAULT_PATH}"
    ]
    already = "/usr/bin:/home/dev/.local/bin"
    assert path_of(sandbox.exec_env(ctx, "/home/dev", path=already)) == [f"PATH={already}"]
    remote = {"PATH": "/usr/bin:/opt"}
    assert path_of(sandbox.exec_env(ctx, "/home/dev", remote, path="/usr/bin")) == [
        "PATH=/home/dev/.local/bin:/usr/bin:/opt"
    ]
    ctx.config.env_set["PATH"] = "/mine"
    assert path_of(sandbox.exec_env(ctx, "/home/dev", remote, path="/usr/bin")) == ["PATH=/mine"]


def test_resolve_command(configured: Path) -> None:
    engine = FakeEngine()
    found = {"claude"}
    engine.on(("exec",), lambda args: 0 if args[-1] in found else 1)
    ctx = make_ctx(configured, engine, config=ProjectConfig(image=IMAGE, harness="claude -c"))
    assert sandbox._resolve_command(ctx, None, []) == ["claude", "-c"]
    assert sandbox._resolve_command(ctx, ["tmux"], []) == ["tmux"]
    ctx.config.harness = "copilot"
    assert sandbox._resolve_command(ctx, None, []) == sandbox.SHELL_FALLBACK
    ctx.config.harness = "bash"
    assert sandbox._resolve_command(ctx, None, []) == sandbox.SHELL_FALLBACK
    ctx.config.harness = "'unterminated"
    with pytest.raises(SandboxError, match="Cannot parse"):
        sandbox._resolve_command(ctx, None, [])


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
    monkeypatch.setattr(sandbox, "apply_acls", lambda root, uid, **k: 0)
    monkeypatch.setattr(sandbox, "start_proxy", lambda ctx: None)
    engine.on(("create", "--name", ctx.project.workspace_container), lambda args: 1)
    with pytest.raises(EngineError):
        sandbox.create_sandbox(ctx)
    p = ctx.project
    removed = [c for c in engine.calls if "rm" in c[:2]]
    assert removed == [
        ("rm", "-f", p.proxy_container),
        ("volume", "rm", p.isolated_volume("node_modules")),
        ("volume", "rm", p.isolated_volume(".venv")),
        ("volume", "rm", f"agent-sandbox-state-{p.id}-cache-pre-commit"),
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
    monkeypatch.setattr(sandbox, "apply_acls", lambda root, uid, **k: acl_calls.append(uid) or 0)
    monkeypatch.setattr(sandbox, "start_proxy", lambda ctx: None)
    sandbox.create_sandbox(ctx)
    assert acl_calls == [100999]
    workspace_create = ("create", "--name", ctx.project.workspace_container)
    create = next(c for c in engine.calls if c[:3] == workspace_create)
    joined = " ".join(create)
    assert "--network " + ctx.project.network in joined
    assert "--security-opt no-new-privileges" in joined and "--init" in joined
    assert "--user 1000:1000" in joined and "--privileged" not in joined
    assert f"--workdir {configured} " in joined
    assert f"type=bind,src={configured}/.git,dst={configured}/.git,readonly" in joined
    assert f"type=bind,src={configured}/.claude,dst={configured}/.claude,readonly" in joined
    assert "dst=/home/dev/.claude" in joined
    venv_volume = ctx.project.isolated_volume(".venv")
    assert f"type=volume,src={venv_volume},dst={configured}/.venv" in joined
    assert (configured / ".idea").is_dir() and (configured / ".venv").is_dir()
    assert create[-2:] == (IMAGE, "infinity")
    assert "--network" not in " ".join(
        next(c for c in engine.calls if c[:3] == ("create", "--name", ctx.project.proxy_container))
    )
    chown = next(c for c in engine.calls if c[:3] == ("exec", "--user", "0"))
    assert chown[-6:] == (
        "/home/dev/.claude", "/home/dev/.copilot",
        "/home/dev/.cache", "/home/dev/.cache/pre-commit",
        f"{configured}/.venv", f"{configured}/node_modules",
    )  # fmt: skip


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
    assert calls == [(tree.resolve(), (".git", *COVERED))]
    calls.clear()
    rw = make_ctx(tree.resolve(), user=UserConfig(git="rw"))
    sandbox.share_workspace(rw, make_plan(rw), 100999)
    assert calls == [(tree.resolve(), COVERED), (repo / ".git", ())]


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


# --- reclaiming files owned by the sandbox user -----------------------------------------


ReclaimAnswer = subprocess.CompletedProcess[str] | str


def reclaim_engine(
    ctx: Context, inside: str, reclaim: Callable[[list[str]], ReclaimAnswer]
) -> FakeEngine:
    """`inside` is how the container sees `.agent-sandbox`; `reclaim` answers the root exec."""
    engine = ctx.engine
    assert isinstance(engine, FakeEngine)
    ws = ctx.project.workspace_container
    engine.on(("exec", ws, "stat", "-c", "%u %g"), lambda args: inside + "\n")
    engine.on(("exec", "--user", "0", ws, "sh", "-c"), lambda args: reclaim(list(args[12:])))
    return engine


def root_execs(engine: FakeEngine, ctx: Context) -> list[tuple[str, ...]]:
    prefix = ("exec", "--user", "0", ctx.project.workspace_container)
    return [c for c in engine.calls if c[:4] == prefix]


def test_reclaim_hands_sandbox_files_back_to_the_host_user(
    configured: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ctx = make_ctx(configured)
    listed = [str(configured / "a.txt"), str(configured / "d")]
    walks: list[tuple[Path, frozenset[str], int, int]] = []

    def fake_foreign(root: Path, exclude: frozenset[str], uid: int, gid: int) -> list[str]:
        walks.append((root, exclude, uid, gid))
        return listed

    monkeypatch.setattr(sandbox, "foreign_paths", fake_foreign)
    engine = reclaim_engine(ctx, "0 0", lambda paths: "".join(f"{p}\n" for p in paths))
    assert sandbox.reclaim_workspace(ctx, make_plan(ctx)) == (2, 0)
    reference = (configured / ".agent-sandbox").lstat()
    assert walks[0] == (configured, frozenset((".git", *COVERED)), os.getuid(), reference.st_gid)
    stat_call = ("exec", ctx.project.workspace_container, "stat", "-c", "%u %g",
                 str(configured / ".agent-sandbox"))  # fmt: skip
    assert stat_call in engine.calls
    (call,) = root_execs(engine, ctx)
    # Sandbox user and group as the container sees them, then the host user's inside ids.
    assert call[7:12] == ("sh", "1000", "1000", "0", "0")
    assert list(call[12:]) == listed
    script = call[6]
    assert "-maxdepth 0" in script and "chown -h" in script and "-user" in script
    assert "-group" in script


@pytest.mark.parametrize(
    ("engine_kind", "inside"),
    # A setgid project directory may give `.agent-sandbox` another group: only the uid decides.
    [
        ("docker-rootful", "1000 1000"),
        ("podman-keep-id", "1000 1000"),
        ("docker-rootful", "1000 50"),
    ],
)
def test_reclaim_is_a_no_op_when_the_sandbox_user_is_the_host_user(
    configured: Path, monkeypatch: pytest.MonkeyPatch, engine_kind: str, inside: str
) -> None:
    kind, _, mode = engine_kind.partition("-")
    ctx = make_ctx(configured, FakeEngine(kind, rootless=mode != "rootful"))
    monkeypatch.setattr(sandbox, "foreign_paths", lambda *a: pytest.fail("walked the workspace"))
    engine = reclaim_engine(ctx, inside, lambda paths: pytest.fail("reclaimed"))
    assert sandbox.reclaim_workspace(ctx, make_plan(ctx)) == (0, 0)
    assert root_execs(engine, ctx) == []


def test_reclaim_lists_again_what_reclaiming_made_readable(
    configured: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ctx = make_ctx(configured)
    locked, inner = str(configured / "locked"), str(configured / "locked" / "f")
    rounds = [[locked], [locked, inner], [locked, inner]]
    monkeypatch.setattr(sandbox, "foreign_paths", lambda *a: rounds.pop(0))
    engine = reclaim_engine(ctx, "0 0", lambda paths: "".join(f"{p}\n" for p in paths))
    assert sandbox.reclaim_workspace(ctx, make_plan(ctx)) == (2, 0)
    assert [list(c[12:]) for c in root_execs(engine, ctx)] == [[locked], [inner]]


def test_reclaim_stops_when_nothing_changes(
    configured: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ctx = make_ctx(configured)
    stuck = [str(configured / "stuck")]
    monkeypatch.setattr(sandbox, "foreign_paths", lambda *a: list(stuck))
    failing = subprocess.CompletedProcess([], 1, "", "chown: stuck: Operation not permitted\n")
    engine = reclaim_engine(ctx, "0 0", lambda paths: failing)
    assert sandbox.reclaim_workspace(ctx, make_plan(ctx)) == (0, 1)
    assert len(root_execs(engine, ctx)) == 1


def test_reclaim_covers_git_dirs_only_when_rw(
    repo: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    tree = tmp_path / "tree"
    git(repo, "worktree", "add", "-q", str(tree))
    manage.init_project(project_for(tree.resolve()), IMAGE)
    roots: list[tuple[Path, frozenset[str]]] = []

    def fake_foreign(root: Path, exclude: frozenset[str], uid: int, gid: int) -> list[str]:
        roots.append((root, exclude))
        return []

    monkeypatch.setattr(sandbox, "foreign_paths", fake_foreign)
    rw = make_ctx(tree.resolve(), user=UserConfig(git="rw"))
    reclaim_engine(rw, "0 0", lambda paths: "")
    sandbox.reclaim_workspace(rw, make_plan(rw))
    assert roots == [(tree.resolve(), frozenset(COVERED)), (repo / ".git", frozenset())]


# --- the workspace image ----------------------------------------------------------------


def test_spec_is_unchanged_without_a_dockerfile(configured: Path) -> None:
    """Containers created before the image layers existed keep matching their configuration."""
    ctx = make_ctx(configured)
    spec = compute_spec(ctx, make_plan(ctx), "sha256:base")
    assert "dockerfile" not in spec and spec["base_ref"] == IMAGE
    (configured / ".agent-sandbox" / "Dockerfile").write_text("ARG base\nFROM $base\n")
    first = compute_spec(ctx, make_plan(ctx), "sha256:base")["dockerfile"]
    (configured / ".agent-sandbox" / "ca.crt").write_text("CERT")  # may be copied in
    assert compute_spec(ctx, make_plan(ctx), "sha256:base")["dockerfile"] != first
    with_toolkit_change = sandbox.extension_digest(ctx)
    (configured / ".agent-sandbox" / "allow.extra").write_text("pypi.org\n")
    assert sandbox.extension_digest(ctx) == with_toolkit_change  # never affects the image


def test_workspace_image_from_image_warns_when_unpinned(
    configured: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    seen: dict[str, object] = {}

    def fake_user_image(engine: object, ref: str, **kwargs: object) -> UserImage:
        seen.update(kwargs, ref=ref)
        return fake_image()

    monkeypatch.setattr(sandbox, "ensure_user_image", fake_user_image)
    ctx = make_ctx(configured)
    assert sandbox.workspace_image(ctx).ref == IMAGE
    assert seen["ref"] == IMAGE and seen["remote_user"] is None and seen["tag"] is None
    assert "example/dev:1 is not pinned by digest" in capsys.readouterr().err
    ctx.config.image = "example/dev@sha256:abc"
    sandbox.workspace_image(ctx)
    assert "not pinned" not in capsys.readouterr().err


def test_workspace_image_from_devcontainer_adapts_its_user(
    configured: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    engine = FakeEngine()
    tag = "localhost/agent-sandbox/dev-x-devcontainer:abc"
    metadata = [{"id": "f"}, {"remoteUser": "vscode"}]
    engine.add("image", tag, {"devcontainer.metadata": json.dumps(metadata)}, Id="sha256:dc")
    monkeypatch.setattr(sandbox.devcontainer, "ensure_image", lambda *a, **k: tag)
    seen: dict[str, object] = {}

    def fake_user_image(engine: object, ref: str, **kwargs: object) -> UserImage:
        seen.update(kwargs, ref=ref)
        return fake_image()

    monkeypatch.setattr(sandbox, "ensure_user_image", fake_user_image)
    config = ProjectConfig(devcontainer=".devcontainer/devcontainer.json")
    ctx = make_ctx(configured, engine, config=config)
    sandbox.workspace_image(ctx, pull=True)
    assert seen == {
        "ref": tag, "user": "dev", "uid": 1000, "gid": 1000, "group": "dev",
        "rebuild": False, "pull": False, "remote_user": "vscode",
        "tag": f"localhost/agent-sandbox/dev-{ctx.project.id}-user:abc",
    }  # fmt: skip


def test_workspace_image_adds_the_dockerfile_layer(
    configured: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    engine = FakeEngine()
    monkeypatch.setattr(sandbox, "ensure_user_image", lambda *a, **k: fake_image())
    built: list[tuple[str, ...]] = []
    engine.on(("build",), lambda args: built.append(args) and None)
    engine.on(("image", "inspect", "--format"), lambda args: "sha256:ext" if built else 1)
    (configured / ".agent-sandbox" / "Dockerfile").write_text("ARG base\nFROM $base\n")
    ctx = make_ctx(configured, engine, config=ProjectConfig(image="i@sha256:1"))
    image = sandbox.workspace_image(ctx)
    assert image.ref.startswith(f"localhost/agent-sandbox/dev-{ctx.project.id}-extended:")
    assert (image.image_id, image.base_id, image.home) == ("sha256:ext", "sha256:base", "/home/dev")
    args = built[0]
    assert args[args.index("--file") + 1] == str(configured / ".agent-sandbox" / "Dockerfile")
    assert args[-1] == str(configured / ".agent-sandbox")  # the context: never the workspace
    assert {"base=" + IMAGE, "user=dev", "uid=1000", "home=/home/dev"} <= set(args)
    sandbox.workspace_image(ctx)
    assert len(built) == 1  # same content, same tag: not built again


def test_remote_env_never_overrides_the_toolkit_or_the_config(
    configured: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("TERM", "xterm")
    config = load_project_config(configured)
    extra = {"HTTPS_PROXY": "http://evil:1", "TERM": "dumb", "CLAUDE_CONFIG_DIR": "/x", "NEW": "1"}
    args = sandbox.exec_env(make_ctx(configured, config=config), "/home/dev", extra)
    pairs = [args[i + 1] for i in range(0, len(args), 2)]
    assert "NEW=1" in pairs
    assert not any(p.startswith(("HTTPS_PROXY=http://evil", "TERM=dumb", "CLAUDE_CONFIG_DIR=/x"))
                   for p in pairs)  # fmt: skip


def test_remote_env_is_resolved_from_the_container(configured: Path) -> None:
    engine = FakeEngine()
    config = ProjectConfig(devcontainer=".devcontainer/devcontainer.json")
    ctx = make_ctx(configured, engine, config=config)
    metadata = [{"remoteEnv": {"P": "${containerEnv:PATH}:/opt", "W": "${localWorkspaceFolder}",
                               "GONE": None}}]  # fmt: skip
    engine.add("container", ctx.project.workspace_container,
               {"devcontainer.metadata": json.dumps(metadata)}, Id="c")  # fmt: skip
    engine.objects[("container", ctx.project.workspace_container)]["Config"]["Env"] = ["PATH=/bin"]
    current = sandbox.session(ctx)
    assert sandbox.remote_env(ctx, current) == {"P": "/bin:/opt", "W": str(configured)}
    ctx.config.devcontainer, ctx.config.image = None, IMAGE
    assert sandbox.remote_env(ctx, current) == {}
