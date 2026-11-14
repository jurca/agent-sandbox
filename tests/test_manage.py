from __future__ import annotations

import os
from pathlib import Path

import pytest

from agent_sandbox import approval, manage
from agent_sandbox.project import LABEL_ROLE, LABEL_STATE_SCOPE, make_id, project_for
from agent_sandbox.util import SandboxError

from .conftest import make_repo
from .fakes import FakeEngine


def test_init_project(repo: Path) -> None:
    p = project_for(repo)
    written = manage.init_project(p, "img:1")
    assert sorted(f.name for f in written) == [
        "allow.base", "allow.extra", "config.toml", "tinyproxy.conf",
    ]  # fmt: skip
    assert approval.is_approved(p)
    with pytest.raises(SandboxError, match="--force"):
        manage.init_project(p, "img:2")
    manage.init_project(p, "img:2", force=True)
    assert 'image = "img:2"' in (repo / ".agent-sandbox" / "config.toml").read_text()
    assert approval.is_approved(p)


def test_clone_repository(repo: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    work = tmp_path / "work"
    work.mkdir()
    monkeypatch.chdir(work)
    assert manage.clone_repository(str(repo), None) == work / "repo"
    assert manage.clone_repository(f"file://{repo}/.git", "second") == work / "second"
    assert manage.clone_repository(str(repo), "custom") == work / "custom"
    assert (work / "custom" / "README").exists()
    with pytest.raises(SandboxError, match="clone failed"):
        manage.clone_repository("ext::sh -c touch% /tmp/asb-pwned", "evil")
    assert not Path("/tmp/asb-pwned").exists()


@pytest.mark.parametrize(
    ("url", "name"),
    [("https://github.com/org/repo.git", "repo"), ("git@github.com:org/repo.git", "repo"),
     ("host:repo", "repo"), ("/srv/git/project/.git", "project"), ("/srv/git/p.git/", "p"),
     ("file:///srv/x", "x")],
)  # fmt: skip
def test_clone_dir_name(url: str, name: str) -> None:
    assert manage.clone_dir_name(url) == name


def test_clone_dir_name_rejects_empty() -> None:
    with pytest.raises(SandboxError, match="pass DIR"):
        manage.clone_dir_name("/")


def test_orphan_reasons(repo: Path, tmp_path: Path) -> None:
    engine = FakeEngine()
    good = manage.Workspace(make_id(repo), str(repo), engine)
    assert good.orphan_reason() is None
    assert "no workspace path" in (manage.Workspace("x", None, engine).orphan_reason() or "")
    gone = manage.Workspace("x", str(tmp_path / "gone"), engine)
    assert "no longer exists" in (gone.orphan_reason() or "")
    plain = tmp_path / "plain"
    plain.mkdir()
    assert "git working tree" in (manage.Workspace("x", str(plain), engine).orphan_reason() or "")
    assert "identity" in (manage.Workspace("other-id", str(repo), engine).orphan_reason() or "")


def test_collect_and_find_workspaces(tmp_path: Path) -> None:
    engine = FakeEngine()
    a = project_for(make_repo(tmp_path / "alpha"))
    b = project_for(make_repo(tmp_path / "alphabet"))
    labels = a.labels("workspace")
    engine.add("container", a.workspace_container, labels, State={"Status": "running"})
    engine.add("container", a.proxy_container, a.labels("proxy"), State={"Status": "running"})
    engine.add("network", a.network, a.labels("network"))
    engine.add("volume", "va", {**a.labels("state"), LABEL_STATE_SCOPE: "per-workspace"})
    engine.add("volume", "shared", {**a.labels("state"), LABEL_STATE_SCOPE: "login"})
    engine.add("volume", "vb", {**b.labels("state"), LABEL_STATE_SCOPE: "per-workspace"})
    engine.add("container", "unrelated", {LABEL_ROLE: "workspace"})
    found = manage.collect_workspaces([engine])
    assert [w.id for w in found] == [a.id, b.id]
    first, second = found
    assert first.containers == {"workspace": "running", "proxy": "running"}
    assert first.networks == [a.network] and first.volumes == ["va"]
    assert (first.state, second.state) == ("running", "state only")

    assert manage.find_workspace(a.id, found) is first
    assert manage.find_workspace("alphab", found) is second
    with pytest.raises(SandboxError, match="ambiguous"):
        manage.find_workspace("alpha", found)
    with pytest.raises(SandboxError, match="No sandbox"):
        manage.find_workspace("zzz", found)


def test_print_workspaces(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    engine = FakeEngine()
    manage.print_workspaces([])
    assert "No sandboxes" in capsys.readouterr().out
    gone = manage.Workspace("gone-12345678", str(tmp_path / "gone"), engine, volumes=["v"])
    manage.print_workspaces([gone])
    out = capsys.readouterr().out
    assert "gone-12345678" in out and "state only" in out and "orphaned:" in out


def test_prune_needs_tty(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    engine = FakeEngine()
    orphan = manage.Workspace("gone", str(tmp_path / "gone"), engine)
    monkeypatch.setattr(manage, "list_workspaces", lambda: [orphan])
    monkeypatch.setattr(manage, "is_tty", lambda: False)
    with pytest.raises(SandboxError, match="interactive"):
        manage.prune()


def test_repair_keeps_live_net_session(repo: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from agent_sandbox import proxyctl

    from .test_sandbox import make_ctx

    ctx = make_ctx(repo, FakeEngine("podman"))
    proxyctl.prepare_runtime(ctx.project)
    proxyctl.write_deadline(ctx.engine, ctx.project, 2_000_000_000)
    (proxyctl.runtime_path(ctx.project) / "net.pid").write_text(str(os.getpid()))
    manage.repair(ctx)
    assert proxyctl.read_deadline(ctx.project) is not None
    (proxyctl.runtime_path(ctx.project) / "net.pid").write_text("999999999")
    manage.repair(ctx)
    assert proxyctl.read_deadline(ctx.project) is None


def test_repair_reclaims_before_reapplying_acls(
    repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from .test_sandbox import make_ctx

    engine = FakeEngine("docker")
    ctx = make_ctx(repo, engine)
    ws = ctx.project.workspace_container
    engine.add("container", ws, {}, State={"Status": "running"})
    engine.on(("exec", ws, "cat", "/proc/self/uid_map"), lambda args: "0 1000 1\n1 100000 65536\n")
    steps: list[str] = []
    monkeypatch.setattr(manage, "reclaim_workspace", lambda c, p: steps.append("reclaim") or (3, 0))
    monkeypatch.setattr(
        manage, "share_workspace", lambda c, p, uid: steps.append(f"acl {uid}") or 0
    )
    monkeypatch.setattr(manage, "reset_volume_ownership", lambda c, p, i: steps.append("state"))
    monkeypatch.setattr(manage, "container_home", lambda c: "/home/dev")
    manage.repair(ctx)
    assert steps == ["reclaim", "acl 100999", "state"]


def test_repair_reclaims_on_other_engines_too(repo: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from .test_sandbox import make_ctx

    engine = FakeEngine("podman")
    ctx = make_ctx(repo, engine)
    steps: list[str] = []
    monkeypatch.setattr(manage, "reclaim_workspace", lambda c, p: steps.append("reclaim") or (0, 0))
    monkeypatch.setattr(manage, "share_workspace", lambda c, p, uid: pytest.fail("no ACLs"))
    monkeypatch.setattr(manage, "reset_volume_ownership", lambda c, p, i: steps.append("state"))
    monkeypatch.setattr(manage, "container_home", lambda c: "/home/dev")
    manage.repair(ctx)
    assert steps == []  # not running: nothing to reclaim
    engine.add("container", ctx.project.workspace_container, {}, State={"Status": "running"})
    manage.repair(ctx)
    assert steps == ["reclaim", "state"]


CONFINED = {"Seccomp": "2", "NoNewPrivs": "1", "CapEff": "0000000000000000"}


def test_parse_proc_status() -> None:
    text = (
        "CapEff:\t0000000000000000\nNoNewPrivs:\t1\nSeccomp:\t2\n"
        "Label:\tdocker-default (enforce)\0\n"
    )
    assert manage.parse_proc_status(text) == {**CONFINED, "Label": "docker-default (enforce)"}


@pytest.mark.parametrize(
    ("change", "ok", "fragment"),
    [
        ({}, True, "seccomp filter, no-new-privileges, no capabilities"),
        ({"Seccomp": "0"}, False, "seccomp is off (mode 0)"),
        ({"NoNewPrivs": "0"}, False, "no-new-privileges is not set"),
        ({"CapEff": "00000000a80425fb"}, False, "has capabilities (00000000a80425fb)"),
    ],
)
def test_process_confinement(change: dict[str, str], ok: bool, fragment: str) -> None:
    result = manage.process_confinement("the sandbox user", {**CONFINED, **change})
    assert result[0] == ok and fragment in result[1]


def test_process_confinement_without_output_fails() -> None:
    ok, text = manage.process_confinement("the proxy", {})
    assert not ok and "seccomp is off (mode ?)" in text and "has capabilities (?)" in text


@pytest.mark.parametrize(
    ("host", "ok", "fragment"),
    [
        ({"Privileged": False, "CapAdd": None}, True, "not privileged"),
        ({"Privileged": True}, False, "is privileged"),
        ({"CapAdd": ["SYS_ADMIN", "NET_ADMIN"]}, False, "capabilities: SYS_ADMIN, NET_ADMIN"),
    ],
)
def test_container_privileges(host: dict[str, object], ok: bool, fragment: str) -> None:
    result = manage.container_privileges({"HostConfig": host})
    assert result[0] == ok and fragment in result[1]


@pytest.mark.parametrize(
    ("label", "modules", "rootless", "level"),
    [
        ("docker-default (enforce)", {"apparmor"}, False, "ok"),
        ("system_u:system_r:container_t:s0:c1,c2", {"selinux"}, True, "ok"),
        ("kernel", set(), False, "warn"),
        ("runc (unconfined)", set(), True, "warn"),  # rootless docker, Ubuntu 24.04 host
        ("", set(), True, "warn"),
        ("unconfined", {"apparmor"}, True, "warn"),
        ("unconfined", {"apparmor"}, False, "FAIL"),
        ("docker-default (complain)", {"apparmor"}, False, "FAIL"),
        ("system_u:system_r:spc_t:s0", {"selinux"}, False, "FAIL"),
        ("unconfined_u:unconfined_r:unconfined_t:s0", {"selinux"}, False, "FAIL"),
    ],
)
def test_lsm_confinement(label: str, modules: set[str], rootless: bool, level: str) -> None:
    assert manage.lsm_confinement(label, modules, rootless=rootless)[0] == level
