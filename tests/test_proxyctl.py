from __future__ import annotations

import time
from pathlib import Path

import pytest

from agent_sandbox import manage, proxyctl
from agent_sandbox.project import Project, project_for
from agent_sandbox.proxy import CONFIG_END
from agent_sandbox.util import SandboxError

from .fakes import FakeEngine, done
from .test_sandbox import IMAGE


@pytest.fixture
def project(repo: Path) -> Project:
    manage.init_project(project_for(repo), IMAGE)
    return project_for(repo)


def pushed(engine: FakeEngine, project: Project, name: str) -> str:
    return engine.files[(project.proxy_container, f"/var/lib/asb/{name}")]


def test_base_tier_is_pushed_filter_first(
    project: Project, monkeypatch: pytest.MonkeyPatch, isolated_dirs: Path
) -> None:
    monkeypatch.setenv("HTTPS_PROXY", "http://user:secret@corp:3128")
    monkeypatch.setenv("NO_PROXY", ".corp.example")
    engine = FakeEngine()
    entries = proxyctl.write_base_tier(engine, project, "172.18.0.0/16")
    assert "api.anthropic.com" in entries and "pypi.org" not in entries
    assert engine.copies == [
        (project.proxy_container, ["base.filter", "base.conf", "net.filter", "net.conf"])
    ]
    conf = pushed(engine, project, "base.conf")
    assert conf.startswith("# Static tinyproxy settings")
    assert conf.rstrip("\n").endswith(CONFIG_END)
    assert 'Filter "/var/lib/asb/base.filter"' in conf
    assert "Upstream http user:secret@corp:3128" in conf and 'Upstream none ".corp.example"' in conf
    assert pushed(engine, project, "net.conf").replace("net.filter", "base.filter") == conf
    assert not any("user:secret" in p.read_text() for p in isolated_dirs.rglob("*") if p.is_file())


def test_base_tier_does_not_clobber_running_session(project: Project) -> None:
    engine = FakeEngine()
    proxyctl.write_net_tier(engine, project, None, ["pypi.org"], allow_all=False)
    proxyctl.write_deadline(engine, project, time.time() + 60)
    proxyctl.write_base_tier(engine, project, None)
    assert engine.copies[-1][1] == ["base.filter", "base.conf"]
    assert "pypi" in pushed(engine, project, "net.filter")


def test_net_tier_allow_all_has_no_filter(project: Project) -> None:
    engine = FakeEngine()
    entries = proxyctl.write_net_tier(engine, project, None, ["10.1.2.3"], allow_all=True)
    assert engine.copies == [(project.proxy_container, ["net.conf"])]
    conf = pushed(engine, project, "net.conf")
    assert "Filter" not in conf
    assert 'Upstream http 0.0.0.0:0 "10.0.0.0/8"' in conf
    assert conf.splitlines()[-2] == 'Upstream none "10.1.2.3"'
    assert "10.1.2.3" in entries


def test_static_config_is_validated(project: Project) -> None:
    (project.root / ".agent-sandbox" / "tinyproxy.conf").write_text("Port 1\n")
    with pytest.raises(SandboxError, match="generates itself"):
        proxyctl.write_base_tier(FakeEngine(), project, None)


def test_deadline_is_pushed_and_mirrored(project: Project) -> None:
    engine = FakeEngine()
    engine.add("container", project.proxy_container, {})
    assert proxyctl.active_deadline(project) is None
    proxyctl.write_deadline(engine, project, time.time() - 5)
    assert proxyctl.read_deadline(project) is not None
    assert proxyctl.active_deadline(project) is None
    soon = time.time() + 5
    proxyctl.write_deadline(engine, project, soon)
    assert proxyctl.active_deadline(project) == int(soon)
    assert pushed(engine, project, "deadline") == f"{int(soon)}\n"
    proxyctl.clear_deadline(engine, project)
    assert proxyctl.read_deadline(project) is None
    assert pushed(engine, project, "deadline") == "0\n"


def test_clear_deadline_without_proxy(project: Project) -> None:
    engine = FakeEngine()
    proxyctl.clear_deadline(engine, project)
    assert engine.copies == []


def test_status_and_reload(project: Project) -> None:
    engine = FakeEngine()
    state = {"text": "base 1\n"}
    engine.on(("exec", project.proxy_container, "cat"), lambda args: state["text"])
    assert proxyctl.proxy_status(engine, project) == ("base", "1")
    assert proxyctl.proxy_state(engine, project) == "base"
    assert proxyctl.wait_for_state(engine, project, "base", timeout=1)
    assert not proxyctl.wait_for_state(engine, project, "net", timeout=0.4)

    def acknowledge(args: tuple[str, ...]) -> str:
        nonce = pushed(engine, project, "reload").strip()
        return f"net {nonce}\n"

    engine.on(("exec", project.proxy_container, "cat"), acknowledge)
    assert proxyctl.request_reload(engine, project, timeout=2)
    engine.on(("exec", project.proxy_container, "cat"), lambda args: done(args, "", 1))
    assert proxyctl.proxy_status(engine, project) is None
    assert not proxyctl.request_reload(engine, project, timeout=0.4)
