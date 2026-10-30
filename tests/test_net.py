from __future__ import annotations

import subprocess
import time
from pathlib import Path

import pytest

from agent_sandbox import approval, manage, net, proxyctl
from agent_sandbox.net import LogTail, Observed, render_bar
from agent_sandbox.project import project_for
from agent_sandbox.proxy import LogEvent
from agent_sandbox.util import SandboxError

from .fakes import FakeEngine
from .test_sandbox import IMAGE, make_ctx


def test_render_bar() -> None:
    assert render_bar(10, 10, width=4) == "[████]"
    assert render_bar(5, 10, width=4) == "[██░░]"
    assert render_bar(0, 10, width=4) == "[░░░░]"
    assert render_bar(20, 10, width=4) == "[████]"
    assert render_bar(1, 0, width=2) == "[░░]"


def test_log_tail_parses_process_output() -> None:
    script = (
        "printf '%s\\n' 'NOTICE x: Proxying refused on filtered domain \"new.com\"'"
        " 'NOTICE x: Reloading config file' 'CONNECT x: Request (file descriptor 6):"
        " CONNECT a.org:443 HTTP/1.1' >&2"
    )
    tail = LogTail(
        subprocess.Popen(
            ["sh", "-c", script], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True
        )
    )
    events: list[LogEvent] = []
    end = time.monotonic() + 5
    while len(events) < 2 and time.monotonic() < end:
        events += tail.poll()
        time.sleep(0.05)
    tail.close()
    assert events == [LogEvent("refused", "new.com"), LogEvent("request", "a.org")]
    assert tail.poll() == []


def test_log_tail_close_stops_a_follower() -> None:
    tail = LogTail(subprocess.Popen(["sleep", "30"], stdout=subprocess.PIPE, text=True))
    tail.close()
    assert tail.process.returncode is not None


def test_observed_filtered_mode() -> None:
    seen = Observed(["api.anthropic.com"], allow_all=False)
    assert seen.add(LogEvent("request", "pypi.org")) is None
    assert seen.add(LogEvent("refused", "pypi.org")) == "blocked: pypi.org"
    assert seen.add(LogEvent("refused", "pypi.org")) is None
    seen.add(LogEvent("refused", "a.org"))
    seen.add(LogEvent("request", "api.anthropic.com"))
    assert seen.candidates() == [("pypi.org", 2), ("a.org", 1)]


def test_observed_allow_all_mode() -> None:
    seen = Observed([".github.com"], allow_all=True, no_proxy=(".corp.example",))
    assert seen.add(LogEvent("request", "api.github.com")) is None
    assert seen.add(LogEvent("request", "pypi.org")) == "outside allowlists: pypi.org"
    assert seen.add(LogEvent("request", "pypi.org")) is None
    assert seen.add(LogEvent("request", "git.corp.example")) == "blocked (internal): git.corp.example"
    assert seen.add(LogEvent("request", "10.0.0.1")) == "blocked (internal): 10.0.0.1"
    assert seen.candidates() == [("pypi.org", 2)]


@pytest.fixture
def configured(repo: Path) -> Path:
    manage.init_project(project_for(repo), IMAGE)
    return repo


def test_append_to_extra_updates_approval(configured: Path) -> None:
    ctx = make_ctx(configured)
    path = configured / ".agent-sandbox" / "allow.extra"
    path.write_text(path.read_text() + "pypi.org")  # no trailing newline
    approval.record(ctx.project)
    net.append_to_extra(ctx, ["pypi.org", "files.pythonhosted.org", ".npmjs.org"])
    text = path.read_text()
    assert "pypi.org\n\n# added by `agent-sandbox net`" in text
    assert text.endswith("files.pythonhosted.org\n.npmjs.org\n")
    assert approval.is_approved(ctx.project)
    net.append_to_extra(ctx, ["pypi.org"])
    assert path.read_text() == text


def running_ctx(configured: Path):
    engine = FakeEngine()
    ctx = make_ctx(configured, engine)
    engine.add("container", ctx.project.proxy_container, {}, State={"Status": "running"})
    engine.add("network", ctx.project.network, {}, IPAM={"Config": [{"Subnet": "172.30.0.0/16"}]})
    return ctx


def test_net_needs_running_proxy(configured: Path) -> None:
    ctx = make_ctx(configured)
    with pytest.raises(SandboxError, match="not running"):
        net.run_net(ctx, duration=60, allow=[], allow_all=False, extend=False)


def test_net_rejects_bad_hosts_and_missing_duration(configured: Path) -> None:
    ctx = running_ctx(configured)
    with pytest.raises(SandboxError, match="wildcards"):
        net.run_net(ctx, duration=60, allow=["*.x.com"], allow_all=False, extend=False)
    with pytest.raises(SandboxError, match="duration is required"):
        net.run_net(ctx, duration=None, allow=[], allow_all=False, extend=False)


def test_second_session_needs_extend(configured: Path) -> None:
    ctx = running_ctx(configured)
    proxyctl.write_deadline(ctx.engine, ctx.project, time.time() + 300)
    with pytest.raises(SandboxError, match="--extend"):
        net.run_net(ctx, duration=60, allow=[], allow_all=False, extend=False)


def test_allow_all_needs_tty(configured: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    ctx = running_ctx(configured)
    monkeypatch.setattr(net, "is_tty", lambda: False)
    with pytest.raises(SandboxError, match="interactive"):
        net.run_net(ctx, duration=60, allow=[], allow_all=True, extend=False)
    assert proxyctl.read_deadline(ctx.project) is None


def test_net_session_starts_without_runtime_dir(
    configured: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ctx = running_ctx(configured)
    monkeypatch.setattr(proxyctl, "wait_for_state", lambda engine, project, wanted: True)
    monkeypatch.setattr(net, "_watch", lambda ctx, entries, session, **kw: 0)
    assert net.run_net(ctx, duration=30, allow=[], allow_all=False, extend=False) == 0
    assert proxyctl.active_deadline(ctx.project) is not None


def test_extend_with_live_owner_only_moves_deadline(
    configured: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ctx = running_ctx(configured)
    start = time.time() + 100
    proxyctl.write_deadline(ctx.engine, ctx.project, start)
    monkeypatch.setattr(proxyctl, "request_reload", lambda engine, project: True)
    monkeypatch.setattr(net, "owner_alive", lambda ctx: True)
    assert net.run_net(ctx, duration=60, allow=["pypi.org"], allow_all=False, extend=True) == 0
    assert proxyctl.read_deadline(ctx.project) == int(start + 60)
    engine, proxy_name = ctx.engine, ctx.project.proxy_container
    assert isinstance(engine, FakeEngine)
    assert r"^pypi\.org$" in engine.files[(proxy_name, "/var/lib/asb/net.filter")]
    assert "Allow 172.30.0.0/16" in engine.files[(proxy_name, "/var/lib/asb/net.conf")]
    # configurations first, then the deadline that activates them
    assert [names for _, names in engine.copies[-2:]] == [["net.filter", "net.conf"], ["deadline"]]


def test_stop_net(configured: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    ctx = running_ctx(configured)
    net.stop_net(ctx)  # nothing active: just a message
    proxyctl.write_deadline(ctx.engine, ctx.project, time.time() + 100)
    monkeypatch.setattr(
        proxyctl, "wait_for_state", lambda engine, project, wanted: wanted == "base"
    )
    net.stop_net(ctx)
    assert proxyctl.read_deadline(ctx.project) is None
