"""`agent-sandbox net`: time-boxed extra network access through the proxy."""

from __future__ import annotations

import contextlib
import json
import os
import queue
import signal
import subprocess
import sys
import threading
import time
from collections import Counter
from collections.abc import Generator
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path

from . import approval, proxy, proxyctl
from .config import ALLOW_EXTRA_FILE, PROJECT_DIR
from .proxy import LogEvent
from .sandbox import Context, project_lock
from .util import SandboxError, confirm, eprint, format_duration, is_tty

ALLOW_ALL_WARNING = """\
WARNING: --allow-all lets the sandbox reach ANY host on the internet for the whole period.
  - Everything in the workspace and every secret in the container environment can be sent out.
  - Internal names listed in your NO_PROXY and private IP ranges stay blocked (hosts you
    allowlisted are the exception). If NO_PROXY is unset, internal *names* are not recognised.
Use it for surveys and first-time setup, not for unattended work."""

SPINNER = "|/-\\"
# The net tier opened for setup is a lease, renewed while setup runs: a killed CLI leaves it
# open for at most this long.
SETUP_LEASE = 300
SETUP_RENEW = 60
HOURGLASS = ("⏳", "⌛")


@dataclass
class NetSession:
    allow_all: bool = False
    hosts: list[str] = field(default_factory=list)


def render_bar(remaining: float, total: float, width: int = 24) -> str:
    fraction = 0.0 if total <= 0 else max(0.0, min(1.0, remaining / total))
    filled = round(fraction * width)
    return "[" + "█" * filled + "░" * (width - filled) + "]"


class LogTail:
    """Collects log lines from a process (the proxy's container log) in the background."""

    def __init__(self, process: subprocess.Popen[str]) -> None:
        self.process = process
        self.lines: queue.Queue[str] = queue.Queue()
        threading.Thread(target=self._read, daemon=True).start()

    def _read(self) -> None:
        if self.process.stdout is not None:
            for line in self.process.stdout:
                self.lines.put(line)

    def poll(self) -> list[LogEvent]:
        events = []
        while True:
            try:
                line = self.lines.get_nowait()
            except queue.Empty:
                return events
            if event := proxy.parse_log_line(line):
                events.append(event)

    def close(self) -> None:
        self.process.terminate()
        try:
            self.process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.process.kill()


@dataclass
class Observed:
    allowed: list[str]
    allow_all: bool
    no_proxy: tuple[str, ...] = ()
    requested: Counter[str] = field(default_factory=Counter)
    refused: Counter[str] = field(default_factory=Counter)

    def add(self, event: LogEvent) -> str | None:
        """Record an event; return a live message the first time something noteworthy is seen."""
        if event.kind == "refused":
            first = event.host not in self.refused
            self.refused[event.host] += 1
            return f"blocked: {event.host}" if first else None
        first = event.host not in self.requested
        self.requested[event.host] += 1
        if first and self.allow_all and not proxy.host_allowed(self.allowed, event.host):
            if proxy.is_internal(event.host, self.no_proxy):
                return f"blocked (internal): {event.host}"
            return f"outside allowlists: {event.host}"
        return None

    def candidates(self) -> list[tuple[str, int]]:
        """Hosts worth adding to the allowlist, most used first."""
        if self.allow_all:
            counts = Counter(
                {
                    host: n
                    for host, n in self.requested.items()
                    if not proxy.host_allowed(self.allowed, host)
                    and not proxy.is_internal(host, self.no_proxy)
                }
            )
        else:
            counts = Counter(self.refused)
        return counts.most_common()


def _pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _session_path(ctx: Context) -> Path:
    return proxyctl.runtime_path(ctx.project) / "net.json"


def _pid_path(ctx: Context) -> Path:
    return proxyctl.runtime_path(ctx.project) / "net.pid"


def _load_session(ctx: Context) -> NetSession:
    try:
        data = json.loads(_session_path(ctx).read_text())
        return NetSession(bool(data.get("allow_all")), list(data.get("hosts", [])))
    except (FileNotFoundError, json.JSONDecodeError):
        return NetSession()


def _save_session(ctx: Context, session: NetSession) -> None:
    proxyctl.prepare_runtime(ctx.project)
    _session_path(ctx).write_text(
        json.dumps({"allow_all": session.allow_all, "hosts": session.hosts})
    )


def owner_alive(ctx: Context) -> bool:
    try:
        return _pid_alive(int(_pid_path(ctx).read_text().strip()))
    except (FileNotFoundError, ValueError):
        return False


def stop_net(ctx: Context) -> None:
    project = ctx.project
    if proxyctl.active_deadline(project) is None:
        eprint("No network session is active.")
        return
    proxyctl.clear_deadline(ctx.engine, project)
    if not proxyctl.wait_for_state(ctx.engine, project, "base"):
        raise SandboxError("The proxy did not return to the base allowlist in time.")
    eprint("Network session ended; the proxy is back on the base allowlist.")


def _require_running_proxy(ctx: Context) -> None:
    if ctx.engine.container_status(ctx.project.proxy_container) != "running":
        raise SandboxError(
            "The sandbox is not running. Start it with `agent-sandbox`, then run `net` "
            "from a second terminal."
        )


def run_net(
    ctx: Context,
    *,
    duration: int | None,
    allow: list[str],
    allow_all: bool,
    extend: bool,
) -> int:
    if duration is None:
        raise SandboxError("A duration is required: agent-sandbox net <seconds|Nm|Nh>.")
    hosts = [proxy.parse_allow_entry(h, "--allow") for h in allow]
    project = ctx.project
    with project_lock(project):
        approval.ensure_approved(project)
        _require_running_proxy(ctx)
        now = time.time()
        active = proxyctl.active_deadline(project)
        session = _load_session(ctx) if active else NetSession()
        if active and not extend:
            raise SandboxError(
                f"A network session is already active ({format_duration(active - now)} left). "
                "Use --extend to add time, or `agent-sandbox net --stop`."
            )
        if allow_all and not session.allow_all:
            eprint(ALLOW_ALL_WARNING)
            if not is_tty():
                raise SandboxError("--allow-all needs an interactive terminal to confirm.")
            if not confirm(f"Allow ALL hosts for {format_duration(duration)}?"):
                raise SandboxError("Cancelled.")
        session.allow_all = session.allow_all or allow_all
        session.hosts = proxy.merge_entries(session.hosts, hosts)
        subnet = ctx.engine.network_subnet(project.network)
        entries = proxyctl.write_net_tier(
            ctx.engine, project, subnet, session.hosts, allow_all=session.allow_all
        )
        _save_session(ctx, session)
        deadline = (active or now) + duration
        proxyctl.write_deadline(ctx.engine, project, deadline)
        if active:
            proxyctl.request_reload(ctx.engine, project)
            if owner_alive(ctx):
                eprint(f"Extended; the session now ends in {format_duration(deadline - now)}.")
                return 0
        elif not proxyctl.wait_for_state(ctx.engine, project, "net"):
            proxyctl.clear_deadline(ctx.engine, project)
            raise SandboxError("The proxy did not switch to the network tier in time.")
        _pid_path(ctx).write_text(str(os.getpid()))
    return _watch(ctx, entries, session, total=deadline - now, since=now)


@contextlib.contextmanager
def setup_network(ctx: Context) -> Generator[Observed]:
    """The net tier (base + allow.extra) while the setup's create phase runs.

    An active `net` session is used as it is (and left running). Otherwise a lease is opened and
    renewed; at the end it is closed unless someone else changed the deadline meanwhile (`net
    --extend` or `--stop`). Blocked hosts are reported live and collected in the result.
    """
    project, engine = ctx.project, ctx.engine
    lease: float | None = None
    with project_lock(project):
        _require_running_proxy(ctx)
        if proxyctl.active_deadline(project) is None:
            subnet = engine.network_subnet(project.network)
            entries = proxyctl.write_net_tier(engine, project, subnet, [], allow_all=False)
            _save_session(ctx, NetSession())
            lease = float(int(time.time()) + SETUP_LEASE)  # stored in whole seconds
            proxyctl.write_deadline(engine, project, lease)
            if not proxyctl.wait_for_state(engine, project, "net"):
                proxyctl.clear_deadline(engine, project)
                raise SandboxError("The proxy did not switch to the network tier in time.")
            _pid_path(ctx).write_text(str(os.getpid()))
            allow_all = False
        else:
            session = _load_session(ctx)
            base, extra = proxyctl.read_allowlists(project)
            entries = proxy.merge_entries(base, extra, session.hosts)
            allow_all = session.allow_all
    log = LogTail(proxyctl.follow_log(engine, project, time.time()))
    observed = Observed(entries, allow_all, no_proxy=proxy.read_proxy_env(os.environ).no_proxy)
    stop = threading.Event()

    def report() -> None:
        for event in log.poll():
            if message := observed.add(event):
                eprint(f"agent-sandbox: {message}")

    def background() -> None:
        nonlocal lease
        last_renewal = time.monotonic()
        while not stop.wait(0.5):
            report()
            if lease is None or time.monotonic() - last_renewal < SETUP_RENEW:
                continue
            last_renewal = time.monotonic()
            if proxyctl.read_deadline(project) != lease:
                lease = None  # taken over by `net`: leave it alone
                continue
            lease = float(int(time.time()) + SETUP_LEASE)  # stored in whole seconds
            proxyctl.write_deadline(engine, project, lease)

    thread = threading.Thread(target=background, daemon=True)
    thread.start()
    try:
        yield observed
    finally:
        stop.set()
        thread.join()
        if lease is not None and proxyctl.read_deadline(project) == lease:
            proxyctl.clear_deadline(engine, project)
            _pid_path(ctx).unlink(missing_ok=True)
            proxyctl.wait_for_state(engine, project, "base")
        time.sleep(0.5)  # let the last log lines arrive
        report()
        log.close()


def _install_signal_handlers() -> None:
    def handler(signum: int, _frame: object) -> None:
        raise KeyboardInterrupt

    for sig in (signal.SIGTERM, signal.SIGHUP):
        signal.signal(sig, handler)


def _watch(
    ctx: Context, entries: list[str], session: NetSession, *, total: float, since: float
) -> int:
    project = ctx.project
    _install_signal_handlers()
    log = LogTail(proxyctl.follow_log(ctx.engine, project, since))
    observed = Observed(
        entries, session.allow_all, no_proxy=proxy.read_proxy_env(os.environ).no_proxy
    )
    tty = sys.stderr.isatty()
    mode = "ALL hosts" if session.allow_all else f"{len(entries)} allowed hosts"
    eprint(f"Network access is on ({mode}). Press Ctrl-C to end it early.")
    last_plain = 0.0
    tick = 0
    interrupted = False
    try:
        while True:
            deadline = proxyctl.read_deadline(project)
            remaining = (deadline or 0) - time.time()
            if deadline is None or remaining <= 0:
                break
            for event in log.poll():
                message = observed.add(event)
                if message:
                    eprint(("\r\x1b[K" if tty else "") + f"  {message}")
            if tty:
                glyph = HOURGLASS[tick % 2] if sys.stderr.encoding == "utf-8" else SPINNER[tick % 4]
                bar = render_bar(remaining, max(total, remaining))
                line = f"{glyph} net {bar} {format_duration(remaining)} left  {mode}"
                sys.stderr.write("\r\x1b[K" + line)
                sys.stderr.flush()
            elif time.monotonic() - last_plain >= 30:
                eprint(f"net: {format_duration(remaining)} left")
                last_plain = time.monotonic()
            tick += 1
            time.sleep(0.5)
    except KeyboardInterrupt:
        interrupted = True
    finally:
        if tty:
            sys.stderr.write("\r\x1b[K")
        proxyctl.clear_deadline(ctx.engine, project)
        _pid_path(ctx).unlink(missing_ok=True)
        proxyctl.wait_for_state(ctx.engine, project, "base")
        time.sleep(0.5)  # let the last log lines arrive
        for event in log.poll():
            observed.add(event)
        log.close()
    eprint("Network session ended early." if interrupted else "Network session expired.")
    eprint("The proxy is back on the base allowlist.")
    offer_promotion(ctx, observed)
    return 130 if interrupted else 0


def offer_promotion(ctx: Context, observed: Observed) -> None:
    candidates = observed.candidates()
    if not candidates:
        eprint("No hosts outside your allowlists were accessed or blocked.")
        return
    label = "accessed outside" if observed.allow_all else "blocked by"
    eprint(f"\nHosts {label} your allowlists:")
    for host, count in candidates:
        eprint(f"  {count:5d}  {host}")
    if not is_tty():
        return
    try:
        answer = (
            input(f"\nAdd them to {PROJECT_DIR}/{ALLOW_EXTRA_FILE}? [y/N/s(elect)] ")
            .strip()
            .lower()
        )
    except EOFError:
        return
    if answer in ("y", "yes"):
        chosen = [host for host, _ in candidates]
    elif answer in ("s", "select"):
        chosen = [host for host, _ in candidates if confirm(f"  add {host}?")]
    else:
        return
    if chosen:
        append_to_extra(ctx, chosen)


def append_to_extra(ctx: Context, hosts: list[str]) -> None:
    project = ctx.project
    path = project.root / PROJECT_DIR / ALLOW_EXTRA_FILE
    existing = path.read_text() if path.exists() else ""
    known = set(proxy.parse_allow_text(existing, str(path)))
    new = [h for h in hosts if h not in known]
    if not new:
        return
    block = (
        f"\n# added by `agent-sandbox net` on {date.today().isoformat()}\n" + "\n".join(new) + "\n"
    )
    if existing and not existing.endswith("\n"):
        block = "\n" + block
    with path.open("a") as handle:
        handle.write(block)
    approval.record(project)
    eprint(f"Added {len(new)} host(s) to {PROJECT_DIR}/{ALLOW_EXTRA_FILE}.")
