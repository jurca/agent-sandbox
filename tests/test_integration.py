"""End-to-end tests against a real engine (`pytest --integration`).

They need rootless docker (or another engine the CLI accepts), `setfacl`, and outbound HTTPS to
example.com. Everything lives in /tmp/asb-it-* with isolated AGENT_SANDBOX_*_DIR; finalizers run
`rm --state`. Images are never pulled: ASB_TEST_IMAGE (default: a local devcontainer image whose
uid 1000 user exists) must be present, and the derived-image tests use the locally built
tinyproxy image as their Alpine base. The devcontainer test only runs when
ASB_TEST_DEVCONTAINER_CLI names the devcontainers CLI (e.g. "npx @devcontainers/cli") and
ASB_TEST_DEVCONTAINER_IMAGE (default debian:bookworm-slim) is present; it uses a local Feature,
so it needs no registry.
"""

from __future__ import annotations

import getpass
import grp
import json
import os
import pty
import re
import select
import shlex
import shutil
import signal
import socket
import subprocess
import tempfile
import threading
import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from pathlib import Path

import pytest

from agent_sandbox.config import DEFAULT_PROXY_BASE_IMAGE, UserConfig
from agent_sandbox.engine import detect_engine
from agent_sandbox.images import derived_tag, ensure_user_image, proxy_image_tag
from agent_sandbox.project import make_id

from .conftest import git, make_repo

pytestmark = pytest.mark.integration

LAUNCHER = str(Path(__file__).resolve().parent.parent / "agent-sandbox")
IMAGE = os.environ.get("ASB_TEST_IMAGE", "python:3.14")
DEFAULT_HARNESS_LINE = 'harness = ["claude", "copilot", "bash", "sh"]'
ENGINE = os.environ.get("ASB_TEST_ENGINE", "docker")

PROBE = r"""
connect() {
  exec 3<>/dev/tcp/proxy/8888 || { echo "$1 noproxy"; return; }
  printf 'CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n' "$1" "$1" >&3
  line=""; read -r -t 15 line <&3; line=${line%$'\r'}
  echo "$1 ${line:-timeout}"
  exec 3>&-
}
get() {
  exec 3<>/dev/tcp/proxy/8888 || { echo "$1 noproxy"; return; }
  printf 'GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n' "$1" "${1#http://}" >&3
  line=""; read -r -t 15 line <&3; line=${line%$'\r'}
  echo "$1 ${line:-timeout}"
  exec 3>&-
}
for target; do case $target in http://*) get "$target" ;; *) connect "$target" ;; esac; done
"""


@dataclass
class Env:
    base: Path
    vars: dict[str, str]

    @property
    def user_config(self) -> Path:
        return self.base / "config" / "config.toml"

    def runtime(self, root: Path) -> Path:
        return self.base / "run" / make_id(root)


@dataclass
class Result:
    code: int
    out: str
    err: str

    @property
    def text(self) -> str:
        return self.out + self.err


def engine(*args: str, check: bool = False) -> subprocess.CompletedProcess[str]:
    return subprocess.run([ENGINE, *args], capture_output=True, text=True, check=check)


def has_image(ref: str) -> bool:
    return engine("image", "inspect", ref).returncode == 0


@pytest.fixture(scope="session")
def env() -> Iterator[Env]:
    if shutil.which(ENGINE) is None or engine("info").returncode != 0:
        pytest.skip(f"{ENGINE} is not usable")
    if not has_image(IMAGE):
        pytest.skip(f"{IMAGE} is not present locally (set ASB_TEST_IMAGE)")
    base = Path(tempfile.mkdtemp(prefix="asb-it-", dir="/tmp"))
    variables = {
        **os.environ,
        "AGENT_SANDBOX_CONFIG_DIR": str(base / "config"),
        "AGENT_SANDBOX_STATE_DIR": str(base / "state"),
        "AGENT_SANDBOX_RUNTIME_DIR": str(base / "run"),
        "TERM": "dumb",
    }
    (base / "config").mkdir()
    yield Env(base, variables)
    shutil.rmtree(base, ignore_errors=True)


def asb(env: Env, cwd: Path, *args: str, stdin: str = "", timeout: float = 300) -> Result:
    proc = subprocess.run(
        [LAUNCHER, *args],
        cwd=cwd,
        env=env.vars,
        input=stdin,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    return Result(proc.returncode, proc.stdout, proc.stderr)


def ok(env: Env, cwd: Path, *args: str, stdin: str = "") -> Result:
    result = asb(env, cwd, *args, stdin=stdin)
    assert result.code == 0, f"{args} failed ({result.code}):\n{result.text}"
    return result


def sh(env: Env, cwd: Path, script: str, *args: str) -> str:
    return ok(env, cwd, "exec", "--", "sh", "-c", script, "sh", *args).out


def probe(env: Env, cwd: Path, *targets: str) -> dict[str, str]:
    out = ok(env, cwd, "exec", "--", "bash", "-c", PROBE, "probe", *targets).out
    statuses = {}
    for line in out.splitlines():
        target, _, status = line.partition(" ")
        match = re.match(r"HTTP/1\.[01] (\d+)", status)
        statuses[target] = match.group(1) if match else status
    return statuses


Responder = Callable[[str], str | None]


@dataclass
class PtyRun:
    """Runs the CLI on a pseudo-terminal; `respond` sees new output and may type a reply."""

    env: Env
    cwd: Path
    args: tuple[str, ...]
    respond: Responder = lambda _text: None
    output: str = ""
    code: int | None = None
    _thread: threading.Thread | None = field(default=None, repr=False)
    _pid: int = 0

    def start(self) -> PtyRun:
        pid, fd = pty.fork()
        if pid == 0:  # pragma: no cover - child
            os.chdir(self.cwd)
            os.execve(LAUNCHER, [LAUNCHER, *self.args], self.env.vars)
        self._pid = pid
        self._thread = threading.Thread(target=self._pump, args=(fd,), daemon=True)
        self._thread.start()
        return self

    def _pump(self, fd: int) -> None:
        unanswered = ""
        while True:
            ready, _, _ = select.select([fd], [], [], 0.2)
            if ready:
                try:
                    chunk = os.read(fd, 4096).decode("utf-8", "replace")
                except OSError:
                    break
                if not chunk:
                    break
                self.output += chunk
                unanswered += chunk
                reply = self.respond(unanswered)
                if reply is not None:
                    os.write(fd, (reply + "\n").encode())
                    unanswered = ""
        _, status = os.waitpid(self._pid, 0)
        self.code = os.waitstatus_to_exitcode(status)
        os.close(fd)

    def wait(self, timeout: float = 120) -> PtyRun:
        assert self._thread is not None
        self._thread.join(timeout)
        if self._thread.is_alive():
            os.kill(self._pid, signal.SIGKILL)
            self._thread.join(5)
            pytest.fail(f"{self.args} did not finish:\n{self.output}")
        return self


def answer(*pairs: tuple[str, str]) -> Responder:
    """Reply to each prompt pattern in turn."""
    pending = list(pairs)

    def respond(text: str) -> str | None:
        if pending and re.search(pending[0][0], text):
            return pending.pop(0)[1]
        return None

    return respond


def wait_for(predicate: Callable[[], bool], timeout: float, what: str) -> None:
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if predicate():
            return
        time.sleep(0.25)
    pytest.fail(f"timed out waiting for {what}")


def proxy_state(env: Env, root: Path) -> str:
    result = engine("exec", f"agent-sandbox-{make_id(root)}-proxy", "cat", "/var/lib/asb/state")
    return result.stdout.split(" ", 1)[0].strip() if result.returncode == 0 else ""


def configure(root: Path, env: Env, image: str = IMAGE) -> None:
    """`init` records the approval itself, so nothing is created yet."""
    ok(env, root, "init", "--image", image, "--force")


def approve(env: Env, root: Path) -> None:
    run = PtyRun(env, root, ("exec", "--", "true"), answer((r"Approve this", "y"))).start()
    assert run.wait().code == 0, run.output


@pytest.fixture(scope="session")
def workspace(env: Env) -> Iterator[Path]:
    """One long-lived sandbox shared by the non-destructive tests."""
    root = make_repo(env.base / "main")
    configure(root, env)
    yield root
    asb(env, root, "rm", "--state")


@pytest.fixture
def scratch(env: Env, request: pytest.FixtureRequest) -> Iterator[Path]:
    """A fresh repository whose sandbox is removed afterwards (if it still exists)."""
    root = make_repo(env.base / f"ws-{request.node.name[:40]}")
    configure(root, env)
    yield root
    if root.exists():
        asb(env, root, "rm", "--state")
    else:
        asb(env, env.base, "rm", make_id(root), "--state")


def removed_by_id(sandbox_id: str) -> None:
    selector = f"label=agent-sandbox.id={sandbox_id}"
    for args in (("ps", "-a"), ("network", "ls"), ("volume", "ls")):
        listing = engine(*args, "--filter", selector, "--quiet").stdout.strip()
        assert listing == "", f"{args[0]} left over: {listing}"


# --- creation, exec, ownership ----------------------------------------------------------


def test_exec_runs_as_host_user_with_sandbox_environment(env: Env, workspace: Path) -> None:
    out = sh(
        env,
        workspace,
        'id -u; id -g; pwd; umask; echo "$HTTPS_PROXY $AGENT_SANDBOX"; '
        'echo "$CLAUDE_CONFIG_DIR"; git config --get safe.directory',
    )
    uid, gid, cwd, umask, proxy_line, claude_dir, safe = out.split("\n")[:7]
    assert (uid, gid) == (str(os.getuid()), str(os.getgid()))
    assert cwd == str(workspace.resolve())  # the workspace keeps its host path
    current = os.umask(0)
    os.umask(current)
    assert umask == f"{current:04o}"
    assert proxy_line == "http://proxy:8888 1"
    assert claude_dir.endswith("/.claude")
    assert safe == "*"


def test_workspace_is_shared_and_git_and_config_are_read_only(env: Env, workspace: Path) -> None:
    sh(
        env,
        workspace,
        "echo from-sandbox > made-inside && mkdir -p d/e && echo x > d/e/f",
    )
    made = workspace / "made-inside"
    assert made.read_text() == "from-sandbox\n"
    made.write_text("host can write\n")  # default ACL gives the host user access back
    (workspace / "d" / "e" / "f").unlink()
    (workspace / "host-file").write_text("x")
    assert sh(env, workspace, "cat host-file; echo >> host-file && echo w") == "xw\n"
    script = (
        "for p in .git/x .git/hooks/pre-commit .agent-sandbox/x;"
        ' do if touch "$p" 2>/dev/null; then echo "writable $p"; fi; done;'
        " git status --short >/dev/null && echo status-ok;"
        " git commit -q --allow-empty -m x 2>/dev/null || echo commit-refused"
    )
    assert sh(env, workspace, script) == "status-ok\ncommit-refused\n"
    for name in ("made-inside", "host-file", "d"):
        target = workspace / name
        shutil.rmtree(target) if target.is_dir() else target.unlink()


def test_protected_paths_are_read_only_and_isolated_paths_are_separate(
    env: Env, workspace: Path
) -> None:
    (workspace / ".venv" / "host-marker").write_text("host venv")
    script = (
        "for p in .claude/settings.local.json .agents/x .vscode/x .idea/x .devcontainer/x;"
        ' do if touch "$p" 2>/dev/null; then echo "writable $p"; fi; done;'
        " ls -A .venv | grep -c host-marker;"
        " stat -c %u .venv node_modules; touch .venv/made-inside && echo venv-writable"
    )
    uid = str(os.getuid())
    assert sh(env, workspace, script).split() == ["0", uid, uid, "venv-writable"]
    for rel in (".claude", ".agents", ".vscode", ".idea", ".devcontainer"):
        assert (workspace / rel).is_dir() and not any((workspace / rel).iterdir())
    assert not (workspace / ".venv" / "made-inside").exists()
    ok(env, workspace, "recreate")
    assert sh(env, workspace, "ls .venv") == "made-inside\n"  # the volume survives recreate


def test_state_dirs_belong_to_the_user_and_survive_recreate(env: Env, scratch: Path) -> None:
    out = sh(
        env,
        scratch,
        'stat -c %u "$HOME/.claude" "$HOME/.copilot"; echo kept > "$HOME/.claude/marker"',
    )
    assert out.split() == [str(os.getuid())] * 2
    ok(env, scratch, "recreate")
    assert sh(env, scratch, 'cat "$HOME/.claude/marker"') == "kept\n"
    ok(env, scratch, "rm")
    assert sh(env, scratch, 'cat "$HOME/.claude/marker"') == "kept\n"
    ok(env, scratch, "rm", "--state")
    assert sh(env, scratch, 'cat "$HOME/.claude/marker" 2>/dev/null || echo gone') == "gone\n"


def test_tmp_is_a_fresh_executable_tmpfs_on_every_start(env: Env, scratch: Path) -> None:
    script = (
        "awk '$2 == \"/tmp\" { print $3 }' /proc/mounts;"
        " echo gone > /tmp/marker; echo kept > /var/tmp/marker;"
        " printf '#!/bin/sh\\necho ran\\n' > /tmp/run.sh && chmod +x /tmp/run.sh && /tmp/run.sh"
    )
    assert sh(env, scratch, script) == "tmpfs\nran\n"
    assert "Stopped:" in ok(env, scratch, "stop").out
    # Only the workspace's mount point remains (the scratch repo lives under /tmp/asb-it-*).
    out = sh(env, scratch, "ls -A /tmp; stat -c %a /tmp; cat /var/tmp/marker")
    assert out == f"{env.base.name}\n1777\nkept\n"  # /var/tmp keeps its contents


def test_proxy_is_unprivileged_without_host_mounts(env: Env, workspace: Path) -> None:
    name = f"agent-sandbox-{make_id(workspace)}-proxy"
    info = engine(
        "inspect",
        "--format",
        "{{json .Mounts}} {{.State.Pid}} {{json .HostConfig.CapAdd}}",
        name,
        check=True,
    ).stdout.split()
    mounts, pid, cap_add = info
    assert mounts == "[]" and cap_add in ("[]", "null")
    inside = engine("exec", name, "sh", "-c", "id -u; ls -ld /var/lib/asb").stdout.split("\n")
    assert inside[0] == "65534" and inside[1].startswith("drwx------")
    tinyproxy = engine("exec", name, "pidof", "asb-tinyproxy").stdout.split()
    assert tinyproxy
    host_uids = {Path(f"/proc/{pid}").stat().st_uid}
    host_uids |= {
        int(line.split()[1])
        for line in Path(f"/proc/{pid}/status").read_text().splitlines()
        if line.startswith("Uid:")
    }
    assert os.getuid() not in host_uids and 0 not in host_uids, host_uids
    # The upstream configuration never lands in the host runtime directory.
    assert not list(env.runtime(workspace).glob("*.conf"))


def test_status_and_doctor(env: Env, workspace: Path) -> None:
    status = ok(env, workspace, "status").out
    assert "approved" in status and "matches the configuration" in status
    assert "network:    base tier" in status
    doctor = ok(env, workspace, "doctor").out
    assert "FAIL" not in doctor and "No problems found." in doctor


def test_repair_restores_acls(env: Env, workspace: Path) -> None:
    target = workspace / "acl-target"
    target.write_text("x")
    sh(env, workspace, "echo y >> acl-target")
    subprocess.run(["setfacl", "-b", str(target)], check=True)
    target.chmod(0o644)
    refused = sh(env, workspace, "echo z >> acl-target 2>/dev/null || echo refused")
    assert refused == "refused\n"
    ok(env, workspace, "repair")
    assert sh(env, workspace, "echo z >> acl-target && echo ok") == "ok\n"
    target.unlink()


def test_file_replaced_in_the_sandbox_stays_writable_on_the_host(env: Env, workspace: Path) -> None:
    target = workspace / "replaced.txt"
    target.write_text("hello\n")
    # GNU sed -i writes a temp file, copies the old file's ACL onto it and renames it.
    sh(env, workspace, "sed -i s/hello/bye/ replaced.txt")
    assert target.read_text() == "bye\n"
    assert target.stat().st_uid != os.getuid()  # owned by the sandbox user's sub-uid now
    with target.open("a") as handle:
        handle.write("host\n")
    target.unlink()


def test_repair_reclaims_files_the_host_cannot_change(env: Env, workspace: Path) -> None:
    # A sandbox-owned file without the host user's ACL entry (as left by older versions or a
    # chmod), inside a directory the host cannot even read.
    sh(
        env,
        workspace,
        "mkdir -p reclaim/locked && echo x > reclaim/locked/f && echo y > reclaim/g && "
        "python3 -c \"import os; os.removexattr('reclaim/g', 'system.posix_acl_access')\" && "
        "chmod 644 reclaim/g && chmod 700 reclaim/locked",
    )
    base = workspace / "reclaim"
    assert not os.access(base / "g", os.W_OK)
    assert not os.access(base / "locked", os.R_OK)
    ok(env, workspace, "repair")
    for rel in ("g", "locked", "locked/f"):
        info = (base / rel).lstat()
        assert (info.st_uid, info.st_gid) == (os.getuid(), os.getgid()), rel
    (base / "g").write_text("host\n")
    (base / "locked" / "f").write_text("host\n")
    assert sh(env, workspace, "echo s >> reclaim/g && echo s >> reclaim/locked/f && echo ok") == (
        "ok\n"
    )
    shutil.rmtree(base)


def test_harness_fallback_and_root_banner(env: Env, workspace: Path) -> None:
    config = workspace / ".agent-sandbox" / "config.toml"
    original = config.read_text()
    config.write_text(original.replace(DEFAULT_HARNESS_LINE, 'harness = "no-such-harness --x"'))
    try:
        approve(env, workspace)
        result = ok(env, workspace, stdin="echo shell-$((1+1))\n")
        assert "No harness was found in the container (tried 'no-such-harness')" in result.err
        assert "shell-2" in result.out
    finally:
        config.write_text(original)
        approve(env, workspace)
    result = ok(env, workspace, "root", stdin="id -u\n")
    assert "ROOT SHELL" in result.err and "Rootless engine" in result.err
    assert result.out.strip() == "0"


def test_harness_in_local_bin_is_found(env: Env, workspace: Path) -> None:
    sh(
        env,
        workspace,
        'mkdir -p ~/.local/bin && printf "#!/bin/sh\\necho local-harness\\n" > ~/.local/bin/lh'
        " && chmod +x ~/.local/bin/lh",
    )
    config = workspace / ".agent-sandbox" / "config.toml"
    original = config.read_text()
    config.write_text(original.replace(DEFAULT_HARNESS_LINE, 'harness = "lh"'))
    try:
        approve(env, workspace)
        result = ok(env, workspace)
        assert "No harness was found" not in result.err
        assert "local-harness" in result.out
    finally:
        config.write_text(original)
        approve(env, workspace)
        sh(env, workspace, "rm -f ~/.local/bin/lh")


# --- network tiers ----------------------------------------------------------------------


def test_base_tier_allows_only_the_base_list(env: Env, workspace: Path) -> None:
    statuses = probe(
        env, workspace, "api.anthropic.com:443", "example.com:443", "example.com:80", "10.1.2.3:443"
    )
    assert statuses == {
        "api.anthropic.com:443": "200",
        "example.com:443": "403",
        "example.com:80": "403",
        "10.1.2.3:443": "403",
    }
    direct = sh(
        env,
        workspace,
        "timeout 5 bash -c 'exec 3<>/dev/tcp/1.1.1.1/443' 2>/dev/null && echo open || echo closed",
    )
    assert direct == "closed\n"


def test_net_session_opens_and_expires(env: Env, workspace: Path) -> None:
    proc = subprocess.Popen(
        [LAUNCHER, "net", "12s", "--allow", "example.com"],
        cwd=workspace,
        env=env.vars,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    try:
        wait_for(lambda: proxy_state(env, workspace) == "net", 15, "net tier")
        statuses = probe(
            env,
            workspace,
            "example.com:443",
            "pypi.org:443",
            "example.com:80",
            "http://example.net/",
        )
        assert statuses == {
            "example.com:443": "200",
            "pypi.org:443": "403",
            "example.com:80": "403",
            "http://example.net/": "403",
        }
        assert ok(env, workspace, "status").out.count("net tier") == 1
        output, _ = proc.communicate(timeout=30)
    finally:
        proc.kill()
    assert proc.returncode == 0, output
    assert "blocked: pypi.org" in output and "blocked: example.net" in output
    assert "Network session expired." in output
    assert re.search(r"\n\s+1\s+pypi\.org", output), output
    assert proxy_state(env, workspace) == "base"
    assert probe(env, workspace, "example.com:443") == {"example.com:443": "403"}


def test_net_refuses_second_session_extends_and_stops(env: Env, workspace: Path) -> None:
    proc = subprocess.Popen(
        [LAUNCHER, "net", "60"],
        cwd=workspace,
        env=env.vars,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    try:
        wait_for(lambda: proxy_state(env, workspace) == "net", 15, "net tier")
        second = asb(env, workspace, "net", "30")
        assert second.code == 1 and "already active" in second.err
        deadline = float((env.runtime(workspace) / "deadline").read_text())
        extended = ok(env, workspace, "net", "1m", "--extend", "--allow", "example.org")
        assert "Extended" in extended.err
        assert float((env.runtime(workspace) / "deadline").read_text()) == deadline + 60
        assert probe(env, workspace, "example.org:443") == {"example.org:443": "200"}
        ok(env, workspace, "net", "--stop")
        output, _ = proc.communicate(timeout=15)
    finally:
        proc.kill()
    assert "back on the base allowlist" in output
    assert proxy_state(env, workspace) == "base"
    assert probe(env, workspace, "example.org:443") == {"example.org:443": "403"}


def test_killed_net_session_still_ends_on_time(env: Env, workspace: Path) -> None:
    proc = subprocess.Popen(
        [LAUNCHER, "net", "6", "--allow", "example.com"],
        cwd=workspace,
        env=env.vars,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    wait_for(lambda: proxy_state(env, workspace) == "net", 15, "net tier")
    proc.send_signal(signal.SIGKILL)
    proc.wait()
    assert proxy_state(env, workspace) == "net"
    wait_for(lambda: proxy_state(env, workspace) == "base", 12, "deadline to pass")
    assert probe(env, workspace, "example.com:443") == {"example.com:443": "403"}
    # The stale session does not block the next one.
    run = ok(env, workspace, "net", "2")
    assert "expired" in run.err


def test_allow_all_keeps_internal_closed_and_offers_promotion(env: Env, workspace: Path) -> None:
    run = PtyRun(
        env,
        workspace,
        ("net", "40", "--allow-all"),
        answer((r"Allow ALL hosts", "y"), (r"Add them to .*\[y/N/s", "n")),
    ).start()
    try:
        wait_for(lambda: proxy_state(env, workspace) == "net", 20, "net tier")
        statuses = probe(
            env,
            workspace,
            "example.com:443",
            "api.anthropic.com:443",
            "10.1.2.3:443",
            "127.0.0.1:443",
            "localhost:443",
            "169.254.169.254:443",
        )
        assert statuses["example.com:443"] == "200"
        assert statuses["api.anthropic.com:443"] == "200"
        for internal in ("10.1.2.3:443", "127.0.0.1:443", "localhost:443", "169.254.169.254:443"):
            assert statuses[internal] == "502", (internal, statuses)
        wait_for(lambda: "blocked (internal): 10.1.2.3" in run.output, 10, "live log line")
        ok(env, workspace, "net", "--stop")
    finally:
        run.wait(60)
    assert run.code == 0, run.output
    assert "WARNING: --allow-all" in run.output
    assert "outside allowlists: example.com" in run.output
    tail = run.output.split("Hosts accessed outside your allowlists:")[1]
    assert "example.com" in tail and "10.1.2.3" not in tail and "api.anthropic.com" not in tail
    assert "example.com" not in (workspace / ".agent-sandbox" / "allow.extra").read_text()
    assert probe(env, workspace, "example.com:443") == {"example.com:443": "403"}


def test_promotion_appends_to_allow_extra(env: Env, workspace: Path) -> None:
    extra = workspace / ".agent-sandbox" / "allow.extra"
    original = extra.read_text()
    run = PtyRun(env, workspace, ("net", "15"), answer((r"\[y/N/s", "y"))).start()
    try:
        wait_for(lambda: proxy_state(env, workspace) == "net", 20, "net tier")
        assert probe(env, workspace, "example.net:443") == {"example.net:443": "403"}
        ok(env, workspace, "net", "--stop")
        run.wait(60)
        assert "example.net" in extra.read_text()
        assert "approved" in ok(env, workspace, "status").out
        assert "NOT approved" not in ok(env, workspace, "status").out
    finally:
        extra.write_text(original)
        approve(env, workspace)


# --- approval, drift, sockets -----------------------------------------------------------


def test_changed_config_needs_approval(env: Env, workspace: Path) -> None:
    extra = workspace / ".agent-sandbox" / "allow.extra"
    original = extra.read_text()
    extra.write_text(original + "evil.example\n")
    try:
        refused = asb(env, workspace, "exec", "--", "true")
        assert refused.code == 1
        assert "+evil.example" in refused.err and "Not approved" in refused.err
        run = PtyRun(env, workspace, ("exec", "--", "true"), answer((r"Approve", "n"))).start()
        assert run.wait().code == 1 and "not approved" in run.output
    finally:
        extra.write_text(original)
    ok(env, workspace, "exec", "--", "true")


def test_drift_requires_recreate(env: Env, scratch: Path) -> None:
    ok(env, scratch, "exec", "--", "true")
    env.user_config.write_text(f'[workspaces."{scratch}"]\ngit = "rw"\n')
    try:
        drift = asb(env, scratch, "exec", "--", "true")
        assert drift.code == 1 and "changed: git, mounts" in drift.err
        assert "DIFFERS" in ok(env, scratch, "status").out
        ok(env, scratch, "recreate")
        assert sh(env, scratch, "touch .git/rw-test && echo rw") == "rw\n"
    finally:
        env.user_config.unlink()
        (scratch / ".git" / "rw-test").unlink(missing_ok=True)
    assert asb(env, scratch, "exec", "--", "true").code == 1
    ok(env, scratch, "recreate")


def test_sockets_in_workspace_block_creation(env: Env, scratch: Path) -> None:
    sock = socket.socket(socket.AF_UNIX)
    sock.bind(str(scratch / "agent.sock"))
    try:
        refused = asb(env, scratch, "exec", "--", "true")
        assert refused.code == 1 and "agent.sock" in refused.err
        assert engine("inspect", f"agent-sandbox-{make_id(scratch)}").returncode != 0
        unsafe = ("exec", "--unsafely-mount-dirs-with-sockets", "--", "true")
        prompt = r"Type \"I understand"
        wrong = PtyRun(env, scratch, unsafe, answer((prompt, "yes"))).start().wait()
        assert wrong.code == 1 and "Not confirmed" in wrong.output
        phrase = "I understand the risks"
        right = PtyRun(env, scratch, unsafe, answer((prompt, phrase))).start().wait()
        assert right.code == 0, right.output
    finally:
        sock.close()


# --- other layouts and flows ------------------------------------------------------------


def test_derived_image_on_alpine(env: Env, scratch: Path) -> None:
    alpine = proxy_image_tag(DEFAULT_PROXY_BASE_IMAGE)  # built by the sandbox fixture
    if not has_image(alpine):
        pytest.skip("local tinyproxy image missing")
    tag = derived_tag(os.environ.get("USER", "user"), alpine)
    existed = has_image(tag)
    configure(scratch, env, image=alpine)
    try:
        out = sh(
            env,
            scratch,
            'id -un; echo "$HOME"; stat -c %u "$HOME"; '
            "awk -F: -v u=$(id -u) '$3==u {print $7}' /etc/passwd",
        )
        name, home, owner, shell = out.split()
        assert name == os.environ.get("USER") and home == f"/home/{name}"
        assert owner == str(os.getuid()) and shell == "/bin/sh"
        labels = engine("image", "inspect", "--format", "{{json .Config.Labels}}", tag).stdout
        assert engine("image", "inspect", "--format", "{{.Id}}", alpine).stdout.strip() in labels
    finally:
        asb(env, scratch, "rm", "--state")
        if not existed:
            engine("image", "rm", tag)


def test_linked_worktree_with_shared_state_volume(env: Env, workspace: Path) -> None:
    tree = env.base / "tree"
    git(workspace, "worktree", "add", "-q", str(tree))
    tree = tree.resolve()
    shared = "asb-it-shared"
    volume = f"agent-sandbox-state-shared-{shared}-claude"
    shared_volumes = [
        f"agent-sandbox-state-shared-{shared}-{suffix}"
        for suffix in ("claude", "copilot", "cache-pre-commit")
    ]
    env.user_config.write_text(f'[workspaces."{tree}"]\nstate_volume = "{shared}"\n')
    try:
        configure(tree, env)
        common = workspace / ".git"
        script = (
            "git log --oneline | wc -l;"
            f" touch {common}/x 2>/dev/null || echo common-ro; ls -d {common}/worktrees"
        )
        out = sh(env, tree, script)
        assert out.split("\n")[:3] == ["1", "common-ro", f"{common}/worktrees"]
        removed = ok(env, tree, "rm", "--state")
        assert "Kept shared state volume" in removed.err
        assert engine("volume", "inspect", volume).returncode == 0
    finally:
        asb(env, tree, "rm", "--state")
        engine("volume", "rm", *shared_volumes)
        env.user_config.unlink(missing_ok=True)
        git(workspace, "worktree", "remove", "--force", str(tree))


def test_clone_flow(env: Env, workspace: Path) -> None:
    outside = env.base / "clones"
    outside.mkdir(exist_ok=True)
    # A clone that already carries .agent-sandbox/ must be approved first.
    source = make_repo(env.base / "configured-src")
    configure(source, env)
    git(source, "add", ".agent-sandbox")
    git(source, "commit", "-q", "-m", "sandbox config")
    cloned = asb(env, outside, f"file://{source}/.git")
    assert cloned.code == 1 and "Not approved" in cloned.err, cloned.text
    assert (outside / "configured-src" / "README").exists()
    # A plain repository is initialised with --image.
    bare = make_repo(env.base / "plain-src")
    target = outside / "fresh"
    try:
        result = ok(env, outside, "--image", IMAGE, str(bare), str(target), stdin="pwd\n")
        assert "Created .agent-sandbox/" in result.err
        assert result.out.strip() == str(target.resolve())
    finally:
        asb(env, target, "rm", "--state")


def test_ls_rm_name_and_prune(env: Env, scratch: Path) -> None:
    ok(env, scratch, "exec", "--", "true")
    sandbox_id = make_id(scratch)
    listing = ok(env, scratch, "ls").out
    assert re.search(rf"{sandbox_id}\s+running", listing)
    ok(env, scratch, "rm")
    assert re.search(rf"{sandbox_id}\s+state only", ok(env, scratch, "ls").out)
    ok(env, scratch, "exec", "--", "true")
    removed = ok(env, env.base, "rm", sandbox_id)
    assert "container" in removed.out and "volume" not in removed.out

    ok(env, scratch, "exec", "--", "true")
    shutil.rmtree(scratch)
    assert "orphaned: the workspace directory no longer exists" in ok(env, env.base, "ls").out

    def respond(text: str) -> str | None:
        match = re.search(r"Remove sandbox (\S+)\? \[y/N\]", text)
        if match:
            return "y" if match.group(1) == sandbox_id else "n"
        return None

    run = PtyRun(env, env.base, ("prune",), respond).start().wait()
    assert run.code == 0, run.output
    assert f"removed volume agent-sandbox-state-{sandbox_id}-claude" in run.output
    removed_by_id(sandbox_id)


# --- environment setup ------------------------------------------------------------------


def append_config(root: Path, text: str) -> None:
    with (root / ".agent-sandbox" / "config.toml").open("a") as handle:
        handle.write("\n" + text)


USER = getpass.getuser()  # the name the CLI uses in image tags


def remove_images(prefix: str) -> None:
    listing = engine("images", "--format", "{{.Repository}}:{{.Tag}}").stdout.split()
    for ref in listing:
        if ref.startswith(prefix):
            engine("image", "rm", "-f", ref)


def test_setup_runs_before_the_harness_with_allow_extra(env: Env, scratch: Path) -> None:
    (scratch / ".agent-sandbox" / "allow.extra").write_text("example.com\n")
    append_config(
        scratch,
        "[setup]\ncreate = [\n"
        '  "echo run >> setup-ran",\n'
        "  \"curl -sS -o /dev/null -w '%{http_code}' https://example.com > setup-net\",\n"
        '  "curl -s -o /dev/null https://pypi.org || true",\n'
        ']\nstart = ["echo s >> started"]\n',
    )
    approve(env, scratch)
    first = ok(env, scratch)
    assert (scratch / "setup-ran").read_text() == "run\n"
    assert (scratch / "setup-net").read_text() == "200"
    assert "agent-sandbox: blocked: pypi.org" in first.err
    assert re.search(r"\n\s+1\s+pypi\.org", first.err), first.err
    assert proxy_state(env, scratch) == "base"
    assert probe(env, scratch, "example.com:443") == {"example.com:443": "403"}
    ok(env, scratch)
    assert (scratch / "setup-ran").read_text() == "run\n"  # once per container
    assert (scratch / "started").read_text() == "s\n"  # once per start
    ok(env, scratch, "stop")
    ok(env, scratch)
    assert (scratch / "started").read_text() == "s\ns\n"
    ok(env, scratch, "setup")
    assert (scratch / "setup-ran").read_text() == "run\nrun\n"
    assert "setup:      done" in ok(env, scratch, "status").out
    ok(env, scratch, "recreate")
    assert "pending" in ok(env, scratch, "status").out
    ok(env, scratch)
    assert (scratch / "setup-ran").read_text() == "run\nrun\nrun\n"


def test_what_rc_files_set_up_reaches_setup_and_execs(env: Env, scratch: Path) -> None:
    append_config(
        scratch,
        "[setup]\ncreate = [\n"
        "  \"mkdir -p ~/rc-bin && printf '#!/bin/sh\\\\necho from-rc\\\\n' > ~/rc-bin/rc-tool\",\n"
        '  "chmod +x ~/rc-bin/rc-tool",\n'
        "  \"echo 'export PATH=$PATH:$HOME/rc-bin RC_VAR=1' >> ~/.bashrc\",\n"
        '  "rc-tool > rc-ran",\n'  # the step after the rc change already sees it
        "]\n",
    )
    approve(env, scratch)
    ok(env, scratch)
    assert (scratch / "rc-ran").read_text() == "from-rc\n"
    out = sh(env, scratch, 'rc-tool; echo "$RC_VAR"; echo "$PATH"')
    tool, var, path = out.splitlines()
    assert (tool, var) == ("from-rc", "1")
    # /etc/profile resets PATH; what the image had is put back, ~/.local/bin stays in front
    assert path.startswith(f"{sh(env, scratch, 'echo $HOME').strip()}/.local/bin:"), path
    assert "/usr/local/bin" in path.split(":") and path.endswith("/rc-bin"), path


def test_failed_setup_keeps_the_harness_from_starting(env: Env, scratch: Path) -> None:
    append_config(scratch, '[setup]\ncreate = ["test -f allow-setup"]\n')
    approve(env, scratch)
    failed = asb(env, scratch)
    assert failed.code == 1 and "Setup did not finish" in failed.err, failed.text
    assert "failed with exit code 1: create from config.toml: test -f allow-setup" in failed.err
    ok(env, scratch, "exec", "--", "true")  # exec still works
    (scratch / "allow-setup").touch()
    ok(env, scratch, "setup")
    ok(env, scratch)


def test_dockerfile_layer_is_built_from_the_config_dir(env: Env, scratch: Path) -> None:
    cfg = scratch / ".agent-sandbox"
    (cfg / "hello.txt").write_text("hi\n")
    (cfg / "Dockerfile").write_text(
        "ARG base\nFROM $base\nARG user\nUSER root\n"
        'COPY hello.txt /etc/asb-hello\nRUN echo "$user" > /etc/asb-user\n'
    )
    try:
        approve(env, scratch)
        name = sh(env, scratch, "id -un").strip()
        assert sh(env, scratch, "cat /etc/asb-hello /etc/asb-user") == f"hi\n{name}\n"
        (cfg / "hello.txt").write_text("changed\n")
        refused = PtyRun(env, scratch, ("exec", "--", "true"), answer((r"Approve", "y")))
        result = refused.start().wait()
        assert result.code == 1 and "changed: dockerfile" in result.output, result.output
        ok(env, scratch, "recreate")
        assert sh(env, scratch, "cat /etc/asb-hello") == "changed\n"
    finally:
        asb(env, scratch, "rm", "--state")
        remove_images(f"localhost/agent-sandbox/{USER}-{make_id(scratch)}-extended:")


@pytest.mark.parametrize("remote", ["vscode", "newuser"])
def test_devcontainer_user_gets_the_host_uid(env: Env, remote: str) -> None:
    alpine = proxy_image_tag(DEFAULT_PROXY_BASE_IMAGE)
    if not has_image(alpine):
        pytest.skip("local tinyproxy image missing")
    base = "localhost/asb-it-remote-user:1"
    build = subprocess.run(
        [ENGINE, "build", "--tag", base, "-"],
        input=f"FROM {alpine}\nUSER root\nRUN adduser -D -u 4321 vscode && "
        "touch /home/vscode/marker\nUSER vscode\n",
        capture_output=True, text=True, check=False,
    )  # fmt: skip
    assert build.returncode == 0, build.stderr
    user = os.environ.get("USER", "user")
    tag = derived_tag(user, base)
    try:
        image = ensure_user_image(
            detect_engine(UserConfig(engine=ENGINE)), base, user=user, uid=os.getuid(),
            gid=os.getgid(), group=grp.getgrgid(os.getgid()).gr_name, remote_user=remote,
        )  # fmt: skip
        assert (image.name, image.home, image.ref) == (remote, f"/home/{remote}", tag)
        script = 'id -un; stat -c %u "$HOME"; ls -A "$HOME"'
        out = engine("run", "--rm", "--user", f"{os.getuid()}:{os.getgid()}", "--entrypoint",
                     "sh", tag, "-c", script).stdout.split()  # fmt: skip
        assert out[:2] == [remote, str(os.getuid())]
        assert ("marker" in out) == (remote == "vscode")  # the existing home was kept
    finally:
        engine("image", "rm", "-f", tag, base)


DEVCONTAINER_CLI = os.environ.get("ASB_TEST_DEVCONTAINER_CLI")
DEVCONTAINER_IMAGE = os.environ.get("ASB_TEST_DEVCONTAINER_IMAGE", "debian:bookworm-slim")


def test_devcontainer_flow(env: Env, scratch: Path) -> None:
    if not DEVCONTAINER_CLI:
        pytest.skip("set ASB_TEST_DEVCONTAINER_CLI to run the devcontainer test")
    if not has_image(DEVCONTAINER_IMAGE):
        pytest.skip(f"{DEVCONTAINER_IMAGE} is not present locally")
    cli = shlex.split(DEVCONTAINER_CLI)
    dc = scratch / ".devcontainer"
    (dc / "hello").mkdir(parents=True)
    (dc / "hello" / "devcontainer-feature.json").write_text(json.dumps({
        "id": "hello", "version": "1.0.0", "name": "hello", "containerEnv": {"HELLO": "1"},
        "postCreateCommand": "echo feature >> dc-created",
    }))  # fmt: skip
    (dc / "hello" / "install.sh").write_text(
        "#!/bin/sh\nset -e\necho hi > /usr/local/bin/hello-from-feature\n"
        # Like the pipx-based Features (e.g. poetry): PATH only in the bashrc, not in ENV.
        "mkdir -p /opt/hello/bin\n"
        "printf '#!/bin/sh\\necho from-rc\\n' > /opt/hello/bin/hello-rc\n"
        "chmod +x /opt/hello/bin/hello-rc\n"
        "echo 'export PATH=\"$PATH:/opt/hello/bin\"' >> /etc/bash.bashrc\n"
    )
    (dc / "devcontainer.json").write_text(json.dumps({
        "image": DEVCONTAINER_IMAGE, "remoteUser": "dev", "features": {"./hello": {}},
        "remoteEnv": {"FROM_DC": "${localWorkspaceFolderBasename}"},
        "postCreateCommand": "echo created >> dc-created && hello-rc >> dc-created",
        "postAttachCommand": "echo attach >> dc-attached",
        "runArgs": ["--privileged"],
    }))  # fmt: skip
    config = scratch / ".agent-sandbox" / "config.toml"
    text = re.sub(r"(?m)^image = .*\n", "", config.read_text())
    config.write_text(text.replace(DEFAULT_HARNESS_LINE, 'harness = "true"'))
    append_config(scratch, "[devcontainer]\nenabled = true\n")
    env.user_config.write_text(f"devcontainer_cli = {json.dumps(cli)}\n")
    try:
        first = PtyRun(env, scratch, (), answer((r"Approve", "y"))).start().wait(300)
        assert first.code == 1 and "has no lockfile" in first.output, first.output
        assert "upgrade --workspace-folder . --config .devcontainer/devcontainer.json" in (
            first.output.replace("\r\n", " ").replace("\n", " ").replace("  ", " ")
        )
        upgrade = [*cli, "upgrade", "--workspace-folder", ".", "--config",
                   ".devcontainer/devcontainer.json"]  # fmt: skip
        assert (
            subprocess.run(upgrade, cwd=scratch, capture_output=True, check=False).returncode == 0
        )
        second = PtyRun(env, scratch, (), answer((r"Approve", "y"))).start().wait(600)
        assert second.code == 0, second.output
        assert "runArgs is not applied" in second.output
        assert f"{DEVCONTAINER_IMAGE} is not pinned" in second.output
        assert (scratch / "dc-created").read_text() == "feature\ncreated\nfrom-rc\n"
        assert (scratch / "dc-attached").read_text() == "attach\n"
        out = sh(
            env,
            scratch,
            'id -un; echo "$HELLO $FROM_DC"; cat /usr/local/bin/hello-from-feature; hello-rc',
        )
        assert out == f"dev\n1 {scratch.name}\nhi\nfrom-rc\n"
        ok(env, scratch)
        assert (scratch / "dc-created").read_text() == "feature\ncreated\nfrom-rc\n"
        assert (scratch / "dc-attached").read_text() == "attach\nattach\n"
        touched = sh(env, scratch, "touch .devcontainer/x 2>/dev/null && echo writable || echo ro")
        assert touched == "ro\n"
    finally:
        env.user_config.unlink(missing_ok=True)
        asb(env, scratch, "rm", "--state")
        for layer in ("devcontainer", "user"):
            remove_images(f"localhost/agent-sandbox/{USER}-{make_id(scratch)}-{layer}:")


# --- secret files -----------------------------------------------------------------------


def test_secret_files_stay_out_of_the_sandbox(env: Env, scratch: Path) -> None:
    secret = scratch / ".env"
    secret.write_text("FAKE_CANARY=1\n")
    refused = asb(env, scratch, "exec", "--", "true")
    assert refused.code != 0 and "a real file in the workspace" in refused.text
    assert "FAKE_CANARY" not in refused.text
    assert engine("container", "inspect", f"agent-sandbox-{make_id(scratch)}").returncode != 0
    assert asb(env, scratch, "secrets", "check").code == 1

    assert ok(env, scratch, "secrets", "adopt").code == 0
    assert secret.is_symlink() and secret.read_text() == "FAKE_CANARY=1\n"
    assert str(secret.resolve()).startswith(str(env.base / "config" / "secrets"))

    # A dangling link inside, and nothing to find anywhere the sandbox can read.
    assert sh(env, scratch, "test -L .env && ! test -e .env && echo ok").strip() == "ok"
    assert sh(env, scratch, "grep -rl FAKE_CANARY . ~ 2>/dev/null; true").strip() == ""

    # A real file that appears later stops every further start.
    secret.unlink()
    secret.write_text("FAKE_CANARY=2\n")
    refused = asb(env, scratch, "exec", "--", "true")
    assert refused.code != 0 and "sessions can read" in refused.text
    secret.unlink()
    secret.symlink_to(env.base / "elsewhere")
    assert "outside" in asb(env, scratch, "exec", "--", "true").text
    secret.unlink()
    assert ok(env, scratch, "exec", "--", "true").code == 0


def test_secret_rules_block_creation(env: Env, scratch: Path) -> None:
    (scratch / ".gitignore").write_text("")
    git(scratch, "add", ".gitignore")
    git(scratch, "commit", "-q", "-m", "no rules")
    assert "rule for .env" in asb(env, scratch, "exec", "--", "true").text
    (scratch / ".git" / "info" / "exclude").write_text(".env\n.env.*\n*.env\n")
    assert "which clones do not get" in asb(env, scratch, "exec", "--", "true").text
    (scratch / ".git" / "info" / "exclude").write_text("")
    (scratch / ".gitignore").write_text(".env\n.env.*\n*.env\n")
    git(scratch, "add", ".gitignore")
    git(scratch, "commit", "-q", "-m", "rules")
    tracked = scratch / "tracked.env"
    tracked.write_text("FAKE=1\n")
    git(scratch, "add", "-f", "tracked.env")
    git(scratch, "commit", "-q", "-m", "oops")
    assert "tracked by git" in asb(env, scratch, "exec", "--", "true").text
    git(scratch, "rm", "-q", "--cached", "tracked.env")
    git(scratch, "commit", "-q", "-m", "remove")
    tracked.unlink()
    assert ok(env, scratch, "exec", "--", "true").code == 0  # the history check is off


def test_secret_history_check_is_opt_in_and_bounded(env: Env, scratch: Path) -> None:
    tracked = scratch / "old.env"
    tracked.write_text("FAKE=1\n")
    git(scratch, "add", "-f", "old.env")
    git(scratch, "commit", "-q", "-m", "oops")
    git(scratch, "rm", "-q", "--cached", "old.env")
    git(scratch, "commit", "-q", "-m", "remove")
    tracked.unlink()
    git(scratch, "commit", "-q", "--allow-empty", "-m", "newer")
    config = scratch / ".agent-sandbox" / "config.toml"
    text = config.read_text()
    config.write_text(text.replace("[workspace]\n", "[workspace]\nsecrets_history_depth = 1\n", 1))
    approve(env, scratch)  # beyond the depth: not found, and this creates the sandbox
    ok(env, scratch, "rm")
    config.write_text(text.replace("[workspace]\n", "[workspace]\nsecrets_history_depth = 3\n", 1))
    run = PtyRun(env, scratch, ("exec", "--", "true"), answer((r"Approve this", "y"))).start()
    assert run.wait().code != 0 and "secrets rotated old.env" in run.output
    ok(env, scratch, "secrets", "rotated", "old.env")
    assert ok(env, scratch, "exec", "--", "true").code == 0
