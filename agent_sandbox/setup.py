"""The setup layer: commands that prepare a created container (`[setup]`, devcontainer hooks).

- create: once per container, before the first harness start. It is the only phase with the net
  tier (base + allow.extra), opened just for it: no harness runs in the container yet. Success
  is recorded on the host after every command succeeded; until then the harness does not start.
- start: once per container start, after the create phase, on the base tier; failures warn.
- attach: before each harness start, on the base tier; failures warn.

Every command is its own process (`sh -c` for a string), as with the devcontainers CLI; an
object runs its named commands in parallel.
"""

from __future__ import annotations

import contextlib
import fcntl
import hashlib
import json
import subprocess
import threading
from collections.abc import Generator
from dataclasses import dataclass
from pathlib import Path

from . import devcontainer, net
from .devcontainer import CREATE_HOOKS, Step
from .sandbox import (
    Context,
    Session,
    command_with_umask,
    exec_env,
    remote_env,
    session,
    substitution,
)
from .util import SandboxError, atomic_write, confirm, eprint, is_tty, runtime_dir, state_dir

CONFIG_ORIGIN = "config.toml"


@dataclass
class Plan:
    create: list[Step]
    start: list[Step]
    attach: list[Step]


def plan_for(ctx: Context, current: Session) -> Plan:
    """config.toml's commands first, then the devcontainer's (Features first, per hook)."""
    create = [Step(CONFIG_ORIGIN, "create", c) for c in ctx.config.setup_create]
    start = [Step(CONFIG_ORIGIN, "start", c) for c in ctx.config.setup_start]
    attach: list[Step] = []
    if ctx.config.devcontainer is not None:
        metadata = current.metadata
        for hook in CREATE_HOOKS:
            create += devcontainer.steps(metadata, hook)
        start += devcontainer.steps(metadata, "postStartCommand")
        attach += devcontainer.steps(metadata, "postAttachCommand")
    return Plan(create, start, attach)


def steps_hash(steps: list[Step]) -> str:
    data = json.dumps([[s.origin, s.hook, s.command] for s in steps], sort_keys=True)
    return hashlib.sha256(data.encode()).hexdigest()[:16]


# --- the record of what ran -------------------------------------------------------------


def _record_path(ctx: Context) -> Path:
    return state_dir() / "setup" / f"{ctx.project.id}.json"


def load_record(ctx: Context) -> dict[str, str]:
    try:
        data = json.loads(_record_path(ctx).read_text())
    except (FileNotFoundError, json.JSONDecodeError):
        return {}
    return {k: v for k, v in data.items() if isinstance(v, str)} if isinstance(data, dict) else {}


def save_record(ctx: Context, record: dict[str, str]) -> None:
    atomic_write(_record_path(ctx), json.dumps(record, sort_keys=True) + "\n", mode=0o600)


def forget(project_id: str) -> None:
    (state_dir() / "setup" / f"{project_id}.json").unlink(missing_ok=True)


def create_done(ctx: Context, current: Session, plan: Plan) -> bool:
    record = load_record(ctx)
    return record.get("container") == current.container_id and record.get("create") == steps_hash(
        plan.create
    )


@contextlib.contextmanager
def setup_lock(ctx: Context) -> Generator[None]:
    """One setup at a time per workspace (a second `agent-sandbox` waits, then sees the record)."""
    path = runtime_dir() / f"{ctx.project.id}.setup.lock"
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w") as handle:
        fcntl.flock(handle, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(handle, fcntl.LOCK_UN)


# --- running commands -------------------------------------------------------------------


def spawn(argv: list[str]) -> subprocess.Popen[str]:
    return subprocess.Popen(
        argv,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        errors="replace",
    )


def _argv(ctx: Context, env_args: list[str], command: str | list[str]) -> list[str]:
    words = ["sh", "-c", command] if isinstance(command, str) else list(command)
    return [
        *ctx.engine.base_cmd(), "exec", "--user", f"{ctx.uid}:{ctx.gid}",
        "--workdir", str(ctx.project.root), *env_args, ctx.project.workspace_container,
        *command_with_umask(words, ctx.umask),
    ]  # fmt: skip


def _pump(process: subprocess.Popen[str], prefix: str) -> None:
    assert process.stdout is not None
    for line in process.stdout:
        print(prefix + line, end="", flush=True)


def _describe(command: str | list[str]) -> str:
    text = command if isinstance(command, str) else " ".join(command)
    text = " ".join(text.split())
    return text if len(text) <= 70 else text[:67] + "..."


def run_step(ctx: Context, step: Step, env_args: list[str]) -> bool:
    """Run one command (an object: its commands in parallel, output prefixed by name)."""
    commands = step.command if isinstance(step.command, dict) else {"": step.command}
    processes: list[tuple[str, subprocess.Popen[str], threading.Thread]] = []
    for name, command in commands.items():
        label = f"{step.hook} from {step.origin}" + (f" ({name})" if name else "")
        label += f": {_describe(command)}"
        eprint(f"==> {label}")
        process = spawn(_argv(ctx, env_args, command))
        thread = threading.Thread(
            target=_pump, args=(process, f"[{name}] " if len(commands) > 1 else ""), daemon=True
        )
        thread.start()
        processes.append((label, process, thread))
    ok = True
    for label, process, thread in processes:
        code = process.wait()
        thread.join()
        if code != 0:
            eprint(f"==> failed with exit code {code}: {label}")
            ok = False
    return ok


def run_steps(ctx: Context, steps: list[Step], current: Session) -> bool:
    """Run in order, stopping at the first failure."""
    subst = substitution(ctx, current)
    env_args = exec_env(ctx, current.home, remote_env(ctx, current))
    for step in steps:
        command = step.command if step.origin == CONFIG_ORIGIN else subst.command(step.command)
        if not run_step(ctx, Step(step.origin, step.hook, command), env_args):
            return False
    return True


def run_create(ctx: Context, plan: Plan, current: Session) -> bool:
    eprint(
        f"==> Setting up the sandbox ({len(plan.create)} command(s); the hosts in allow.extra "
        "are reachable while it runs). This can take a while."
    )
    with net.setup_network(ctx) as observed:
        ok = run_steps(ctx, plan.create, current)
    if observed.candidates():
        net.offer_promotion(ctx, observed)
    return ok


# --- entry points -----------------------------------------------------------------------

FAILED = (
    "Setup did not finish, so the harness was not started. Fix the cause, then run "
    "`agent-sandbox setup` (or plain `agent-sandbox` again). `agent-sandbox exec` and `root` "
    "work meanwhile."
)


def ensure_setup(ctx: Context, *, force: bool = False) -> None:
    """Run what has not run for this container (everything when `force`); raise if create fails."""
    with setup_lock(ctx):
        current = session(ctx)
        plan = plan_for(ctx, current)
        if force or not create_done(ctx, current, plan):
            if plan.create:
                while not run_create(ctx, plan, current):
                    if not is_tty() or not confirm("Setup failed. Retry now?"):
                        raise SandboxError(FAILED)
            save_record(ctx, {"container": current.container_id, "create": steps_hash(plan.create)})
        record = load_record(ctx)
        started, start_hash = current.started_at, steps_hash(plan.start)
        if force or record.get("started") != started or record.get("start") != start_hash:
            if plan.start and not run_steps(ctx, plan.start, current):
                eprint("warning: a start command failed; continuing.")
            save_record(ctx, {**record, "started": started, "start": start_hash})


def before_harness(ctx: Context) -> None:
    """Setup as needed, then the attach commands (on the base tier; failures warn)."""
    ensure_setup(ctx)
    current = session(ctx)
    plan = plan_for(ctx, current)
    if plan.attach and not run_steps(ctx, plan.attach, current):
        eprint("warning: an attach command failed; starting the harness anyway.")
