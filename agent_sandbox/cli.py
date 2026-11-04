"""Command line interface."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from . import manage
from .config import CONFIG_FILE, PROJECT_DIR, load_user_config
from .engine import Engine, detect_engine
from .images import ensure_proxy_image, ensure_user_image
from .net import run_net, stop_net
from .project import NotARepositoryError, Project, find_project, git_toplevel
from .sandbox import (
    build_context,
    ensure_ready,
    project_lock,
    remove_by_id,
    run_in_container,
    stop_sandbox,
)
from .util import SandboxError, eprint, parse_duration

UNSAFE_FLAG = "--unsafely-mount-dirs-with-sockets"
COMMANDS = (
    "init", "exec", "root", "net", "stop", "rm", "recreate", "rebuild", "ls", "prune",
    "status", "doctor", "repair",
)  # fmt: skip

OVERVIEW = f"""\
agent-sandbox - per-workspace sandboxes for AI agent harnesses

A sandbox is a container holding one git working tree. The workspace is bind-mounted
read-write at its host path; `.git`, `{PROJECT_DIR}/` and editor/agent configuration (.claude,
.vscode, ...) are read-only inside, so commits, hooks and configuration stay under your control
on the host. Virtualenvs and node_modules are separate volumes the host never runs. The
container sits on an internal network with no route out; its only way out is a tinyproxy
container that allows a short list of hosts.

USAGE
  agent-sandbox                     Create the sandbox if needed, start it, run the harness.
                                    Run it at the root of a git repository.
  agent-sandbox [--image IMAGE] URL [DIR]
                                    Outside a repository: clone URL, then do the same. With
                                    --image, a repository without {PROJECT_DIR}/ is initialised.

COMMANDS
  init --image IMAGE [--force]      Create {PROJECT_DIR}/ (config, allowlists, proxy settings).
  exec [--] COMMAND...              Run a command in the sandbox (e.g. a second harness).
  root                              Root shell, for installing packages. Not for harnesses.
  net DURATION [--allow HOST]... [--allow-all] [--extend]
  net --stop                        Open the network for a limited time (see `help network`).
  stop                              Stop the sandbox and its proxy.
  rm [NAME] [--state]               Remove containers and network (workspace files are never
                                    touched). --state also deletes the harness state and
                                    isolated volumes.
  recreate                          Remove and create the containers again (keeps state).
  rebuild [--pull]                  Rebuild the derived workspace image and the proxy image.
  ls                                List sandboxes of all engines; orphaned ones are flagged.
  prune [--keep-state]              Remove orphaned sandboxes, asking about each one.
  status                            Show state, approval and configuration drift.
  doctor                            Check isolation of a running sandbox.
  repair                            Reclaim sandbox-owned files, re-apply access.
  help [config|network|security|COMMAND]

OPTIONS
  {UNSAFE_FLAG}
                                    Allow mounting directories that contain unix sockets
                                    (asks you to type a confirmation phrase).

More: `agent-sandbox help config`, `help network`, `help security`.
"""

HELP_CONFIG = f"""\
CONFIGURATION

Project: {PROJECT_DIR}/ at the repository root. Commit it. It is mounted read-only into the
sandbox, and the host asks you to approve it (showing a diff) whenever it differs from what you
approved last, including after a clone or pull.

  {CONFIG_FILE}      image, harness, environment, workspace paths, extra mounts, state
  tinyproxy.conf   static tinyproxy settings (Timeout, ConnectPort, ...); agent-sandbox
                   generates the rest and rejects those directives here
  allow.base       hosts reachable whenever the sandbox runs (model APIs, login)
  allow.extra      hosts reachable only during `agent-sandbox net`

{CONFIG_FILE} keys
  image            base image; a derived image with your user (same uid, gid, name) is built
                   automatically when the base lacks that uid
  harness          command line started by a plain `agent-sandbox`
  [env] pass       host variables to pass into the container (when set)
  [env.set]        fixed variables; {{home}} expands to the container home directory
  [workspace] protected
                   workspace paths mounted read-only (default: .claude .agents .vscode
                   .idea .devcontainer); missing ones are created empty
  [workspace] isolated
                   workspace paths replaced by a per-workspace volume, so the sandbox keeps
                   its own copy (default: .venv node_modules)
  [[mounts]]       extra read-only bind mounts: source, target (default: source); `~` is
                   your home in source and the container home in target
  [state] paths    directories under the container home kept in a volume
                   (per workspace by default; default: .claude .copilot .cache/pre-commit)
  [proxy] base_image   image tinyproxy is installed on (default: alpine:3)

Allowlist syntax (allow.base, allow.extra, --allow)
  example.com      exactly that host
  .example.com     that host and all subdomains
  no wildcards, no ports; `#` starts a comment

User-level configuration: ~/.config/agent-sandbox/config.toml (never in the repository)
  engine = "auto" | "docker" | "podman"      docker_context = "..."
  allow_rootful = false                      rootful engines need an explicit opt-in
  git = "ro" | "rw"                          writable .git is a host-side risk, so it can only
                                             be set here
  state_volume = "per-workspace" | "NAME"    "NAME" shares harness logins between workspaces
  [workspaces."/abs/path"]                   per-workspace overrides of git and state_volume
  [proxy] base_image = "..."

Environment overrides: AGENT_SANDBOX_CONFIG_DIR, AGENT_SANDBOX_STATE_DIR,
AGENT_SANDBOX_RUNTIME_DIR, AGENT_SANDBOX_ALLOW_ROOTFUL=1.
"""

HELP_NETWORK = """\
NETWORK

The workspace container is attached only to an internal network, so it cannot reach anything
directly. HTTP_PROXY/HTTPS_PROXY point at a tinyproxy container ("proxy") that is also on the
default network. The proxy runs whenever the sandbox runs and enforces two tiers:

  base   allow.base only (model APIs and login)
  net    allow.base + allow.extra + --allow hosts, for a limited time

  agent-sandbox net 15m                   open the extra tier for 15 minutes
  agent-sandbox net 2h --allow pypi.org   ... plus a host that is not in a file
  agent-sandbox net 30m --allow-all       any host (asks for confirmation; see below)
  agent-sandbox net 10m --extend          add time to the running session
  agent-sandbox net --stop                end the session now

DURATION is seconds, or a number with an m or h suffix (90, 15m, 2h, 1h30m). The command
shows a countdown, so run it in a second terminal. The proxy returns to the base tier when the
time is up, when the command is interrupted, or when it is killed (the proxy container enforces
the deadline itself). Connections that are already open finish normally.

While a session runs, hosts that were blocked (or, with --allow-all, accessed outside your
allowlists) are listed live. Afterwards you can add them to allow.extra.

--allow-all keeps the internal network closed as far as tinyproxy can tell: hosts in your
NO_PROXY and private/loopback/link-local IP literals are blocked unless an allowlist names
them. Internal *names* are only recognised through NO_PROXY.

Host proxy: if HTTP_PROXY/HTTPS_PROXY/NO_PROXY are set where you run agent-sandbox, tinyproxy
forwards through that proxy and sends NO_PROXY hosts directly (lowercase variables win; an
https:// proxy URL is not supported; ports and IPv6 in NO_PROXY are ignored with a warning).
"""

HELP_SECURITY = """\
SECURITY NOTES

- The container is the boundary: default seccomp/AppArmor, no-new-privileges, no sudo, a
  non-root user. Only the workspace, harness state volumes and your extra mounts are shared.
- The proxy container runs as `nobody` with no capabilities and no host mounts; its
  configuration is copied in, so a compromised proxy owns nothing on the host.
- `agent-sandbox root` is for setup. In a rootless engine root is your own host user on every
  mount; in a rootful engine it can create root-owned and setuid files in the workspace.
  Do not start a harness from a root shell; that cannot be prevented, only discouraged.
- Review agent changes on the host: `.git` and the protected paths are read-only in the
  container, but files the agent wrote (scripts, Makefiles, .envrc) are yours to inspect
  before you run them. Gitignored files do not show up in `git diff`; that is why
  .claude/settings.local.json is protected and virtualenvs are isolated, not shared.
- The sandbox cannot protect you from code you run yourself. Tests run on the host by
  pre-commit, build scripts, CI jobs (with their tokens and deploy keys): anything the agent wrote
  runs with full rights there and could exfiltrate secrets. Review before running.
- Network access is closed by default because agents, like people, can be manipulated (prompt
  injection). The design limits what a manipulated agent can reach instead of trusting it.
- Rootless docker maps the container user to a sub-uid, so the workspace is shared with ACLs
  (setfacl) naming both you and the sandbox user. Podman uses --userns=keep-id. Rootful engines
  need `allow_rootful = true`. If you cannot write a file the sandbox created or changed, run
  `agent-sandbox repair`: it gives sandbox-owned files back to you and re-applies the ACLs.
- Directories you mount may not contain unix sockets: a read-only mount still lets the
  sandbox connect to them. Override with the long flag only if you know what they are.
"""


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="agent-sandbox", description="Per-workspace sandboxes for AI agent harnesses."
    )
    sub = parser.add_subparsers(dest="command", required=True)

    def add(name: str, help_text: str, *, unsafe: bool = False) -> argparse.ArgumentParser:
        p = sub.add_parser(name, help=help_text, description=help_text)
        if unsafe:
            p.add_argument(
                UNSAFE_FLAG, dest="unsafe", action="store_true", help="see `help security`"
            )
        return p

    p = add("init", "Create the .agent-sandbox/ configuration directory.")
    p.add_argument("--image", required=True, help="base image for the workspace container")
    p.add_argument("--force", action="store_true", help="overwrite existing files")

    p = add("exec", "Run a command in the sandbox.", unsafe=True)
    p.add_argument("cmd", nargs=argparse.REMAINDER, help="command and arguments (after --)")

    add("root", "Open a root shell in the sandbox (setup only).", unsafe=True)

    p = add("net", "Open the network for a limited time.")
    p.add_argument("duration", nargs="?", help="seconds, or a number with an m or h suffix")
    p.add_argument(
        "--allow", action="append", default=[], metavar="HOST", help="extra allowed host"
    )
    p.add_argument("--allow-all", action="store_true", help="allow every host (asks to confirm)")
    p.add_argument("--extend", action="store_true", help="add time to the running session")
    p.add_argument("--stop", action="store_true", help="end the running session now")

    add("stop", "Stop the sandbox and its proxy.")
    p = add("rm", "Remove the sandbox containers and network.")
    p.add_argument("name", nargs="?", help="sandbox id from `ls` (default: this directory)")
    p.add_argument("--state", action="store_true", help="also delete harness state volumes")
    add("recreate", "Remove and create the containers again.", unsafe=True)
    p = add("rebuild", "Rebuild the derived workspace image and the proxy image.")
    p.add_argument("--pull", action="store_true", help="pull the base image first")
    add("ls", "List sandboxes.")
    p = add("prune", "Remove orphaned sandboxes (asks about each).")
    p.add_argument("--keep-state", action="store_true", help="keep their state volumes")
    add("status", "Show the state of this sandbox.")
    add("doctor", "Check the isolation of the running sandbox.")
    add("repair", "Reclaim sandbox-owned files, re-apply file access and ownership.")
    return parser


def _engine_and_project() -> tuple[Engine, Project]:
    project = find_project(Path.cwd())
    return detect_engine(load_user_config()), project


def _default(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(prog="agent-sandbox", add_help=False)
    parser.add_argument("--image")
    parser.add_argument(UNSAFE_FLAG, dest="unsafe", action="store_true")
    parser.add_argument("url", nargs="?")
    parser.add_argument("dir", nargs="?")
    args = parser.parse_args(argv)

    cwd = Path.cwd()
    if git_toplevel(cwd) is None:
        if not args.url:
            raise NotARepositoryError(
                "Not inside a git repository.\n"
                "Clone one: agent-sandbox [--image IMAGE] URL [DIR]   (see `agent-sandbox help`)"
            )
        root = manage.clone_repository(args.url, args.dir)
        os.chdir(root)
        project = find_project(root)
        if not (root / PROJECT_DIR / CONFIG_FILE).exists():
            if not args.image:
                raise SandboxError(
                    f"Cloned into {root}, which has no {PROJECT_DIR}/.\n"
                    f"Run: cd {root} && agent-sandbox init --image IMAGE"
                )
            manage.init_project(project, args.image)
            eprint(f"Created {PROJECT_DIR}/ using image {args.image}.")
    else:
        if args.url or args.image:
            raise SandboxError(
                "URL, DIR and --image are only used outside a git repository "
                "(use `agent-sandbox init --image IMAGE` here)."
            )
        project = find_project(cwd)
    ctx = build_context(project)
    ensure_ready(ctx, unsafe_sockets=args.unsafe)
    run_in_container(ctx)
    return 0


def _cmd_net(args: argparse.Namespace) -> int:
    ctx = build_context(find_project(Path.cwd()))
    if args.stop:
        stop_net(ctx)
        return 0
    if not args.duration:
        raise SandboxError("net needs a duration (for example 15m) or --stop.")
    return run_net(
        ctx,
        duration=parse_duration(args.duration),
        allow=args.allow,
        allow_all=args.allow_all,
        extend=args.extend,
    )


def _cmd_rm(args: argparse.Namespace) -> int:
    if args.name:
        ws = manage.find_workspace(args.name, manage.list_workspaces())
        removed = manage.remove_workspace(ws, state=args.state)
    else:
        engine, project = _engine_and_project()
        with project_lock(project):
            removed = remove_by_id(engine, project.id, state=args.state)
    for item in removed:
        print(f"removed {item}")
    if not removed:
        print("Nothing to remove.")
    return 0


def _cmd_recreate(args: argparse.Namespace) -> int:
    ctx = build_context(find_project(Path.cwd()))
    with project_lock(ctx.project):
        for item in remove_by_id(ctx.engine, ctx.project.id, state=False):
            eprint(f"removed {item}")
    ensure_ready(ctx, unsafe_sockets=args.unsafe)
    eprint("Recreated. Run `agent-sandbox` to enter.")
    return 0


def _cmd_rebuild(args: argparse.Namespace) -> int:
    ctx = build_context(find_project(Path.cwd()))
    image = ensure_user_image(
        ctx.engine, ctx.config.image, user=ctx.username, uid=ctx.uid, gid=ctx.gid,
        group=ctx.groupname, rebuild=True, pull=args.pull,
    )  # fmt: skip
    ensure_proxy_image(ctx.engine, ctx.proxy_base_image, rebuild=True)
    kind = "derived image" if image.derived else "base image (no derived image needed)"
    eprint(
        f"Rebuilt. Workspace uses the {kind}: {image.ref}\nRun `agent-sandbox recreate` to apply."
    )
    return 0


def _dispatch(argv: list[str]) -> int:
    if argv and argv[0] in ("-h", "--help"):
        print(OVERVIEW)
        return 0
    if argv and argv[0] == "help":
        topic = argv[1] if len(argv) > 1 else ""
        texts = {
            "": OVERVIEW,
            "config": HELP_CONFIG,
            "network": HELP_NETWORK,
            "security": HELP_SECURITY,
        }
        if topic in texts:
            print(texts[topic])
            return 0
        if topic not in COMMANDS:
            raise SandboxError(f"No help topic {topic!r}. Try `agent-sandbox help`.")
        argv = [topic, "--help"]
    if os.getuid() == 0:
        raise SandboxError("Refusing to run as root: the sandbox user must not be root.")
    if not argv or argv[0] not in COMMANDS:
        return _default(argv)

    args = build_parser().parse_args(argv)
    cmd = args.command
    if cmd == "init":
        project = find_project(Path.cwd())
        written = manage.init_project(project, args.image, force=args.force)
        for path in written:
            print(f"wrote {path.relative_to(project.root)}")
        print("Review allow.base, then run `agent-sandbox`.")
        return 0
    if cmd in ("exec", "root"):
        ctx = build_context(find_project(Path.cwd()))
        ensure_ready(ctx, unsafe_sockets=args.unsafe)
        if cmd == "root":
            run_in_container(ctx, root=True)
        else:
            command = args.cmd[1:] if args.cmd and args.cmd[0] == "--" else args.cmd
            if not command:
                raise SandboxError("exec needs a command: agent-sandbox exec -- COMMAND...")
            run_in_container(ctx, command)
        return 0
    if cmd == "net":
        return _cmd_net(args)
    if cmd == "stop":
        engine, project = _engine_and_project()
        stopped = stop_sandbox(engine, project)
        print("Stopped: " + ", ".join(stopped) if stopped else "Nothing was running.")
        return 0
    if cmd == "rm":
        return _cmd_rm(args)
    if cmd == "recreate":
        return _cmd_recreate(args)
    if cmd == "rebuild":
        return _cmd_rebuild(args)
    if cmd == "ls":
        manage.print_workspaces(manage.list_workspaces())
        return 0
    if cmd == "prune":
        return manage.prune(keep_state=args.keep_state)
    ctx = build_context(find_project(Path.cwd()))
    if cmd == "status":
        manage.status(ctx)
        return 0
    if cmd == "doctor":
        return manage.doctor(ctx)
    if cmd == "repair":
        manage.repair(ctx)
        return 0
    raise SandboxError(f"Unknown command {cmd!r}.")


def main(argv: list[str] | None = None) -> int:
    try:
        return _dispatch(list(sys.argv[1:] if argv is None else argv))
    except SandboxError as exc:
        eprint(f"error: {exc}")
        return 1
    except KeyboardInterrupt:
        return 130
