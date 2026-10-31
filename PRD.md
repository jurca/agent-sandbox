# agent-sandbox - product requirements

Status: implemented and tested on rootless docker (see section 9); podman and rootful untested.
The previous bash-based version is tagged `v0.1.0`; this is a clean restart.

## 1. Purpose and threat model

Run AI agent harnesses (Claude Code, GitHub Copilot CLI, OpenCode later) against a git working
tree inside a per-workspace container, so that mistakes or prompt injection cannot damage the host.
The concern is accident and manipulation, not malice by the user.

Key properties:

- The **container is the security boundary**. No nested bubblewrap sandbox, no relaxed
  seccomp/AppArmor, no VS Code server attached (it forwards sockets that can take over the host).
  Harnesses are run from a terminal via `exec` (CLI harnesses: Claude Code, Copilot CLI, OpenCode).
- The workspace is **bind-mounted** (read-write) **at its host path**; review and commits happen on
  the host. `.git` and `.agent-sandbox/` are mounted **read-only** so git hooks, `.git/config`
  (fsmonitor, diff drivers...) and the toolkit configuration cannot be planted by the agent.
- Anything the agent writes that the host later **executes or trusts** is an escape route.
  Tracked files show up in `git diff`; gitignored ones do not. So configuration that host tools
  execute (`.claude/` hooks incl. the ignored `settings.local.json`, `.agents/`, `.vscode/`,
  `.idea/`) is **protected** (read-only), and dependency trees the host runs (`.venv`,
  `node_modules`) are **isolated**: the sandbox gets its own copy in a volume and never writes the
  host's.
- What remains is **inescapable by design**: the agent's job is to write code that you then run.
  Tests started on the host by pre-commit or by hand, build scripts, a `Makefile`, a dev server,
  CI jobs (which often hold deploy keys and tokens in their environment): any of it can do
  anything the user or the CI runner can, including exfiltrating secrets. The sandbox only makes
  sure the agent's code runs *outside* it after a human chose to run it, never on its own. Review
  agent changes before running them where secrets live.
- That is also why network access is closed by default. People are manipulated against their own
  interests every day; it would be unfair to expect an LLM agent to withstand every prompt
  injection. So the design does not rely on the agent resisting manipulation. It limits where the
  agent may be exposed to manipulation by managing a network domain allowlist, and what a
  manipulated agent can reach: the allowlisted model APIs normally, more only for a limited time
  the user opened.
- The container sits on an **internal network** (no route out). Its only way out is a tinyproxy
  container with an allowlist. Blocking the internal network (10.0.0.0/8) by default is required
  by company security policy.
- Rootless engines are preferred; rootful is supported with an explicit opt-in.

Non-goals: protection against kernel/container-runtime escapes (use a VM for that); managing VS
Code attach; installing harnesses automatically; DinD.

## 2. Platform

- Python 3.12+, standard library only at runtime. Dev tools: `pytest`, `ruff`, `ty` (via `uv`).
- Layout: `agent_sandbox/` package, thin `agent-sandbox` launcher (symlink into PATH),
  `pyproject.toml`, `tests/`, a minimal `README.md` that only points to `agent-sandbox help`.
- Engines: docker rootless, docker rootful, podman rootless (`--userns=keep-id`), podman rootful.
  Auto-detection tries podman first, then docker. Only rootless docker could be tested during
  development (no podman installed, no rootful docker).
- Must refuse to run as host root.

## 3. Architecture

Per workspace (identified by `<dirname>-<8 hex of sha256(abs path)>`, called `<id>`):

| Resource | Name | Purpose |
|---|---|---|
| workspace container | `agent-sandbox-<id>` | `sleep infinity`, `--init`, non-root user, internal network only |
| proxy container | `agent-sandbox-<id>-proxy` | tinyproxy + supervisor as `nobody`, no host mounts, on the internal and the default network; stateless, replaced when its image changes |
| network | `agent-sandbox-<id>-net` | `--internal`; proxy has alias `proxy` |
| state volumes | `agent-sandbox-state-<id>-<path>` | harness state, one volume per configured path |
| isolated volumes | `agent-sandbox-isolated-<id>-<path>-<6 hex of sha256(path)>` | the sandbox's own copy of an isolated workspace path (the hash keeps `.venv` and `venv` apart) |
| runtime dir | `$XDG_RUNTIME_DIR/agent-sandbox/<id>/` | the CLI's own records: lock, deadline copy, `net` session and pid |
| derived image | `localhost/agent-sandbox/<user>-<flattened base>:<tag>` | base image plus the host user |
| proxy image | `localhost/agent-sandbox/tinyproxy:<hash>` | tinyproxy built locally from a configurable base (default public `alpine:3`) |

Everything carries labels (`agent-sandbox.managed/role/id/workspace/version/spec/...`) so `ls`,
`prune` and `rm NAME` work across engines.

### Workspace container

- User: not root, same uid, gid and name as the host user. If the base image lacks that uid (or its
  home directory), a derived image is built (append to `/etc/passwd` and `/etc/group` directly so it
  works on Alpine; shell is bash when present). Existing user with that uid is accepted whatever its
  name. Derived image carries the base image id as a label and is rebuilt when it changes.
- Host umask applied through `sh -c 'umask ...; exec "$@"'` on every exec.
- Hardening: default seccomp/AppArmor, `no-new-privileges`, default capabilities (so `root` can
  `apt`), `--init`, no memory limit, no restart policy.
- Mounts (every workspace path keeps its host path inside, and the working directory of the
  container and of every exec is the workspace root):
  - workspace rw; `.git` ro (file or directory); `.agent-sandbox` ro;
  - each protected path ro (a directory or a file); missing ones are first created on the host as
    empty directories;
  - each isolated path covered by its per-workspace volume (missing ones are created on the host
    as empty directories first);
  - for linked worktrees/submodules the git common dir (and per-worktree dir if outside it) ro at
    its identical host path;
  - extra read-only mounts from config (`~` in the target is the container home);
  - state volumes under the container home.
- `git = "rw"` (writable `.git` and external git dirs) is a user-level-only opt-in.
- Mirroring the host path keeps absolute paths meaningful on both sides: tool output and
  tracebacks are clickable on the host, caches and editable installs (`.pth`) agree, worktree
  `gitdir:` pointers resolve, and harnesses that key per-project state by the working directory
  (Claude Code's `~/.claude/projects/<path>`) no longer collide in a shared state volume.
- Environment at exec time (so changes need no recreate): proxy variables pointing at
  `http://proxy:8888`, git `safe.directory=*`, `GIT_OPTIONAL_LOCKS=0`, `AGENT_SANDBOX=1`, the
  configured `[env] pass` names (only if set on the host) and `[env.set]` values (`{home}` expands).
- Default command: `harness` from config (shlex-split). If it is not installed: print an error and
  start `bash` (or `sh`). `exec -- CMD` runs arbitrary commands (a second harness, tmux).
- `root`: `exec --user 0` with a prominent banner (setup only; do not run harnesses; root in a
  rootless engine equals the host user on the mounts, in a rootful engine it can create root/setuid
  files in the workspace). Starting a harness as root cannot be prevented, only discouraged.

### Ownership by engine

- Podman rootless: `--userns=keep-id`.
- Docker rootless: container uid N maps to a sub-uid on the host (uid 1000 appears as 100999), so
  default ACLs (`setfacl`) give that host uid access; `.git`, `.agent-sandbox`, protected and
  isolated paths are skipped (matched as paths relative to the workspace root, at any depth): the
  first three stay owned by the host user, and walking a host virtualenv the sandbox never sees would
  only cost time. With `git = "rw"`, `.git` and any
  external git dirs get the ACLs too (otherwise the rw mount would not be writable). The mapping is read from
  `/proc/self/uid_map` inside a container. Applied at creation and by `repair`.
- Rootful engines: same uid; requires `allow_rootful = true` in the user config.
- Volume roots (state paths and their parents under the container home, isolated paths
  themselves but not their workspace parents) are created root-owned by the engine and are chowned
  to the sandbox user from a root exec after creation and by `repair`.

## 4. Configuration

### Project: `.agent-sandbox/` (committed)

- `config.toml`: `image` (required), `harness` (default `bash`), `[env] pass`/`[env.set]`,
  `[workspace] protected` (default `.claude`, `.agents`, `.vscode`, `.idea`), `[workspace]
  isolated` (default `.venv`, `node_modules`), `[[mounts]]` (`source`, `target` defaulting to
  `source`, always read-only), `[state] paths` (default `.claude`, `.copilot`,
  `.cache/pre-commit`), `[proxy] base_image`. Unknown keys are errors.
- Workspace paths (`protected`, `isolated`) are relative to the workspace root and normalised
  (`./x/` -> `x`); absolute paths, `..`, `.`, anything under `.git` or `.agent-sandbox` (already
  read-only) and a path that is protected and isolated at once (equal or nested) are errors.
  Nested paths such as `web/node_modules` are allowed.
- Mount paths: `source` is absolute or starts with `~` (the host home, expanded when parsing);
  `target` is absolute or starts with `~` / `{home}` (the container home, expanded when planning
  the container, because it is only known from the image). Typical use: `source =
  "~/.agents/skills"` with the target defaulting to the same `~` path.
- `tinyproxy.conf`: static settings only (Timeout, ConnectPort...). The toolkit generates Port, Allow,
  Filter*, Upstream, Log*, PidFile and rejects those directives here.
- `allow.base`, `allow.extra`: one host per line, `#` comments. `host` matches exactly; `.host`
  matches the host and all subdomains; no wildcards, no ports.
- `init --image IMG [--force]` writes all four files (allow.base lists the required hosts of all
  supported harnesses, optional ones commented out) and records approval.

### User: `~/.config/agent-sandbox/config.toml` (never in the repo)

`engine`, `docker_context`, `allow_rootful`, `git` (`ro`/`rw`), `state_volume`
(`per-workspace` or a shared name), `[workspaces."/abs/path"]` overrides, `[proxy] base_image`.
Shared state volumes belong to no single workspace: `rm --state` and `prune` keep them (with a note)
and `ls` does not list them.
Env overrides: `AGENT_SANDBOX_CONFIG_DIR`, `_STATE_DIR`, `_RUNTIME_DIR`, `AGENT_SANDBOX_ALLOW_ROOTFUL`.

### Trust on first use

Config arrives via git, so it could widen mounts or allowlists. The host stores a snapshot of the four
files in `~/.local/state/agent-sandbox/approved/<id>/`. Any difference (including the first run after a
clone) shows a unified diff and asks y/N; non-interactive runs refuse. `init` and the `net` promotion
step record approval themselves.

### Drift detection

A hash of the container-creation inputs (spec version, engine, base image id, uid/gid, ownership
mode, git mode, mounts incl. protected paths, state volumes, isolated volumes and their targets,
network) is stored as a label with the full JSON. The container home used to expand mount targets
is stored as a label too, so the check expands them the same way. On attach a mismatch aborts
with the list of changed keys and tells the user to run `recreate`.

## 5. Network and proxy

- Workspace container is only on the internal network. DNS for `proxy` comes from the engine.
- The proxy runs whenever the sandbox runs and has two tiers:
  - **base**: `allow.base` (model APIs, login).
  - **net**: base + `allow.extra` + `--allow` hosts (or allow-all), active only while a deadline file
    in the future exists.
- The proxy has no host mount. The CLI pushes the tier configs and filters, `deadline` (epoch
  seconds) and `reload` (a nonce) into `/var/lib/asb` with `engine cp` from a tar stream that sets
  owner `nobody` and mode `0600`; creation is `create`, push, `start`. A supervisor shell loop inside
  the container switches tiers by copying the tier config over `active.conf` and sending `SIGUSR1`
  (reloads config and filter without dropping connections) when the deadline passes or the nonce
  changes, and reports `<tier> <nonce>` in `state`, which the CLI reads with `exec`. The CLI keeps a
  host copy of the deadline for itself and renders the countdown; the container enforces the
  deadline, so a killed CLI still ends the session on time. Established tunnels finish naturally.
- `cp` writes files in place, so pushes are ordered (filters before configs, configs before
  `deadline`/`reload`) and every tier config ends with a marker line: the supervisor never loads one
  without it (a config cut before its `Filter` lines would allow everything). A (re)started proxy
  begins on the base tier.
- Filtering uses tinyproxy `Filter` (ERE, default deny) generated from the allowlists; only
  `ConnectPort 443` by default. Tinyproxy filters by name, never by resolved IP; names resolving into
  10.x are accepted when allowlisted (explicit user decision).
- The proxy container runs as `nobody` (65534) with all capabilities dropped and `no-new-privileges`;
  on rootless engines that is a sub-uid owning nothing on the host. Its root filesystem stays
  writable because `cp` refuses read-only ones and does not reach a tmpfs. Upstream proxy
  credentials only exist in the CLI's memory and inside the proxy container.
- Host proxy environment is read at every start: `https_proxy` > `HTTPS_PROXY` > `http_proxy` >
  `HTTP_PROXY` becomes `Upstream http|socks5 [user:pass@]host:port` (https:// proxies rejected; a
  differing HTTP/HTTPS pair warns and uses HTTPS). `NO_PROXY` entries become `Upstream none` rules
  (bare/`.suffix`/`*.suffix` -> suffix incl. the host itself; IPv4 and CIDR kept; ports and IPv6
  ignored with a warning; `*` = no upstream). Last matching rule wins, so order matters. The upstream
  proxy host is intentionally NOT added to the allowlist (it is not a request target and doing so
  would allow tunnelling through it).
- The workspace container does not inherit host proxy variables.

### `agent-sandbox net DURATION [--allow HOST]... [--allow-all] [--extend] | --stop`

- Duration: seconds, or `m`/`h` suffix, sums allowed (`1h30m`). Mandatory (except `--stop`).
- Shows a countdown with an hourglass/progress bar; live lines for blocked hosts (or, in allow-all,
  hosts outside the allowlists). Ends on expiry, Ctrl-C, SIGTERM/SIGHUP (and by the container watchdog
  on SIGKILL). A second concurrent session is refused unless `--extend`.
- `--allow-all`: prints a warning, needs a TTY and a y/N. Internal network stays closed as far as
  tinyproxy can tell: hosts from the host `NO_PROXY` and all private/loopback/link-local/CGNAT IP
  literals are null-routed (`Upstream http 0.0.0.0:0 "<spec>"`). Where an allowlist entry overlaps one
  of those, only the overlap (the narrower of the two specs) gets its normal route back: direct if it
  is within `NO_PROXY` or there is no upstream, otherwise the upstream proxy. Internal names are only
  recognised through `NO_PROXY`.
- Tinyproxy logs at `Connect` level to stderr, i.e. the container log (bounded: json-file 2x10 MB,
  podman k8s-file 10 MB); the CLI follows it with `logs --follow --since` (hostnames only).
- After a session, hosts that were blocked (or accessed outside allowlists in allow-all) are listed
  with counts and the user may append them to `allow.extra` (`y`, `N` or `s`elect each); the approval
  snapshot is updated.

## 6. Commands

| Command | Behaviour |
|---|---|
| (none) | at a repo root: create if needed, start (and the proxy), exec the harness |
| `[--image IMG] URL [DIR]` | outside a repo: `git clone` (ext transport disabled), `init` if `--image` given, then as above |
| `init --image IMG [--force]` | create `.agent-sandbox/` |
| `exec [--] CMD...` | run a command as the sandbox user |
| `root` | root shell with banner |
| `net ...` | see section 5 |
| `stop` | stop workspace and proxy |
| `rm [NAME] [--state]` | remove containers, network, runtime dir; keeps state and isolated volumes unless `--state`; never touches workspace files |
| `recreate` | remove containers and network (keeps state and isolated volumes), then create again |
| `rebuild [--pull]` | rebuild derived and proxy images (then `recreate`) |
| `ls` | all sandboxes on all engines, orphans flagged |
| `prune [--keep-state]` | remove orphaned sandboxes (workspace gone, not a git tree, id mismatch), y/N each |
| `status` | state, approval, drift, proxy tier and time left |
| `doctor` | live isolation checks (no direct route, proxy reachable, non-allowlisted host refused, no sockets, ACL) |
| `repair` | re-apply ACLs and volume-root ownership, clear the deadline if no live `net` process owns it |
| `help [config|network|security|COMMAND]` | built-in help is the single source of documentation |

Rules: running in a subdirectory of a repo is an error; per-project lock (flock) serialises creation;
creation rolls back what it created on failure; at most one network session per workspace.

## 7. Safety checks

- Extra mount sources must exist, may not be sockets/devices, and may not be (or contain, or be inside)
  sensitive trees (`~/.ssh`, `~/.gnupg`, `~/.aws`, `~/.kube`, `~/.docker`, `~/.config/gcloud`,
  `~/.config/gh`, `/run`, `/proc`, `/sys`, `/dev`, toolkit config/state/runtime dirs...). Targets
  (after `~` expansion) may not be the workspace, inside it, or a parent of it.
- Protected and isolated paths may not pass through a symlink at any component (a mount there
  would leave the workspace). An isolated path that exists as a file is an error; a protected one
  may be a file.
- Before creation the workspace and every mount source outside it (extra mounts, external git
  dirs) are scanned (budget: 50k entries / 5 s, a
  notice if incomplete) for unix sockets. Found sockets abort unless
  `--unsafely-mount-dirs-with-sockets` is given, in which case a warning is printed and the user must
  type `I understand the risks`.
- SELinux + podman: `relabel=shared` on the workspace mount.

## 8. Harness facts used for defaults

- Claude Code: required hosts `api.anthropic.com`, `claude.ai`, `platform.claude.com`; optional
  `downloads.claude.ai`, `mcp-proxy.anthropic.com`, `registry.npmjs.org`. State: `~/.claude/` and
  `~/.claude.json` (a file in `$HOME`); `CLAUDE_CONFIG_DIR=~/.claude` moves it inside the directory so
  one volume covers it (documented by Anthropic). `CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1` drops
  telemetry/updater traffic. `CLAUDE_CODE_OAUTH_TOKEN` (from `claude setup-token`) can be passed via
  `[env] pass` to avoid per-workspace logins.
- Copilot CLI: `github.com`, `api.github.com`, `.githubcopilot.com` (docs are for Copilot in general,
  not specifically the CLI; verify with the blocked-host log). State: `~/.copilot/`.
- OpenCode: low priority, hosts depend on the provider (Zen subscription hosts to be determined).
- pre-commit: keeps hook environments in `~/.cache/pre-commit` (a default state path; safe to share
  between workspaces, entries are keyed by repo and revision and guarded by a lock). Without
  `--all-files`/`--files` it "stashes" unstaged changes as a patch in that directory and calls
  `git write-tree`, which needs a writable `.git`. In `ro` mode the agent cannot stage anything
  anyway, so plain `pre-commit run` would check the user's staged changes, not the agent's; the
  agent should run `pre-commit run --all-files` (or `--files ...`).
- uv: `uv sync` and `uv venv --clear` work when `.venv` is a volume mount point (they clear the
  contents instead of removing the directory; checked with uv 0.13.4).

## 9. Testing

- Unit tests (pytest, no engine): config parsing/validation, durations, allowlist and NO_PROXY parsing,
  Upstream/Filter generation incl. allow-all ordering, log parsing, derived tag naming, spec hashing,
  uid-map arithmetic, mount validation, socket scan, approval, argument parsing, probe parsing.
- Integration tests (marked `integration`, opt-in with `pytest --integration`, on the user's rootless
  docker, using temp repos under `/tmp/asb-it-*` and isolated `AGENT_SANDBOX_*_DIR`; no image pulls, so
  the base image must be local): create and exec, ownership/ACL, read-only `.git`, tiers via
  `CONNECT`/`GET` through `/dev/tcp/proxy/8888`, `net` expiry/extend/stop/SIGKILL, allow-all, promotion,
  approval, drift/recreate, sockets, rm/ls/prune, clone, linked worktree, shared state volume, derived
  image on Alpine, host-path working directory, protected paths read-only and created empty on the
  host, isolated volumes hiding the host copy, owned by the user and surviving `recreate`.
- Not covered end to end: podman, rootful engines, a real upstream proxy, submodule workspaces,
  `rebuild` (it pulls the proxy base image).
- `ruff check`, `ruff format`, `ty check` must pass.

## 10. Design decisions and rejected alternatives

- **Shared in-project venv** (mirror paths and mount uv's interpreter directory at its host path):
  rejected. A venv hardcodes the project path (shebangs, `activate`, editable `.pth` files) and the
  interpreter path (`bin/python` symlink, `pyvenv.cfg`); even with both available, host and
  container would rewrite each other's venv, and the agent could plant a `.pth` file that runs on
  every host Python start without appearing in `git diff`. Isolation by volume is tool-agnostic
  (unlike `UV_PROJECT_ENVIRONMENT`) and keeps the familiar `.venv/bin/...` path. Cost accepted:
  dependencies are installed twice (large for e.g. pytorch+CUDA).
- **Private git storage for pre-commit stashing** (`GIT_INDEX_FILE`, `GIT_OBJECT_DIRECTORY` with the
  host objects as alternates): rejected as complex and diverging from the host index;
  `--all-files` is the semantically right call in `ro` mode.
- **Missing protected paths**: created as empty host directories, not covered by an empty read-only
  directory from toolkit state. The engine creates missing nested mount points on the host anyway,
  and the existence of the host directory would then flip the mount source and the drift hash on
  the next attach. Consequence: a missing protected *file* (e.g. `.envrc`) is created as a
  directory, so only list files that exist.
- **Per-project namespacing inside shared state volumes**: not done. Mirroring the workspace path
  already separates per-project state of harnesses that key by working directory, and
  namespacing would defeat sharing (logins, pre-commit environments).
- **Protecting `.claude/` costs** Claude Code the ability to persist "always allow" answers in
  `settings.local.json` and the agent the ability to write project skills/commands directly; it
  drafts them elsewhere and the user promotes them. A project can drop entries from `protected`.

## 11. Deferred / out of scope for v1

OpenCode defaults; modular "what to install at creation"; replacing the user's separate
`workspace-sandbox` scripts (to be revisited after solo testing); Podman and rootful verification;
Squid as an alternative proxy (documented option if IP-level enforcement is ever required);
user-level `[[mounts]]` (personal mounts such as `~/.agents/skills` currently live in the committed
project config); resolving symlinks inside mounted skill directories (links pointing outside the
mount dangle in the container).
