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
- The workspace is **bind-mounted** (read-write); review and commits happen on the host.
  `.git` and `.agent-sandbox/` are mounted **read-only** so git hooks, `.git/config` (fsmonitor,
  diff drivers...) and the toolkit configuration cannot be planted by the agent.
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
- Mounts: workspace -> `/workspace` rw; `.git` ro (file or directory); `.agent-sandbox` ro; for linked
  worktrees/submodules the git common dir (and per-worktree dir if outside it) ro at its identical
  host path; extra read-only mounts from config; state volumes under the container home.
  `git = "rw"` is a user-level-only opt-in.
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
  default ACLs (`setfacl`) give that host uid access; `.git` and `.agent-sandbox` are skipped so they
  stay owned by the host user (read-only for the container user). With `git = "rw"`, `.git` and any
  external git dirs get the ACLs too (otherwise the rw mount would not be writable). The mapping is read from
  `/proc/self/uid_map` inside a container. Applied at creation and by `repair`.
- Rootful engines: same uid; requires `allow_rootful = true` in the user config.

## 4. Configuration

### Project: `.agent-sandbox/` (committed)

- `config.toml`: `image` (required), `harness` (default `bash`), `[env] pass`/`[env.set]`,
  `[[mounts]]` (`source`, `target`, always read-only), `[state] paths` (default `.claude`,
  `.copilot`), `[proxy] base_image`. Unknown keys are errors.
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

A hash of the container-creation inputs (engine, base image id, uid/gid, ownership mode, git mode,
mounts, state volumes, network) is stored as a label with the full JSON. On attach a mismatch aborts
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
| `rm [NAME] [--state]` | remove containers, network, runtime dir; keeps state volumes unless `--state`; never touches workspace files |
| `recreate` | remove containers and network (keeps state), then create again |
| `rebuild [--pull]` | rebuild derived and proxy images (then `recreate`) |
| `ls` | all sandboxes on all engines, orphans flagged |
| `prune [--keep-state]` | remove orphaned sandboxes (workspace gone, not a git tree, id mismatch), y/N each |
| `status` | state, approval, drift, proxy tier and time left |
| `doctor` | live isolation checks (no direct route, proxy reachable, non-allowlisted host refused, no sockets, ACL) |
| `repair` | re-apply ACLs and state-dir ownership, clear the deadline if no live `net` process owns it |
| `help [config|network|security|COMMAND]` | built-in help is the single source of documentation |

Rules: running in a subdirectory of a repo is an error; per-project lock (flock) serialises creation;
creation rolls back what it created on failure; at most one network session per workspace.

## 7. Safety checks

- Extra mount sources must exist, may not be sockets/devices, and may not be (or contain, or be inside)
  sensitive trees (`~/.ssh`, `~/.gnupg`, `~/.aws`, `~/.kube`, `~/.docker`, `~/.config/gcloud`,
  `~/.config/gh`, `/run`, `/proc`, `/sys`, `/dev`, toolkit config/state/runtime dirs...). Targets may
  not be inside `/workspace`.
- Before creation the workspace, extra mounts and git dirs are scanned (budget: 50k entries / 5 s, a
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

## 9. Testing

- Unit tests (pytest, no engine): config parsing/validation, durations, allowlist and NO_PROXY parsing,
  Upstream/Filter generation incl. allow-all ordering, log parsing, derived tag naming, spec hashing,
  uid-map arithmetic, mount validation, socket scan, approval, argument parsing, probe parsing.
- Integration tests (marked `integration`, opt-in with `pytest --integration`, on the user's rootless
  docker, using temp repos under `/tmp/asb-it-*` and isolated `AGENT_SANDBOX_*_DIR`; no image pulls, so
  the base image must be local): create and exec, ownership/ACL, read-only `.git`, tiers via
  `CONNECT`/`GET` through `/dev/tcp/proxy/8888`, `net` expiry/extend/stop/SIGKILL, allow-all, promotion,
  approval, drift/recreate, sockets, rm/ls/prune, clone, linked worktree, shared state volume, derived
  image on Alpine.
- Not covered end to end: podman, rootful engines, a real upstream proxy, submodule workspaces,
  `rebuild` (it pulls the proxy base image).
- `ruff check`, `ruff format`, `ty check` must pass.

## 10. Deferred / out of scope for v1

OpenCode defaults; modular "what to install at creation"; replacing the user's separate
`workspace-sandbox` scripts (to be revisited after solo testing); Podman and rootful verification;
Squid as an alternative proxy (documented option if IP-level enforcement is ever required).
