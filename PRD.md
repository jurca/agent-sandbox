# agent-sandbox - product requirements

Status: implemented and tested on rootless docker (see section 10); podman and rootful untested.
Section 6 (environment setup, devcontainer base) is implemented and tested the same way.
"Secret files" in section 8 is implemented and tested the same way.
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
  `.idea/`, `.devcontainer/`) is **protected** (read-only), and dependency trees the host runs
  (`.venv`, `node_modules`) are **isolated**: the sandbox gets its own copy in a volume and never
  writes the host's.
- What remains is **inescapable by design**: the agent's job is to write code that you then run.
  Tests started on the host by pre-commit or by hand, build scripts, a `Makefile`, a dev server,
  CI jobs (which often hold deploy keys and tokens in their environment): any of it can do
  anything the user or the CI runner can, including exfiltrating secrets. The sandbox only makes
  sure the agent's code runs *outside* it after a human chose to run it, never on its own. Review
  agent changes before running them where secrets live.
- **Secret files never enter the workspace.** The policy makes `.env`-style files unreadable to any
  AI agent, and a bind mount shares every file the host creates later. So real secrets live outside
  the workspace, reached through a symlink that dangles in the container, and nothing starts in the
  sandbox while a real one is found (section 8, "Secret files"). This covers files by name only,
  and it does not cover agent-written code a person runs on the host (see above).
- That is also why network access is closed by default. People are manipulated against their own
  interests every day; it would be unfair to expect an LLM agent to withstand every prompt
  injection. So the design does not rely on the agent resisting manipulation. It limits where the
  agent may be exposed to manipulation by managing a network domain allowlist, and what a
  manipulated agent can reach: the allowlisted model APIs normally, more only for a limited time
  the user opened.
- The container sits on an **internal network** (no route out). Its only way out is a tinyproxy
  container with an allowlist. Blocking the internal network (10.0.0.0/8) by default is required
  by security policy.
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
| derived image | `localhost/agent-sandbox/<user>-<flattened base>:<tag>` | `image` plus the host user; shared by the projects using that image |
| devcontainer image | `localhost/agent-sandbox/<user>-<id>-devcontainer:<hash of .devcontainer/>` | `devcontainer build` result, the base when `[devcontainer] enabled`; per user, as `${localEnv:...}` can reach the build |
| devcontainer user image | `localhost/agent-sandbox/<user>-<id>-user:<hash of .devcontainer/>` | the devcontainer image plus the host user (the remote user given the host uid) |
| extended image | `localhost/agent-sandbox/<user>-<id>-extended:<hash>` | `.agent-sandbox/Dockerfile` on top of the user image |
| proxy image | `localhost/agent-sandbox/tinyproxy:<hash>` | tinyproxy built locally from a configurable base (default public `alpine:3`) |

Everything carries labels (`agent-sandbox.managed/role/id/workspace/version/spec/...`) so `ls`,
`prune` and `rm NAME` work across engines.

### Workspace container

- User: not root, same uid, gid and name as the host user. If the base image lacks that uid (or its
  home directory), a derived image is built (append to `/etc/passwd` and `/etc/group` directly so it
  works on Alpine; shell is bash when present). Existing user with that uid is accepted whatever its
  name. Derived image carries the base image id as a label and is rebuilt when it changes.
- Host umask applied through `sh -c 'umask ...; exec "$@"'` on every exec.
- Hardening: default seccomp, AppArmor/SELinux where the engine's host has one (`doctor`
  checks seccomp, no-new-privileges, capabilities and the label from inside the container),
  `no-new-privileges`, default capabilities (so `root` can
  `apt`), `--init`, no restart policy. No resource limits unless the user config opts in with
  a `[resources]` table (defaults pids 4096, memory 4g, cpus 4 for keys it leaves out; `false`
  lifts one; per-workspace overrides): machine-specific, so never in the project config. They
  are part of the spec, and limits the engine cannot enforce (docker drops them with a warning
  when cgroup controllers are not delegated to a rootless engine) refuse creation.
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
  - state volumes under the container home;
  - a fresh tmpfs on `/tmp` (`rw,exec,nosuid,nodev,mode=1777`, no size cap), so `/tmp` starts
    empty on every start like on a rebooted host. `/var/tmp` stays on the container's disk.
    Creating a sandbox refuses a workspace, an external git dir or a `[[mounts]]` target under
    `/tmp`: the engine would create their parents in the tmpfs, owned by root.
- `git = "rw"` (writable `.git` and external git dirs) is a user-level-only opt-in.
- Mirroring the host path keeps absolute paths meaningful on both sides: tool output and
  tracebacks are clickable on the host, caches and editable installs (`.pth`) agree, worktree
  `gitdir:` pointers resolve, and harnesses that key per-project state by the working directory
  (Claude Code's `~/.claude/projects/<path>`) no longer collide in a shared state volume.
- Environment at exec time (so changes need no recreate): proxy variables pointing at
  `http://proxy:8888`, git `safe.directory=*`, `GIT_OPTIONAL_LOCKS=0`, `AGENT_SANDBOX=1`, the
  configured `[env] pass` names (only if set on the host) and `[env.set]` values (`{home}` expands).
  For the sandbox user (not `root`), `PATH` gets `~/.local/bin` in front of the container's (or
  `remoteEnv`'s) `PATH`, unless `[env]` sets `PATH`. Execs do not start login shells: `/etc/profile`
  resets `PATH` on Debian and Alpine, dropping the image's `ENV PATH`, and `~/.profile` would never
  reach the harness anyway.
- **User environment probe** (devcontainer `userEnvProbe`, default `loginInteractiveShell`, also
  for plain images): before each sandbox-user exec (each setup step, the harness, `exec`) the
  user's login shell from `/etc/passwd` (else `bash`, else `sh`) runs once with `-lic` (`-lc`,
  `-ic`; `none` skips it) and prints its environment between two copies of a fixed marker
  (`--agent-sandbox--user-env-probe--`); what lies between the first and the last one is the
  environment, so rc-file output is ignored; `timeout 10` caps it where available. What differs
  from the image's environment applies below `remoteEnv` and the toolkit's and `[env]` variables
  (`PWD`, `OLDPWD`, `SHLVL`, `_` dropped). Its `PATH` gets back the image's entries the profile
  dropped, in place (like the devcontainers CLI's `mergePaths`). This is how what Features and
  setup commands put only in rc files (pipx-based Features such as poetry append to
  `/etc/bash.bashrc`, rustup to `~/.profile`) reaches non-interactive commands such as
  `sh -c "poetry sync"`. A failed probe warns and adds nothing. Root execs are not probed.
- Default command: the first installed of the `harness` candidates (each shlex-split), with the
  user config's `harness` preference tried before the project's list (duplicates once). One exec
  probes all first words with `command -v`. If none is installed: print an error and start `bash`
  (or `sh`). `exec -- CMD` runs arbitrary commands (a second harness, tmux).
- `root`: `exec --user 0` with a prominent banner (setup only; do not run harnesses; root in a
  rootless engine equals the host user on the mounts, in a rootful engine it can create root/setuid
  files in the workspace). Starting a harness as root cannot be prevented, only discouraged.

### Ownership by engine

- Podman rootless: `--userns=keep-id`.
- Docker rootless: container uid N maps to a sub-uid on the host (uid 1000 appears as 100999), so
  ACLs (`setfacl`) give that host uid access; `.git`, `.agent-sandbox`, protected and
  isolated paths are skipped (matched as paths relative to the workspace root, at any depth): the
  first three stay owned by the host user, and walking a host virtualenv the sandbox never sees would
  only cost time. With `git = "rw"`, `.git` and any
  external git dirs get the ACLs too (otherwise the rw mount would not be writable). The mapping is read from
  `/proc/self/uid_map` inside a container. Applied at creation and by `repair`.
  - The ACLs are **symmetric**: every directory and file names *both* the sandbox user's host uid
    and the host user, in the access ACL and (directories) in the default ACL. Tools that replace
    a file (write a temp file, copy the old file's ACL onto it, rename it over the original; GNU
    `sed -i` does this) leave a file owned by the sub-uid with the copied ACL. Had the copy named
    only the sandbox user (the host user used to need no entry as the owner), the host user would
    lose write access, and could not fix it either: only a file's owner may change its ACL.
  - Remaining drift: the agent can `chmod` files it owns, which narrows the ACL mask and with it
    the host user's named entry. `repair` fixes that.
- Rootful engines: same uid; requires `allow_rootful = true` in the user config.
- Volume roots (state paths and their parents under the container home, isolated paths
  themselves but not their workspace parents) are created root-owned by the engine and are chowned
  to the sandbox user from a root exec after creation and by `repair`.
- **Reclaiming** (`repair`, any running engine): workspace files and directories owned by the
  sandbox user (or its group) are handed back to the host user, so the host can re-apply the
  ACLs. The ids come from observing both sides, not from map arithmetic, because
  `/proc/self/uid_map` is relative to the parent user namespace (the host for docker, podman's own
  namespace for rootless podman):
  - the target owner and group are those of `.agent-sandbox/` (host-owned, read-only inside, the
    host checks that it owns it): `stat` inside the container gives the ids passed to `chown`
    (rootless docker: `0:0`). If the owner equals the sandbox user's uid (rootful, `keep-id`),
    the sandbox user *is* the host user and there is nothing to reclaim (the group alone, e.g.
    from a setgid project directory, is no reason to touch the user's files);
  - the host lists directories and regular files (`lstat`, never following symlinks, with the
    same skipped paths as the ACLs) whose owner or group differs from `.agent-sandbox/`'s; a root
    exec passes them to `find -maxdepth 0 -user|-group <sandbox id> -exec chown -h ...`, so only
    what the container sees as the sandbox user's changes and a path swapped for a symlink is not
    followed.
  Directories the host could not read are listed again once they were reclaimed. The sandbox user
  keeps access through its named ACL entry. Reclaiming, then re-applying the ACLs, also restores
  what a `chmod` narrowed.

## 4. Configuration

### Project: `.agent-sandbox/` (committed)

- `config.toml`: `image` or `[devcontainer] enabled`/`config` (exactly one, section 6), `harness`
  (a command line or a list of them, default `["claude", "copilot", "bash", "sh"]`), `[env] pass`/`[env.set]`,
  `[workspace] protected` (default `.claude`, `.agents`, `.vscode`, `.idea`, `.devcontainer`),
  `[workspace] isolated` (default `.venv`, `node_modules`), `[workspace] secrets`,
  `secrets_except` and `secrets_history_depth` (section 8, "Secret files"), `[[mounts]]` (`source`, `target`
  defaulting to `source`, always read-only), `[state] paths` (default `.claude`, `.copilot`,
  `.cache/pre-commit`), `[proxy] base_image`, `[setup] create`/`start`. Unknown keys are errors.
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
(`per-workspace` or a shared name), `harness` (tried before the project's list),
`[workspaces."/abs/path"]` overrides (`git`, `state_volume`, `harness`), `[proxy] base_image`,
`devcontainer_cli` (command list, default `["devcontainer"]`).
Shared state volumes belong to no single workspace: `rm --state` and `prune` keep them (with a note)
and `ls` does not list them.
Env overrides: `AGENT_SANDBOX_CONFIG_DIR`, `_STATE_DIR`, `_RUNTIME_DIR`, `AGENT_SANDBOX_ALLOW_ROOTFUL`.

### Trust on first use

Config arrives via git, so it could widen mounts or allowlists or change the image. The host stores
a snapshot of the whole `.agent-sandbox/` tree (a Dockerfile there may copy any file of it) and,
with `[devcontainer] enabled`, of the whole `.devcontainer/` tree in
`~/.local/state/agent-sandbox/approved/<id>/{agent-sandbox,devcontainer}/` (the flat four-file
layout of older versions is still read). Any difference (including the first run after a clone)
shows a unified diff (binary files by size, symlinks by target) and asks y/N; non-interactive runs
refuse. `init` and the `net` promotion step record approval themselves.

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

## 6. Environment setup

Projects need more than a base image: system packages, devcontainer Features, internal CA
certificates, `~/.bashrc` changes, and per-workspace steps such as `uv sync`, `poetry sync` or
`pre-commit install-hooks`. Two layers, because the two kinds have different properties:

| | Image layer | Setup layer |
|---|---|---|
| What | tools, system packages, CA certificates, home dotfiles | dependency installs and caches that need the workspace |
| Runs | at image build, as root | in the container after creation, as the sandbox user |
| Survives `recreate` | yes (cached image) | its results do where they live in volumes (`.venv`, state paths) |
| Network | the build's own (host network); inputs are approved files only | through the proxy, `allow.extra` open while it runs |

Root work belongs in the image: the container's writable layer is lost on `recreate`, so there is
no root setup hook.

### Image layer

Layers, bottom to top: the base (`image`, or the `devcontainer build` result), the **user layer**
(below), then an optional `.agent-sandbox/Dockerfile` for sandbox-only additions. That Dockerfile
starts with `ARG base` / `FROM $base`, gets the build args `user`, `uid`, `gid` and `home`, and is
built with `.agent-sandbox/` as the context (never the workspace: agent-written files must not
enter the build). The derived image's label carries the Dockerfile's hash, so a change rebuilds it
and the spec hash makes the container drift. CA certificates go first when later steps need them
(TLS-inspecting corporate proxies); for devcontainers they must be in the base image or the
devcontainer's own Dockerfile, because Features run before our layers.

User layer, in order. The devcontainer's remote user is resolved as the CLI does it
(`containerFeatures.ts`): the last `remoteUser` in the metadata, else the last `containerUser`,
else the image's `USER`, else `root`.
1. a user with the host uid exists: use it, whatever its name (today's behaviour);
2. the devcontainer's remote user is not root and exists: change its uid/gid to the host's in
   `/etc/passwd` and `/etc/group` and `chown -R` its home (what the devcontainers CLI does in
   `scripts/updateUID.Dockerfile`; a gid already taken keeps the old gid);
3. the devcontainer's remote user is not root and does not exist (only possible when
   `remoteUser`/`containerUser` names it; the CLI does not check): create our user under that name;
4. a plain `image` project, or a devcontainer whose remote user is root: create our user as today.

A base image without a digest (`image = "..."` in config.toml, or the devcontainer's base, see
below) warns on every build, for consistency with the lockfile requirement: the spec hash notices a
changed base, but not what changed, so only a digest lets the user audit it.

Builds are not proxied: they run only approved, agent-unwritable inputs, which is the same trust
as the user running `docker build`, and BuildKit only offers `default`/`host`/`none` networks to
`RUN` steps. Host proxy variables are passed as build args as today.

### Devcontainer source

Opt-in per project: `config.toml` sets exactly one of `image = "..."` and `[devcontainer]
enabled = true` (both, or neither, is an error). `[devcontainer] config` selects the file:
`.devcontainer/devcontainer.json` (default) or `.devcontainer/<name>/devcontainer.json`. Purpose:
people working in the project's dev container and the agent get the same environment.

- **Everything the build reads must be agent-unwritable.** `.devcontainer/` is protected
  implicitly, even when a project drops it from `[workspace] protected`. A `.devcontainer.json` in
  the workspace root is rejected with a hint to move it to `.devcontainer/devcontainer.json`
  (the CLI and VS Code accept both): the file alone could be protected (protected paths may be
  files), but it conventionally comes with a Dockerfile and context in the workspace root, and the
  approved inputs would be loose files among agent-written ones. A Dockerfile or a local Feature
  outside `.devcontainer/` is an error for the same reason. A `build.context` outside it only warns:
  the approved Dockerfile decides what is copied, but the copied files' contents come from the
  agent.
- **CLI**: the user's `devcontainer` (Node 20+). Which executable runs is a host decision, so it is
  a user-config key (`devcontainer_cli`, a command list, default `["devcontainer"]`, e.g.
  `["npx", "@devcontainers/cli"]`), never project config. Missing CLI: an error saying how to
  install it. It is used only for `build`, `upgrade` (in printed instructions) and
  `read-configuration`.
- **Build**: `devcontainer build --workspace-folder ROOT --config PATH --frozen-lockfile
  --image-name localhost/agent-sandbox/<user>-<id>-devcontainer:<hash of the approved tree>
  --docker-path ENGINE`, result parsed from the JSON line on stdout. `rebuild` adds `--no-cache`.
  Verified with CLI 0.90.0 on rootless docker: `build` never runs `initializeCommand` (only `up`
  does), never remaps uids, installs each Feature's `install.sh` as root in a generated
  Dockerfile (`buildx` with `--build-context`, a fallback without BuildKit exists), turns
  `containerEnv` into image `ENV`, and fetches Features and
  `containers.dev/static/devcontainer-control-manifest.json` over the host network. It sets no
  proxy build args itself.
- **Lockfile required**. Without `--frozen-lockfile` the CLI rewrites `devcontainer-lock.json`
  whenever it differs, i.e. changes approved files behind the user's back; the lockfile pins
  Features by digest, so it is what makes approving them meaningful. Both failures are reported
  before anything is built and turned into instructions:
  - `Lockfile does not exist.`: run `devcontainer upgrade --workspace-folder . [--config PATH]`,
    review and commit `devcontainer-lock.json`, approve, retry;
  - `Lockfile does not match.`: run the same with `--dry-run` (prints the new lockfile, writes
    nothing) to compare, then without it.
- **Unpinned base images warn** (see the image layer): an `image` without `@sha256:` in the
  devcontainer config, or a `FROM` without a digest in its Dockerfile. The lockfile does not cover
  them.
- **Approval** covers the whole `.devcontainer/` tree (configs, lockfiles, Dockerfiles, local
  Features, also those shared between named configs) as a tree diff.
- **What applies** comes from the built image's `devcontainer.metadata` label: a JSON array with
  one entry per Feature (carrying its `id`) in install order and the devcontainer.json entry last,
  with `${...}` variables **unsubstituted**. Keys that only exist in devcontainer.json
  (`initializeCommand`, `runArgs`, `workspaceMount`, ...) are not in the label; warnings about
  them read `devcontainer read-configuration` (parsed JSONC, but already substituted with the host
  environment, so it is used for nothing else).

| Key | Handling |
|---|---|
| `containerEnv` | already `ENV` in the image |
| `remoteEnv` | exec environment (merged in label order; `[env]` from config.toml wins) |
| `userEnvProbe` | the user environment probe, see the workspace container (last value wins) |
| `remoteUser` | user layer, see above; `containerUser` is ignored |
| `onCreateCommand`, `updateContentCommand`, `postCreateCommand` | setup layer, create phase |
| `postStartCommand` | setup layer, every container start |
| `postAttachCommand` | before each harness start (plain `agent-sandbox`, not `exec`/`root`); failures warn |
| `privileged`, `capAdd`, `securityOpt`, `mounts`, Feature `entrypoint` | not applied; a warning names the Feature (e.g. docker-in-docker: installed, but its daemon will not run) |
| `initializeCommand`, `runArgs`, `workspaceMount`, `appPort` | not applied, warned |
| `workspaceFolder` other than the mirrored path | warned; commands run in the mirrored path |
| `init` | always on anyway |
| `forwardPorts`, `portsAttributes`, `hostRequirements`, `customizations`, `shutdownAction` | ignored |
| `dockerComposeFile` | error: not supported |

Variables in commands and `remoteEnv`: `${localWorkspaceFolder}` and `${containerWorkspaceFolder}`
are both the workspace path (mirrored), likewise their `...Basename` forms; `${containerEnv:NAME}`
comes from the image; `${localEnv:NAME[:default]}` resolves only names listed in `[env] pass`,
others become the default (or empty) with a warning; anything else is left as is with a warning.

### Setup layer

- Sources: `[setup] create = [...]` and `[setup] start = [...]` in config.toml (each entry a shell
  command, run with `sh -c` in order, without `${...}` substitution, which is left to the shell),
  then the devcontainer lifecycle commands mapped above (`${devcontainerId}` is the workspace id).
  Devcontainer command forms: a string runs with `sh -c`, an array runs directly, an object runs
  its named commands in parallel with output prefixed by the name. Per hook, label order (Features
  first). Every command is a separate process, as in the CLI (`runRemoteCommand` with
  `/bin/sh -c` or the array, on a PTY), so nothing it exports reaches the harness; that holds for
  `postAttachCommand` too.
- Runs as the sandbox user with the normal exec environment (plus the probed one, probed
  again before each command, and `remoteEnv`), in the workspace
  root, no TTY. Only the **create phase** gets the `net` tier (base + `allow.extra`), and only
  through the proxy: it cannot have a direct route, because the workspace (agent-written, e.g.
  dependency build hooks) and the state volumes (harness credentials) are already mounted. The
  tier is a lease of 5 minutes renewed every minute while it runs, so a killed CLI closes it soon;
  an active `net` session is used as it is and left running, and a lease taken over by `net
  --extend`/`--stop` is left alone. The start and attach phases stay on the base tier: a harness
  may already run in another terminal then.
- Success is recorded on the host (`~/.local/state/agent-sandbox/setup/<id>.json`, keyed by
  container id) only after every create command succeeded, together with a hash of the commands.
  A new container (`recreate`) or changed commands have no matching record; `rm --state` deletes
  it. One setup runs at a time per workspace (a lock in the runtime dir).
- **Automatic**: a harness start (plain `agent-sandbox`) without a matching record runs the create
  phase first, under a header saying so (it can take long). This needs no separate consent: the
  only extra network is `allow.extra`, already approved, and only while setup runs, before any
  harness runs in the container. `exec` and `root` never trigger it and work without a record
  (debugging).
- Fail, inspect, allow, rerun: blocked hosts are logged live and listed at the end with the same
  promotion prompt as `net`, followed by "retry now?" (TTY only). Otherwise the harness is not
  started and the message says to run `agent-sandbox setup`, which reruns the create phase without
  a `recreate`, so commands must be idempotent (`uv sync`, `poetry sync` and
  `pre-commit install-hooks` are).
- The start phase runs once per container start (recorded by the container's `StartedAt`), after
  the create phase, before the next harness start; failures warn. `agent-sandbox setup` reruns
  both phases.
- `pre-commit install` does not belong here: it writes `.git/hooks/pre-commit`, which host git
  executes, and with `.git` shared with the host it changes nothing that a host-side install has not
  done. `pre-commit install-hooks` (fills `~/.cache/pre-commit`, a state path) is the useful part
  and works with a read-only `.git`.

### Open questions

- `devcontainer build` on podman (`--docker-path podman`) is untested; to be done in the podman
  verification session.

## 7. Commands

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
| `rebuild [--pull]` | rebuild every workspace image layer (devcontainer with `--no-cache`) and the proxy image (then `recreate`) |
| `setup` | rerun the setup create and start phases in the running container (section 6) |
| `ls` | all sandboxes on all engines, orphans flagged |
| `prune [--keep-state]` | remove orphaned sandboxes (workspace gone, not a git tree, id mismatch), y/N each |
| `secrets check` | run the secret file checks (section 8) without starting anything; exit 1 on a finding |
| `secrets adopt [--dry-run]` | move real secret files to the secrets directory and leave symlinks; never edits `.gitignore` |
| `secrets rotated PATH...` | with the history check enabled: record that the secrets in the commits at these paths so far were rotated (section 8) |
| `status` | state, approval, drift, proxy tier and time left |
| `doctor` | live isolation checks (no direct route, proxy reachable, non-allowlisted host refused, no sockets, ACL) |
| `repair` | reclaim workspace files owned by the sandbox user's sub-uid, re-apply ACLs and volume-root ownership, clear the deadline if no live `net` process owns it |
| `help [config|network|security|COMMAND]` | built-in help is the single source of documentation |

Rules: running in a subdirectory of a repo is an error; per-project lock (flock) serialises creation;
creation rolls back what it created on failure; at most one network session per workspace.

## 8. Safety checks

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
  type `I understand the risks`. `check_sockets = false` on a `[[mounts]]` entry skips the scan of
  that mount (walking a flaky network file system can hang or fail).
- SELinux + podman: `relabel=shared` on the workspace mount.

### Secret files

Files whose **basename** matches `[workspace] secrets` are secret files. The project list adds to
the defaults `.env`, `.env.*` and `*.env`, and cannot remove them. `[workspace] secrets_except`
adds exact basenames holding no secrets to the defaults `.env.example`, `.env.sample` and
`.env.template`, exempting them from every rule here; frameworks that commit `.env.test` or
`.env.development` list those. A wildcard, or a default name such as `.env`, is an error. Both live in
the approved project config, so the agent cannot change them. Directories never match (`.env/` is
a common virtualenv name).

**Run on the host before anything starts in the sandbox** (no command, `exec`, `root`, `setup`, and
before creation), under the per-project lock. Any finding refuses to start, lists every finding
with its fix, and warns that sessions already running can read a real file it found.

1. **Scan** the workspace without following symlinks, skipping every `.git` and isolated paths (the
   container sees the volume there, not the host tree), and also every extra mount source. There is
   no budget and a notice is not enough: a directory the host cannot read is a finding.
2. **Real files**: a match that is not a symlink is a finding, whatever its mode.
3. **Symlink targets**: a matching symlink must resolve inside `<config dir>/secrets/`, created
   `0700`. The target may be missing. Extra mounts already refuse the config directory, so the
   target can never be in the container. The fixed location also stops the agent, which can replace
   links in the workspace, from pointing one at `~/.ssh/id_rsa` or at a file it wrote, for host tools
   to read. A workspace containing the secrets directory (a repository at `~`) is refused.
4. **Ignored and untracked**: every match in the workspace must pass `git check-ignore -q` (without
   `--no-index`, so a tracked file fails even when listed in `.gitignore`; a directory-only pattern
   such as `.env/` fails for a symlink, as it should).
5. **Rule that protects clones**: the rule must come from a `.gitignore` tracked by git, read
   from `git check-ignore -v -n`. `.git/info/exclude` and a global excludes file protect one machine
   only, and in `git = "rw"` mode the agent can write `.git/`. Decide from the reported pattern:
   with `-v` the exit code is 0 for a negated rule too.
6. **Files that do not exist yet**: for each pattern outside `secrets_except`, `*` is replaced by a
   probe name and that name is checked at the root and one directory down
   (`.env`, `agent-sandbox-probe/.env`). Waiting for the file to appear would be too late: the
   point is that the first `git add` of a new `.env` already does nothing.
7. **History, opt-in and at creation only**: off by default, because finding committed secrets is
   the job of the server-side scanner and the pre-commit hook, and a slow start gets a check switched
   off. `[workspace] secrets_history_depth = N` (a positive integer) searches the newest `N` commits
   across all refs (`git log --all -n N`, names filtered afterwards: with a pathspec or
   `--diff-filter`, `-n` counts only matching commits, so it would walk all of a clean history).
   `.git` is readable in the sandbox, so a commit adding or changing a matching path refuses
   creation until the user runs `secrets rotated PATH...`. That records in the workspace state every
   commit on any ref that adds or changes the path so far, rather than a point in time (refs need
   not be linear, clocks drift): a later commit at the path is a new finding, and so is a rewritten
   one, while removing the file is not. Best effort: older commits and unreachable objects are not
   searched.

`secrets adopt` moves each real file to `<config dir>/secrets/<id>/<relative path>` (`0600`),
copies it to a new file so no ACL comes along, and atomically replaces the original with an
absolute symlink. A linked worktree can link to the same file by hand, as anything under `secrets/`
passes. It refuses a tracked file: that is already in history, so it prints the steps instead
(`git rm --cached`, rotate, and `secrets rotated` if the history check is enabled).

Inside the sandbox a secret file is a dangling link (`ENOENT`). Code that needs values gets dummy
ones from `[env.set]` or an excepted file such as `.env.test`, and a tool that insists on `.env`
fails there. A write through the link lands in the container's own disk at most, never on the host.

A dev container may mount the secrets, because the sandbox does not apply `mounts` from
`devcontainer.json`. The links are absolute, so the target must equal the host path, for example
`source=${localEnv:HOME}/.config/agent-sandbox/secrets,target=${localEnv:HOME}/.config/agent-sandbox/secrets,type=bind,readonly`.
An agent started inside that dev container can read them: it is not a sandbox.

**Known gap, accepted:** the checks run when something starts. A real file that appears during a
session is readable until the next check, and that includes a host `sed -i` without
`--follow-symlinks`, which replaces the link with a copy of the secret. So does any tool that
replaces rather than writes through the link. Secrets the agent is told or sees in other files
(`.env.bak`, logs, build output) are out of scope too; those belong to the secrets scanner. So are
secrets already committed, unless the history check finds them: the agent can read those through
`.git`.

## 9. Harness facts used for defaults

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

## 10. Testing

- Unit tests (pytest, no engine): config parsing/validation, durations, allowlist and NO_PROXY parsing,
  Upstream/Filter generation incl. allow-all ordering, log parsing, derived tag naming, spec hashing,
  uid-map arithmetic, symmetric ACLs, the reclaim walk, the reclaim `chown` ids and its no-op when
  the sandbox user is the host user, mount validation, socket scan, approval (trees, binary files,
  old snapshots), argument parsing, probe parsing, devcontainer metadata (remote user, not-applied
  settings, lifecycle steps, `${...}` substitution), configuration checks and lockfile errors, the
  setup phases and their records, image layering and the spec.
- Integration tests (marked `integration`, opt-in with `pytest --integration`, on the user's rootless
  docker, using temp repos under `$ASB_TEST_DIR/asb-it-*` (default `/var/tmp`) and isolated
  `AGENT_SANDBOX_*_DIR`; no image pulls, so
  the base image must be local): create and exec, ownership/ACL, a file replaced by `sed -i` in the
  sandbox stays writable on the host, `repair` reclaims a sub-uid-owned file the host cannot write,
  read-only `.git`, tiers via
  `CONNECT`/`GET` through `/dev/tcp/proxy/8888`, `net` expiry/extend/stop/SIGKILL, allow-all, promotion,
  approval, drift/recreate, sockets, rm/ls/prune, clone, linked worktree, shared state volume, derived
  image on Alpine, host-path working directory, protected paths read-only and created empty on the
  host, isolated volumes hiding the host copy, owned by the user and surviving `recreate`, `/tmp`
  emptied by `stop` while `/var/tmp` survives, `/tmp` executable; setup create with
  `allow.extra` (blocked hosts reported, base tier afterwards), once per container, start once per
  start, failure keeping the harness from starting until `setup` succeeds; the
  `.agent-sandbox/Dockerfile` layer and its drift; a devcontainer `remoteUser` remapped or
  created; and, when `ASB_TEST_DEVCONTAINER_CLI` is set, the devcontainer flow (missing lockfile,
  `upgrade`, build with a local Feature, lifecycle commands, `remoteEnv`, read-only
  `.devcontainer/`).
- Secret files, integration: a dangling link in the container; refusal on a real file, a link
  outside `secrets/`, a tracked file and an excludes-only rule; `adopt` then a clean start; the
  check on `exec` against a running sandbox; the history check off by default, refusing a match
  within `secrets_history_depth`, missing one beyond it, passing after `secrets rotated`, and
  refusing again after a new commit at the path.
- Not covered end to end: podman, rootful engines, a real upstream proxy, submodule workspaces,
  `rebuild` (it pulls the proxy base image).
- `ruff check`, `ruff format`, `ty check` must pass.

## 11. Design decisions and rejected alternatives

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
- **`/tmp` as tmpfs**: the engines keep the container's writable layer across stop/start, so
  without it `/tmp` kept stale sockets, locks and temp files until `recreate`. It is mounted `exec`
  (Podman defaults to `noexec`, which breaks build steps and compiled test binaries) and without a
  `size=` cap (the kernel default is half of RAM): with no memory limit, large temp files cost
  host RAM/swap, which is accepted over builds failing on a cap; `/var/tmp` remains on disk. Wiping
  `/tmp` at start instead was rejected: a workspace under `/tmp` is bind-mounted there and would be
  deleted. Such workspaces are refused at creation instead (keeping the host path inside means
  their parents would be root-owned directories in the tmpfs; Claude Code, for one, refuses a
  root-owned `/tmp/claude-<uid>`).
- **File-system watcher fixing ownership/ACLs as they drift**: rejected. Symmetric ACLs remove
  the common cause (replaced files carrying a copied ACL). A watcher would be a host daemon that
  has to run whenever the sandbox runs, needs inotify watches for the whole tree, races the agent's
  own atomic writes, cannot change ACLs of files it does not own (so it would need root execs
  anyway), and would be a host-user process acting on paths the agent controls. The rare
  remaining drift (`chmod` by the agent) is left to `repair`.
- **Protecting `.claude/` costs** Claude Code the ability to persist "always allow" answers in
  `settings.local.json` and the agent the ability to write project skills/commands directly; it
  drafts them elsewhere and the user promotes them. A project can drop entries from `protected`.

- **The devcontainers CLI owning the container** (`devcontainer up`): rejected. devcontainer.json
  trusts the repository: `initializeCommand` runs on the host, and `runArgs`, `mounts`,
  `privileged`, `capAdd` and `securityOpt` would undo the isolation, so the file would have to be
  filtered anyway; mounts, ownership, labels and drift detection would have to pass through
  generated overrides; `stop`/`down` are missing. The CLI only builds images (section 6).
- **`devcontainer set-up` / `run-user-commands` for lifecycle commands**: rejected. They write the
  "already ran" marker before running the command (`injectHeadless.ts`), so a failed
  `postCreateCommand` is skipped on retry; they patch `/etc/environment` and `/etc/profile` as root
  and pass the proxy variables only via `--remote-env`. The command format is small enough to run
  ourselves.
- **Installing devcontainer Features natively** (fetching the OCI artifacts without the CLI):
  rejected for now. The point of devcontainer support is parity with people using the dev
  container, and reimplementing option defaults, `installsAfter` ordering and the `_REMOTE_USER*`
  variables would drift from the CLI.
- **Setup hooks with an unrestricted network**: rejected. When they run, agent-written workspace
  files and the harness credentials in the state volumes are mounted, and installers execute
  dependency hooks the agent may have planted.
- **Proxying image builds**: not done. Builds run approved inputs only, and BuildKit cannot attach
  `RUN` steps to the internal network.
- **`chmod 600` on secret files**: rejected. `apply_acls` names the sandbox user on every file, and
  the default ACLs override `umask` for new ones (verified: `umask 077` on the host still gave a
  file the sandbox could read). Under keep-id and rootful engines the sandbox user is the owner
  anyway.
- **Masking secret files with an empty read-only bind mount**: rejected, also as a backup for the
  symlinks. It does stop the agent (write, `rm`, `mv`, `ln`, `umount`, `unshare` and `/proc/1/root`
  all failed), but on rootless docker: a host tmp+rename or `rm` + recreate silently removes the mask
  (a rename away moves it with the old name), new files are never masked, and on a symlink the
  engine follows the link and mounts over the target path, leaving `.env` unprotected when the link
  is replaced. With real files refused at every start, a mask would have nothing left to cover.
- **Per-pattern FUSE filter over the workspace**: rejected. It is the only option that closes the
  mid-session gap, but needs a third-party dependency and a daemon, slows every workspace access and
  conflicts with the standard-library-only rule.

## 12. Deferred / out of scope for v1

OpenCode defaults; Podman and rootful verification;
Squid as an alternative proxy (documented option if IP-level enforcement is ever required);
user-level `[[mounts]]` (personal mounts such as `~/.agents/skills` currently live in the committed
project config); resolving symlinks inside mounted skill directories (links pointing outside the
mount dangle in the container); a host-side watcher stopping the container when a real secret file
appears mid-session (needs a process that outlives `exec`, which today replaces the launcher, and
still leaves a short window); a user-level secrets directory other than `<config dir>/secrets/`.
