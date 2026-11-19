# agent-sandbox

Per-workspace containers for AI agent harnesses (Claude Code, Copilot CLI, OpenCode), with
the workspace bind-mounted, `.git` read-only and network access only through an allowlisting proxy.

This is an experimental project exploring stronger AI agent sandboxing approaches. There are also
plenty [known alternatives](https://seznam.github.io/jailoc/explanation/alternatives/) with their
pros and cons.

## What it does not protect against

The agent writes code that you then run: tests started on the host by pre-commit or by hand,
build scripts, CI jobs that hold tokens and deploy keys. Any of it runs with full rights there and
could exfiltrate secrets. The sandbox only ensures nothing the agent wrote runs outside it without
you choosing to run it, so review changes before running them where secrets live.

Network access is closed by default for the same reason: agents, like people, can be manipulated
(prompt injection), so the sandbox limits what a manipulated agent can reach instead of trusting it
to resist. See `agent-sandbox help security`.

A protected or isolated path (`.claude`, `.venv`, ...) that the host itself removes, renames or
replaces while the sandbox runs, as `poetry sync` does with `.venv`, loses its protection until the
sandbox restarts: the kernel drops the mount in the container. Starting a harness or running `exec`
then refuses and names the paths; sessions already running keep the access until the restart.

## Requirements

- Linux, Python 3.12+ (standard library only)
- Rootless docker or podman. Rootful docker is supported and tested too, but needs an explicit
  opt-in (`allow_rootful = true`, see `agent-sandbox help config`): its isolation is weaker,
  since root in the sandbox is root on the host.
- `git`; `setfacl` for rootless docker (`apt install acl`)

## Install

```bash
curl -fsSL https://raw.githubusercontent.com/jurca/agent-sandbox/main/install.sh | sh
```

clones the repository into `~/.agent-sandbox`, symlinks the launcher into `~/.local/bin` (adding it
to `PATH` in `~/.bashrc` if needed), installs the devcontainers CLI if it is missing, checks the
container engine and, for a rootful one, offers the `allow_rootful` opt-in. Run it again to update.

Or, from a checkout, symlink the launcher into your `PATH`:

```bash
ln -s "$PWD/agent-sandbox" ~/.local/bin/agent-sandbox
```

or install it as a tool: `uv tool install .`

## Usage

All documentation is built in:

```bash
agent-sandbox help
```

## Development

```bash
uv sync
uv run ruff check . && uv run ruff format --check . && uv run ty check
uv run pytest                  # unit tests
uv run pytest --integration    # also end-to-end tests against the local engine
```

The integration tests' requirements (a local base image, outbound HTTPS) are listed at the top
of `tests/test_integration.py`.

## License

GNU General Public License v3.0 or later (`GPL-3.0-or-later`); see [LICENSE](LICENSE).
