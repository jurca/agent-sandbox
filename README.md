# agent-sandbox

Per-workspace containers for AI agent harnesses (Claude Code, Copilot CLI), with the workspace
bind-mounted, `.git` read-only and network access only through an allowlisting proxy.

## Requirements

- Linux, Python 3.12+ (standard library only)
- Rootless docker or podman (rootful engines need an explicit opt-in)
- `git`; `setfacl` for rootless docker (`apt install acl`)

## Install

Either symlink the launcher into your `PATH`:

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
