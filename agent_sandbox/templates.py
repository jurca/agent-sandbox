"""Files written by `agent-sandbox init`."""

from __future__ import annotations

CONFIG_TOML = """\
# agent-sandbox configuration. It is committed with the repository; after any change the
# host asks you to approve it before it takes effect (see `agent-sandbox help config`).

# Command lines tried in order by a plain `agent-sandbox`: the first one installed in the
# container is started (a shell if none is). A single string works too. Each person can put
# their preferred harnesses first in the user configuration (see `agent-sandbox help config`).
harness = ["claude", "copilot", "bash", "sh"]

image = "{image}"

# Instead of `image`: build the base from the project's devcontainer (remove `image` above).
# [devcontainer]
# enabled = true
# config = ".devcontainer/devcontainer.json"

[env]
# Host variables passed into the container when they are set on the host.
pass = ["TERM", "COLORTERM", "LANG", "LC_ALL", "TZ"]
# pass = ["TERM", "COLORTERM", "LANG", "LC_ALL", "TZ", "CLAUDE_CODE_OAUTH_TOKEN"]

[env.set]
# `{{home}}` expands to the container user's home directory.
CLAUDE_CONFIG_DIR = "{{home}}/.claude"
CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC = "1"

[workspace]
# Read-only inside the sandbox: configuration that tools on the host execute or trust.
# A missing path is created as an empty directory, so the agent cannot create it either.
protected = [".claude", ".agents", ".vscode", ".idea", ".devcontainer"]
# Replaced by a volume of this workspace: the sandbox builds its own copy (virtualenv,
# node_modules) and never writes the one the host runs.
isolated = [".venv", "node_modules"]
# Secret files (.env, .env.*, *.env by default) may only be symlinks out of the workspace, ignored
# by a committed .gitignore; `agent-sandbox secrets adopt` moves real ones. See `help security`.
# secrets = ["*.secret"]             # more file names, on top of the defaults
# secrets_except = [".env.test"]     # exact names holding no secrets, on top of .env.example,
#                                    # .env.sample and .env.template
# secrets_history_depth = 200        # also search this many newest commits when creating

[state]
# Directories below the container user's home that survive `rm` and `recreate`.
paths = [".claude", ".copilot", ".cache/pre-commit"]

# Extra read-only bind mounts. The source must exist and must not contain unix sockets.
# `~` in source is your home directory; `~` in target is the container user's home.
# [[mounts]]
# source = "~/.config/pypoetry"
# target = "~/.config/pypoetry"
# [[mounts]]
# source = "~/.agents/skills"
# Real secret files (see [workspace] secrets) in a mount stop the sandbox from starting. The
# check reads at most 50000 entries; turn it off for a mount that cannot hold any:
# [[mounts]]
# source = "/data/datasets"
# check_secrets = false

# [proxy]
# base_image = "docker.ops.corp.example/upstream/alpine:3"

# Commands that prepare the container (see `agent-sandbox help setup`). `create` runs once per
# container before the first harness start, with the hosts in allow.extra reachable; `start`
# runs once per container start.
# [setup]
# create = ["uv sync", ".venv/bin/pre-commit install-hooks"]
# start = []
"""

TINYPROXY_CONF = """\
# Static tinyproxy settings. agent-sandbox generates the port, client ACL, logging,
# filtering and upstream directives itself; hosts belong in allow.base / allow.extra.
Timeout 600
MaxClients 100
DisableViaHeader Yes
ConnectPort 443
"""

ALLOW_BASE = """\
# Hosts the sandbox can always reach (model APIs and login). One per line.
#   example.com     matches exactly that host
#   .example.com    matches the host and every subdomain
# Remove the sections for harnesses you do not use.

# Claude Code
api.anthropic.com
claude.ai
platform.claude.com
# Optional:
#   downloads.claude.ai       updates and plugin downloads
#   mcp-proxy.anthropic.com   claude.ai MCP connectors
#   registry.npmjs.org        plugin installs

# GitHub Copilot CLI
github.com
api.github.com
.githubcopilot.com
# Optional:
#   copilot-proxy.githubusercontent.com
#   origin-tracker.githubusercontent.com
#   copilot-telemetry.githubusercontent.com
#   collector.github.com
#   default.exp-tas.com
"""

ALLOW_EXTRA = """\
# Hosts that are only reachable while `agent-sandbox net` is running (package registries,
# documentation, internal services). Same syntax as allow.base. Examples:
# pypi.org
# files.pythonhosted.org
# registry.npmjs.org
"""


def render_config(image: str) -> str:
    return CONFIG_TOML.format(image=image.replace("\\", "\\\\").replace('"', '\\"'))
