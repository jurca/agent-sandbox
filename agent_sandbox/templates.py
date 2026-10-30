"""Files written by `agent-sandbox init`."""

from __future__ import annotations

CONFIG_TOML = """\
# agent-sandbox configuration. It is committed with the repository; after any change the
# host asks you to approve it before it takes effect (see `agent-sandbox help config`).

image = "{image}"

# Command line started by a plain `agent-sandbox`; a shell is started if it is not installed.
# harness = "claude"
# harness = "copilot"
harness = "bash"

[env]
# Host variables passed into the container when they are set on the host.
pass = ["TERM", "COLORTERM", "LANG", "LC_ALL", "TZ"]
# pass = ["TERM", "COLORTERM", "LANG", "LC_ALL", "TZ", "CLAUDE_CODE_OAUTH_TOKEN"]

[env.set]
# `{{home}}` expands to the container user's home directory.
CLAUDE_CONFIG_DIR = "{{home}}/.claude"
CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC = "1"

[state]
# Directories below the container user's home that survive `rm` and `recreate`.
paths = [".claude", ".copilot"]

# Extra read-only bind mounts. The source must exist and must not contain unix sockets.
# [[mounts]]
# source = "/ceph"
# target = "/ceph"

# [proxy]
# base_image = "docker.ops.corp.example/upstream/alpine:3"
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
