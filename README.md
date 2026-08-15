# VS Code Agent Sandbox Container

This project creates a rootless Docker or Podman workspace container prepared
for VS Code's agent terminal sandbox on Linux.

The configuration addresses a nested-sandbox limitation common in containers:
the outer container needs relaxed `seccomp` and AppArmor profiles so Bubblewrap
can construct the inner sandbox. The inner VS Code sandbox then limits agent
commands to the workspace and configured filesystem paths.

## Requirements

- Docker or Podman, usable by the current host user
- A rootless container engine by default
- A Debian or Ubuntu based image with `apt-get`
- A non-root user in the image with UID 1000 or greater and an existing home
  directory

The setup script rejects rootful engines unless `--allow-rootful` is supplied.
Use that override only when you understand the additional host-level risk.

## Create A Container

Run the host-side setup script from this directory:

```bash
./create-vscode-sandbox-container.sh IMAGE CONTAINER USER
```

For example:

```bash
./create-vscode-sandbox-container.sh mcr.microsoft.com/vscode/devcontainers/python vscode-sandbox vscode
```

Options:

```text
--engine docker|podman  Select an engine instead of the automatic choice.
--allow-rootful         Permit a rootful engine.
```

The script checks the engine, image, requested account, and container name. It
then creates a long-running `sleep infinity` container with restart policy
`unless-stopped`, installs `bubblewrap` and `socat`, and installs the socket
diagnostic as `/usr/bin/list-unix-sockets`.

It also writes these remote-machine settings under the chosen user's
`~/.vscode-server/data/Machine/settings.json`:

```json
{
  "chat.agent.sandbox.enabled": "on",
  "chat.agent.sandbox.advanced.runtime": {
    "enableWeakerNestedSandbox": true,
    "network": {
      "allowAllUnixSockets": true
    }
  },
  "chat.agent.sandbox.fileSystem.linux": {
    "denyRead": ["/tmp"],
    "denyWrite": ["/tmp"]
  }
}
```

Connect VS Code to the created container as the specified user. The setup
script merges these keys into an existing settings file rather than replacing
unrelated settings.

## Why The Configuration Is Needed

`bubblewrap` creates the filesystem sandbox used by VS Code's agent terminal.
Inside an already restricted container, its normal nested namespace setup can
fail when mounting `/proc` or when the optional seccomp helper writes
`/proc/self/setgroups`.

The container's unconfined `seccomp` and AppArmor settings allow the nested
Bubblewrap sandbox to initialize. `enableWeakerNestedSandbox` avoids the
nested `/proc` mount. `network.allowAllUnixSockets` disables the optional
second seccomp stage that is incompatible with this nested setup.

## Security: Check Socket Exposure

`network.allowAllUnixSockets` has an important security consequence: it can
allow agent commands to access Unix-domain sockets visible through the sandbox
filesystem. Sockets may provide access to credentials, desktop services, Git,
SSH agents, or other host/container capabilities.

The configured `/tmp` read/write denial is intended to hide common VS Code,
Git, SSH, MCP, and X11 sockets. This is a policy, not a substitute for checking
the actual runtime view.

After connecting with VS Code, run this command **using the agent's sandboxed
terminal**, not an ordinary integrated terminal:

```bash
list-unix-sockets
```

Expected output has the two headings and no entries:

```text
Filesystem Unix sockets:

Abstract-namespace Unix sockets:
```

If it lists any socket, treat that as a security gap. Identify the mount or
runtime path exposing it and add an appropriate
`chat.agent.sandbox.fileSystem.linux` deny rule before relying on the sandbox
with sensitive credentials or services available.

The source diagnostic, [list-unix-sockets.sh](list-unix-sockets.sh), searches
`$HOME`, `/tmp`, `/var/run`, `/run`, and `/dev/shm` for filesystem sockets and
uses `/proc/net/unix` for abstract-namespace sockets.

## Limits

This project configures the VS Code agent terminal sandbox; it does not make a
general-purpose container a security boundary. Review image contents, mounted
volumes, environment variables, device access, and engine-specific policy for
your use case.
