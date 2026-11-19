#!/bin/sh
# Install agent-sandbox for the current user:
#
#   curl -fsSL https://raw.githubusercontent.com/jurca/agent-sandbox/main/install.sh | sh
#   wget -qO- https://raw.githubusercontent.com/jurca/agent-sandbox/main/install.sh | sh
#
# Clones the repository into ~/.agent-sandbox (or updates it), symlinks the launcher into
# ~/.local/bin, installs the devcontainers CLI if it is missing and checks the container engine.
# Running it again updates the checkout and changes nothing that is already set up.

# Everything is in functions called on the last line, so a truncated download runs nothing.

set -eu

REPO_URL="https://github.com/jurca/agent-sandbox.git"
CHECKOUT="$HOME/.agent-sandbox"
BIN_DIR="$HOME/.local/bin"
BASHRC="$HOME/.bashrc"
DEVCONTAINER_INSTALLER="https://raw.githubusercontent.com/devcontainers/cli/main/scripts/install.sh"
DEVCONTAINER_BIN="$HOME/.devcontainers/bin"
CONFIG_DIR="${AGENT_SANDBOX_CONFIG_DIR:-${XDG_CONFIG_HOME:-$HOME/.config}/agent-sandbox}"

RESTART_TERMINAL=""
RELOGIN=""
TODO=""

if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
    BOLD=$(printf '\033[1m') YELLOW=$(printf '\033[33m') RED=$(printf '\033[31m')
    RESET=$(printf '\033[0m')
else
    BOLD="" YELLOW="" RED="" RESET=""
fi

say() { printf '%s> %s%s\n' "$BOLD" "$1" "$RESET"; }
warn() { printf '%swarning:%s %s\n' "$YELLOW" "$RESET" "$1" >&2; }
die() {
    printf '%serror:%s %s\n' "$RED" "$RESET" "$1" >&2
    exit 1
}
todo() { TODO="$TODO
  - $1"; }

# The script itself arrives on stdin under `curl | sh`, so questions go to the terminal.
ask_yes_no() {
    if ! (: </dev/tty) 2>/dev/null; then
        return 1
    fi
    printf '%s [y/N] ' "$1" >/dev/tty
    read -r answer </dev/tty || answer=""
    case "$answer" in
        [yY] | [yY][eE][sS]) return 0 ;;
        *) return 1 ;;
    esac
}

on_path() {
    case ":$2:" in
        *":$1:"*) return 0 ;;
        *) return 1 ;;
    esac
}

# Append a line to ~/.bashrc unless it is there already (from an earlier run).
add_to_bashrc() {
    RESTART_TERMINAL=1
    if [ -f "$BASHRC" ] && grep -qxF "$1" "$BASHRC"; then
        return
    fi
    printf '\n# Added by the agent-sandbox installer\n%s\n' "$1" >>"$BASHRC"
    say "Added to $BASHRC: $1"
}

check_requirements() {
    [ "$(uname -s)" = "Linux" ] || die "agent-sandbox runs on Linux only."
    command -v git >/dev/null 2>&1 || die "git is required; install it and run this again."
    if ! command -v python3 >/dev/null 2>&1; then
        todo "Install Python 3.12 or newer (python3)."
    elif ! python3 -c 'import sys; sys.exit(sys.version_info < (3, 12))'; then
        todo "Install Python 3.12 or newer (python3 is $(python3 -c 'import platform; print(platform.python_version())'))."
    fi
}

install_checkout() {
    if [ -d "$CHECKOUT/.git" ]; then
        origin=$(git -C "$CHECKOUT" remote get-url origin 2>/dev/null || true)
        case "$origin" in
            "$REPO_URL" | "${REPO_URL%.git}") ;;
            *) die "$CHECKOUT is a git checkout of ${origin:-an unknown origin}, not $REPO_URL." ;;
        esac
        say "Updating $CHECKOUT"
        if ! git -C "$CHECKOUT" pull --ff-only --quiet; then
            warn "Could not update $CHECKOUT (local changes?); using it as it is."
        fi
    elif [ -e "$CHECKOUT" ]; then
        die "$CHECKOUT exists and is not a git checkout; move it away and run this again."
    else
        say "Cloning $REPO_URL into $CHECKOUT"
        git clone --quiet "$REPO_URL" "$CHECKOUT"
    fi
}

install_launcher() {
    if [ ! -d "$BIN_DIR" ]; then
        say "Creating $BIN_DIR"
        mkdir -p "$BIN_DIR"
    fi
    link="$BIN_DIR/agent-sandbox"
    if [ -e "$link" ] && [ ! -L "$link" ]; then
        die "$link exists and is not a symlink; remove it and run this again."
    fi
    ln -sfn "$CHECKOUT/agent-sandbox" "$link"
    say "Linked $link -> $CHECKOUT/agent-sandbox"
}

# ~/.local/bin is often added by ~/.profile, but only if it existed at login, which it may
# not have before this script created it. Then a new login is enough and ~/.bashrc stays as is.
check_path() {
    if on_path "$BIN_DIR" "$PATH"; then
        return
    fi
    profile_path=""
    if [ -f "$HOME/.profile" ]; then
        # In a fresh shell: ~/.profile is not written for `set -eu`.
        profile_path=$(sh -c '. "$HOME/.profile" >/dev/null 2>&1 </dev/null; printf "%s" "$PATH"' \
            2>/dev/null) || true
    fi
    if on_path "$BIN_DIR" "$profile_path"; then
        warn "$BIN_DIR is not in your PATH yet: ~/.profile adds it, but it did not exist when you logged in."
        RELOGIN=1
    else
        warn "$BIN_DIR is not in your PATH."
        add_to_bashrc 'export PATH="$HOME/.local/bin:$PATH"'
    fi
}

install_devcontainer_cli() {
    if command -v devcontainer >/dev/null 2>&1; then
        return
    fi
    if [ ! -x "$DEVCONTAINER_BIN/devcontainer" ]; then
        say "Installing the devcontainers CLI into ${DEVCONTAINER_BIN%/bin}"
        if command -v curl >/dev/null 2>&1; then
            curl -fsSL "$DEVCONTAINER_INSTALLER" | sh
        elif command -v wget >/dev/null 2>&1; then
            wget -qO- "$DEVCONTAINER_INSTALLER" | sh
        else
            warn "Neither curl nor wget found; skipping the devcontainers CLI."
            todo "Install the devcontainers CLI: $DEVCONTAINER_INSTALLER"
            return
        fi
    fi
    if ! on_path "$DEVCONTAINER_BIN" "$PATH"; then
        add_to_bashrc 'export PATH="$HOME/.devcontainers/bin:$PATH"'
    fi
}

# Mirrors the engine detection of agent-sandbox: podman first, then docker; the first one that
# answers `info` is used.
check_engine() {
    engine="" rootless=""
    for kind in podman docker; do
        command -v "$kind" >/dev/null 2>&1 || continue
        if [ "$kind" = podman ]; then
            info=$(podman info --format '{{.Host.Security.Rootless}}' 2>&1) || {
                warn "podman is installed but \`podman info\` failed: $info"
                continue
            }
            if [ "$info" = true ]; then rootless=1; fi
        else
            info=$(docker info --format '{{json .SecurityOptions}}' 2>&1) || {
                warn "docker is installed but \`docker info\` failed: $info"
                continue
            }
            case "$info" in *rootless*) rootless=1 ;; esac
        fi
        engine=$kind
        break
    done

    if [ -z "$engine" ]; then
        todo "Install a container engine: rootless docker or podman (https://docs.docker.com/engine/security/rootless/, https://podman.io/docs/installation)."
        return
    fi
    if [ -n "$rootless" ]; then
        say "Found $engine (rootless)"
        if [ "$engine" = docker ] && ! command -v setfacl >/dev/null 2>&1; then
            todo "Install setfacl, which rootless docker needs (apt install acl)."
        fi
        return
    fi

    say "Found $engine (rootful)"
    config="$CONFIG_DIR/config.toml"
    if [ -f "$config" ] && grep -q '^[[:space:]]*allow_rootful[[:space:]]*=' "$config"; then
        say "$config already sets allow_rootful"
        return
    fi
    warn "$engine runs rootful: root inside the sandbox is root on this host, so its isolation is weaker. agent-sandbox refuses rootful engines unless you opt in."
    if ask_yes_no "Add \`allow_rootful = true\` to $config?"; then
        # A top-level key must come before the first table, so it goes first.
        tmp="$config.tmp.$$"
        {
            printf 'allow_rootful = true\n'
            if [ -f "$config" ]; then cat "$config"; fi
        } >"$tmp"
        mv "$tmp" "$config"
        say "Added allow_rootful = true to $config"
    else
        todo "Use rootless docker or podman, or set \`allow_rootful = true\` in $config."
    fi
}

main() {
    check_requirements
    install_checkout
    install_launcher
    check_path
    install_devcontainer_cli
    mkdir -p "$CONFIG_DIR"
    check_engine

    printf '\n%sagent-sandbox is installed.%s\n' "$BOLD" "$RESET"
    if [ -n "$TODO" ]; then
        printf '\nStill to do:%s\n' "$TODO"
    fi
    if [ -n "$RELOGIN" ]; then
        printf '\n%sLog out and back in%s (or run `. ~/.profile` in this terminal) to get %s into your PATH.\n' \
            "$YELLOW" "$RESET" "$BIN_DIR"
    elif [ -n "$RESTART_TERMINAL" ]; then
        printf '\n%sRestart your terminal%s (or run `. ~/.bashrc`) for the PATH entries in %s to take effect.\n' \
            "$YELLOW" "$RESET" "$BASHRC"
        case "${SHELL:-}" in
            */bash | "") ;;
            *) warn "Your shell is ${SHELL##*/}, which does not read ~/.bashrc; add the same PATH entries to its startup file." ;;
        esac
    fi
    printf '\nThen, in a project workspace, run `agent-sandbox` to start, or `agent-sandbox init`\nto set the project up first. `agent-sandbox help` has the documentation.\n'
}

main "$@"
