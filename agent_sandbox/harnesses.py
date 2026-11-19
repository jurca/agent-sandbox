"""`install-harness`: a helper in the workspace container that installs an agent harness."""

from __future__ import annotations

from .engine import Engine, EngineError
from .util import eprint

HELPER_DIR = "/usr/local/bin"
HELPER_NAME = "install-harness"

# Downloaded to a file first: with `curl | bash` a failed download (network still closed) would
# hand bash an empty script and look like success.
INSTALL_HARNESS_SH = r"""#!/bin/sh
# Installs an agent harness in this sandbox. Added by agent-sandbox on every start.
set -eu

for tool in curl bash; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "install-harness needs $tool, which this image lacks. Install it with" \
            "\`agent-sandbox root\` on the host (or in the image) and run this again." >&2
        exit 1
    fi
done

cat <<'EOF'
Which agent harness should be installed?
  [1] Claude Code         (curl -fsSL https://claude.ai/install.sh | bash)
  [2] GitHub Copilot CLI  (curl -fsSL https://gh.io/copilot-install | bash)
  [3] OpenCode            (curl -fsSL https://opencode.ai/v2/install | bash)
EOF
while :; do
    printf 'Enter 1, 2 or 3: '
    read -r choice || { echo; exit 1; }
    case $choice in
        1) name="Claude Code" url=https://claude.ai/install.sh extra_hosts="" ;;
        2) name="GitHub Copilot CLI" url=https://gh.io/copilot-install
           extra_hosts="raw.githubusercontent.com release-assets.githubusercontent.com" ;;
        3) name="OpenCode" url=https://opencode.ai/v2/install
           extra_hosts="registry.npmjs.org" ;;
        *) continue ;;
    esac
    break
done

# Whether an allowlist in the nearest .agent-sandbox/ (the workspace's, mounted read-only)
# lets the host through: same syntax as the proxy reads (`#` comments, `.domain` entries).
allowlisted() {
    dir=$PWD
    while [ ! -d "$dir/.agent-sandbox" ]; do
        [ "$dir" != / ] || return 1
        dir=$(dirname "$dir")
    done
    for list in allow.base allow.extra; do
        [ -f "$dir/.agent-sandbox/$list" ] || continue
        if awk -v host="$1" '
            { sub(/#.*/, ""); for (i = 1; i <= NF; i++) { e = tolower($i)
                if (e == host || (substr(e, 1, 1) == "." && (substr(e, 2) == host ||
                    substr(host, length(host) - length(e) + 1) == e))) found = 1 } }
            END { exit !found }' "$dir/.agent-sandbox/$list"; then
            return 0
        fi
    done
    return 1
}

# The installer's hosts (space-separated) that no allowlist lets through yet.
missing=""
for host in $extra_hosts; do
    allowlisted "$host" || missing="$missing $host"
done

echo
echo "The installer needs the network, which is closed by default. On the host, in this workspace:"
if [ -n "$missing" ]; then
    echo "  1. Add to .agent-sandbox/allow.extra:"
    for host in $missing; do
        echo "       $host"
    done
    echo "  2. Run \`agent-sandbox net 10m\` in another terminal (approve the changed"
    echo "     allow.extra when it asks)."
else
    echo "  Run \`agent-sandbox net 10m\` in another terminal."
fi

script=$(mktemp)
trap 'rm -f "$script"' EXIT
while :; do
    printf 'Press Enter once the network is open (Ctrl+C to cancel). '
    read -r _ || { echo; exit 1; }
    if curl -fsSL "$url" -o "$script"; then
        break
    fi
    echo "Downloading $url failed. Is the network open?"
done

echo "Installing $name ..."
bash "$script"
echo
echo "$name is installed. You can end the network session (\`agent-sandbox net --stop\`)" \
    "unless you need it for something else."
"""


def add_helper(engine: Engine, container: str) -> None:
    """Copy `install-harness` into the container (also a stopped one), owned by root.

    Only warns on failure: the sandbox works without it (an image without /usr/local/bin).
    """
    try:
        engine.copy_in(
            container, HELPER_DIR, {HELPER_NAME: INSTALL_HARNESS_SH}, uid=0, gid=0, mode=0o755
        )
    except EngineError as exc:
        eprint(f"warning: {HELPER_NAME} could not be added to the sandbox: {exc}")
