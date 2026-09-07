#!/usr/bin/env bash

set -euo pipefail

usage() {
  cat <<'EOF'
Usage: create-agent-sandbox-container.sh [--engine docker|podman] [--allow-rootful] IMAGE CONTAINER USER

Creates a rootless Docker or Podman workspace container configured for the
VS Code and Claude Code agent terminal sandboxes.
EOF
}

die() {
  printf 'Error: %s\n' "$*" >&2
  exit 1
}

engine=""
allow_rootful=false

while (($#)); do
  case "$1" in
    --engine)
      (($# >= 2)) || die '--engine requires docker or podman'
      engine="$2"
      shift 2
      ;;
    --allow-rootful)
      allow_rootful=true
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    --*)
      die "unknown option: $1"
      ;;
    *)
      break
      ;;
  esac
done

(($# == 3)) || {
  usage >&2
  exit 2
}

image="$1"
container="$2"
user="$3"
script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
socket_script="$script_dir/list-unix-sockets.sh"

[[ -f "$socket_script" ]] || die "missing companion script: $socket_script"

if [[ -z "$engine" ]]; then
  if command -v podman >/dev/null 2>&1; then
    engine=podman
  elif command -v docker >/dev/null 2>&1; then
    engine=docker
  else
    die 'neither podman nor docker is available'
  fi
fi

[[ "$engine" == docker || "$engine" == podman ]] || die '--engine must be docker or podman'
command -v "$engine" >/dev/null 2>&1 || die "$engine is not available"
"$engine" info >/dev/null 2>&1 || die "$engine is not usable by the current user"

case "$engine" in
  podman)
    rootless="$($engine info --format '{{.Host.Security.Rootless}}')"
    ;;
  docker)
    security_options="$($engine info --format '{{json .SecurityOptions}}')"
    if [[ "$security_options" == *'name=rootless'* ]]; then
      rootless=true
    else
      rootless=false
    fi
    ;;
esac

if [[ "$rootless" != true && "$allow_rootful" != true ]]; then
  die "$engine is rootful; rerun with --allow-rootful to override"
fi

if ! "$engine" image inspect "$image" >/dev/null 2>&1; then
  printf 'Image %q does not exist. Available images:\n' "$image" >&2
  "$engine" image ls --format '{{.Repository}}:{{.Tag}}' >&2
  exit 1
fi

if "$engine" container inspect "$container" >/dev/null 2>&1; then
  die "container already exists: $container"
fi

user_record="$($engine run --rm --user 0 --entrypoint /bin/sh --env TARGET_USER="$user" "$image" -ec '
  entry=$(awk -F: -v name="$TARGET_USER" '\''$1 == name { print; exit}'\'' /etc/passwd)
  [ -n "$entry" ] || exit 10
  IFS=: read -r name _ uid gid _ home _ <<EOF
$entry
EOF
  case "$uid" in (""|*[!0-9]*) exit 11;; esac
  [ "$uid" -ge 1000 ] && [ "$uid" -ne 0 ] || exit 11
  [ -n "$home" ] && [ -d "$home" ] || exit 12
  printf "%s:%s:%s\n" "$uid" "$gid" "$home"
')" || {
  status=$?
  if [[ $status -eq 10 ]]; then
    printf 'User %q is not defined. Available non-root users:\n' "$user" >&2
    "$engine" run --rm --user 0 --entrypoint /bin/sh "$image" -ec \
      'awk -F: '\''$3 >= 1000 && $3 != 0 && $6 ~ /^\// && $6 != "" { print $1}'\'' /etc/passwd' >&2
  elif [[ $status -eq 12 ]]; then
    printf 'User %q has no existing home directory.\n' "$user" >&2
  else
    printf 'User %q is not eligible: it must be non-root with UID >= 1000.\n' "$user" >&2
  fi
  exit 1
}

IFS=: read -r uid gid home <<<"$user_record"
printf 'Creating %s container %q as %s (UID %s, home %s).\n' "$engine" "$container" "$user" "$uid" "$home"

"$engine" run -d \
  --name "$container" \
  --user "$user" \
  --restart unless-stopped \
  --security-opt seccomp=unconfined \
  --security-opt apparmor=unconfined \
  --entrypoint sleep \
  "$image" infinity >/dev/null

cleanup_on_error() {
  printf 'Setup failed; removing incomplete container %q.\n' "$container" >&2
  "$engine" rm -f "$container" >/dev/null 2>&1 || true
}
trap cleanup_on_error ERR

"$engine" exec --user 0 "$container" /bin/sh -ec \
  'export DEBIAN_FRONTEND=noninteractive; apt-get update && apt-get install -y bubblewrap socat'

if ! "$engine" exec --user 0 "$container" /bin/sh -ec 'command -v python3 >/dev/null'; then
  "$engine" exec --user 0 "$container" /bin/sh -ec \
    'export DEBIAN_FRONTEND=noninteractive; apt-get install -y python3'
fi

"$engine" exec --user "$user" "$container" mkdir -p "$home/.vscode-server/data/Machine" "$home/.claude"

cat configure_agent_harnesses.py | "$engine" exec -i --user 0 "$container" python3 - "$home/.vscode-server/data/Machine/settings.json" "$home/.claude/settings.json" "$uid" "$gid"

"$engine" cp "$socket_script" "$container:/usr/bin/list-unix-sockets"
"$engine" exec --user 0 "$container" chmod 0755 /usr/bin/list-unix-sockets

trap - ERR
printf 'Container %q is ready. Connect VS Code to it as user %q.\n' "$container" "$user"
