#!/usr/bin/env bash

set -euo pipefail

search_roots=(
  "$HOME"
  /tmp
  /var/run
  /run
  /dev/shm
)

printf 'Filesystem Unix sockets:\n'
for root in "${search_roots[@]}"; do
  if [[ -d "$root" ]]; then
    find "$root" -xdev -type s -printf '%p\n' 2>/dev/null
  fi
done | sort -u

printf '\nAbstract-namespace Unix sockets:\n'
awk 'NR > 1 && $8 ~ /^@/ { print $8 }' /proc/net/unix | sort -u
