"""Workspace image (a user matching the host user) and proxy image."""

from __future__ import annotations

import hashlib
import os
import re
import tempfile
from dataclasses import dataclass
from pathlib import Path

from .engine import Engine, EngineError, labels_of
from .project import LABEL_BASE_ID, LABEL_KIND
from .proxy import SUPERVISOR_SH, proxy_dockerfile
from .util import SandboxError, eprint, slugify

LABEL_USER = "agent-sandbox.user"
_NAME = re.compile(r"[a-z_][a-z0-9_-]*$")

_PROBE = r"""
line=$(awk -F: -v u="$PROBE_UID" '$3==u {print $1":"$3":"$4":"$6":"$7; exit}' /etc/passwd)
echo "PASSWD $line"
home=$(awk -F: -v u="$PROBE_UID" '$3==u {print $6; exit}' /etc/passwd)
if [ -n "$home" ] && [ -d "$home" ]; then echo HOMEOK; fi
awk '{print "UIDMAP " $1 " " $2 " " $3}' /proc/self/uid_map
if [ -x /bin/bash ]; then echo HASBASH; fi
"""

_DERIVE = r"""
FROM {base}
USER root
ARG user_name
ARG group_name
ARG uid
ARG gid
ARG shell
RUN set -eu; \
    ensure_nl() {{ [ -z "$(tail -c1 "$1")" ] || echo >> "$1"; }}; \
    in_file() {{ awk -F: -v k="$3" -v c="$2" '$c==k {{f=1}} END {{exit !f}}' "$1"; }}; \
    if ! in_file /etc/group 3 "$gid"; then \
      if in_file /etc/group 1 "$group_name"; then \
        echo "group $group_name exists with a different gid" >&2; exit 1; fi; \
      ensure_nl /etc/group; echo "$group_name:x:$gid:" >> /etc/group; \
    fi; \
    if ! in_file /etc/passwd 3 "$uid"; then \
      if in_file /etc/passwd 1 "$user_name"; then \
        echo "user $user_name exists with a different uid" >&2; exit 1; fi; \
      ensure_nl /etc/passwd; \
      echo "$user_name:x:$uid:$gid::/home/$user_name:$shell" >> /etc/passwd; \
    fi; \
    home=$(awk -F: -v u="$uid" '$3==u {{print $6; exit}}' /etc/passwd); \
    mkdir -p "$home"; \
    if [ -d /etc/skel ] && [ -z "$(ls -A "$home")" ]; then cp -a /etc/skel/. "$home"/; fi; \
    chown -R "$uid:$gid" "$home"
"""


@dataclass(frozen=True)
class Probe:
    name: str | None
    gid: int | None
    home: str | None
    shell: str | None
    home_ok: bool
    has_bash: bool
    uid_map: tuple[tuple[int, int, int], ...]


@dataclass(frozen=True)
class UserImage:
    ref: str
    image_id: str
    base_id: str
    name: str
    uid: int
    gid: int
    home: str
    derived: bool
    uid_map: tuple[tuple[int, int, int], ...]


def parse_probe(output: str) -> Probe:
    name = gid = home = shell = None
    home_ok = has_bash = False
    uid_map: list[tuple[int, int, int]] = []
    for line in output.splitlines():
        if line.startswith("PASSWD "):
            fields = line[len("PASSWD ") :].split(":")
            if len(fields) >= 5 and fields[0]:
                name, gid, home, shell = fields[0], int(fields[2]), fields[3], fields[4]
        elif line == "HOMEOK":
            home_ok = True
        elif line == "HASBASH":
            has_bash = True
        elif line.startswith("UIDMAP "):
            inside, outside, count = (int(part) for part in line.split()[1:4])
            uid_map.append((inside, outside, count))
    return Probe(name, gid, home, shell, home_ok, has_bash, tuple(uid_map))


def host_uid_for(uid_map: tuple[tuple[int, int, int], ...], container_uid: int) -> int:
    """The host uid a container uid corresponds to (identity when the engine has no mapping)."""
    for inside, outside, count in uid_map:
        if inside <= container_uid < inside + count:
            return outside + (container_uid - inside)
    raise SandboxError(f"uid {container_uid} is not mapped inside the container user namespace.")


def probe_image(engine: Engine, ref: str, uid: int) -> Probe:
    result = engine.run(
        "run", "--rm", "--user", "0", "--network", "none", "--entrypoint", "/bin/sh",
        "--env", f"PROBE_UID={uid}", ref, "-c", _PROBE,
        check=False,
    )  # fmt: skip
    if result.returncode != 0:
        raise EngineError(
            f"Could not inspect {ref}: it needs /bin/sh and awk to be usable.\n"
            f"{result.stderr.strip()}"
        )
    return parse_probe(result.stdout)


def derived_tag(user: str, base_ref: str) -> str:
    ref, tag, suffix = base_ref, "latest", ""
    if "@" in ref:
        ref, digest = ref.split("@", 1)
        tag = suffix = f"sha256-{digest.split(':')[-1][:12]}"
    name, _, maybe_tag = ref.rpartition(":")
    if name and "/" not in maybe_tag:
        ref, tag = name, maybe_tag + (f"-{suffix}" if suffix else "")
    flat = re.sub(r"[^a-z0-9._-]+", "-", ref.lower()).strip("-.")
    return f"localhost/agent-sandbox/{slugify(user)}-{flat}:{tag}"


def render_user_dockerfile(base_ref: str) -> str:
    return _DERIVE.format(base=base_ref)


def proxy_build_args() -> list[str]:
    args: list[str] = []
    for name in ("HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "http_proxy", "https_proxy", "no_proxy"):
        if value := os.environ.get(name):
            args += ["--build-arg", f"{name}={value}"]
    return args


def ensure_user_image(
    engine: Engine,
    base_ref: str,
    *,
    user: str,
    uid: int,
    gid: int,
    group: str,
    rebuild: bool = False,
    pull: bool = False,
) -> UserImage:
    if uid == 0:
        raise SandboxError("Refusing to run as root: the sandbox user must not be root.")
    if not _NAME.match(user) or not _NAME.match(group):
        raise SandboxError(f"Cannot create user {user!r}/group {group!r} in an image: odd names.")
    if pull:
        engine.run("pull", base_ref, capture=False)
    base_id = engine.pull_if_missing(base_ref)
    probe = probe_image(engine, base_ref, uid)
    if probe.name and probe.home_ok and probe.home:
        return UserImage(
            base_ref, base_id, base_id, probe.name, uid, gid, probe.home, False, probe.uid_map
        )

    tag = derived_tag(user, base_ref)
    expected = f"{uid}:{gid}:{user}"
    info = engine.inspect("image", tag)
    labels = labels_of("image", info) if info else {}
    stale = (
        rebuild
        or info is None
        or labels.get(LABEL_BASE_ID) != base_id
        or labels.get(LABEL_USER) != expected
    )
    if stale:
        eprint(f"Building {tag} (adds user {user}, uid {uid}) ...")
        shell = "/bin/bash" if probe.has_bash else "/bin/sh"
        with tempfile.TemporaryDirectory() as context:
            engine.run(
                "build", "--tag", tag, "--file", "-",
                "--label", f"{LABEL_BASE_ID}={base_id}",
                "--label", f"{LABEL_USER}={expected}",
                "--label", f"{LABEL_KIND}=user",
                "--build-arg", f"user_name={user}",
                "--build-arg", f"group_name={group}",
                "--build-arg", f"uid={uid}",
                "--build-arg", f"gid={gid}",
                "--build-arg", f"shell={shell}",
                *proxy_build_args(),
                context,
                input=render_user_dockerfile(base_ref),
                capture=False,
            )  # fmt: skip
    image_id = engine.image_id(tag)
    if not image_id:
        raise EngineError(f"Image {tag} was not created.")
    derived = probe_image(engine, tag, uid)
    if not (derived.name and derived.home):
        raise EngineError(f"Image {tag} still has no user with uid {uid}.")
    return UserImage(
        tag, image_id, base_id, derived.name, uid, gid, derived.home, True, derived.uid_map
    )


def proxy_image_tag(base_ref: str) -> str:
    digest = hashlib.sha256((proxy_dockerfile(base_ref) + SUPERVISOR_SH).encode()).hexdigest()
    return f"localhost/agent-sandbox/tinyproxy:{digest[:12]}"


def ensure_proxy_image(engine: Engine, base_ref: str, *, rebuild: bool = False) -> str:
    tag = proxy_image_tag(base_ref)
    if not rebuild and engine.image_id(tag):
        return tag
    eprint(f"Building {tag} (tinyproxy on {base_ref}) ...")
    with tempfile.TemporaryDirectory() as context:
        (Path(context) / "supervisor.sh").write_text(SUPERVISOR_SH)
        (Path(context) / "Dockerfile").write_text(proxy_dockerfile(base_ref))
        args = ["build", "--tag", tag, "--label", f"{LABEL_KIND}=proxy", *proxy_build_args()]
        if rebuild:
            args += ["--pull", "--no-cache"]
        engine.run(*args, context, capture=False)
    return tag
