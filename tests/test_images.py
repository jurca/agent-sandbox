from __future__ import annotations

import pytest

from agent_sandbox import images
from agent_sandbox.images import Probe, derived_tag, host_uid_for, parse_probe, parse_uid_map
from agent_sandbox.util import SandboxError

DIGEST = "sha256:" + "ab12" * 16


@pytest.mark.parametrize(
    ("base", "tag"),
    [
        ("alpine", "localhost/agent-sandbox/martin-alpine:latest"),
        ("alpine:3", "localhost/agent-sandbox/martin-alpine:3"),
        ("docker.ops.corp.example/upstream/alpine:3.20",
         "localhost/agent-sandbox/martin-docker.ops.corp.example-upstream-alpine:3.20"),
        ("registry:5000/team/img", "localhost/agent-sandbox/martin-registry-5000-team-img:latest"),
        ("registry:5000/img:v1", "localhost/agent-sandbox/martin-registry-5000-img:v1"),
        (f"alpine@{DIGEST}", "localhost/agent-sandbox/martin-alpine:sha256-ab12ab12ab12"),
        (f"alpine:3@{DIGEST}", "localhost/agent-sandbox/martin-alpine:3-sha256-ab12ab12ab12"),
        ("Mixed/Case:Tag", "localhost/agent-sandbox/martin-mixed-case:Tag"),
    ],
)  # fmt: skip
def test_derived_tag(base: str, tag: str) -> None:
    assert derived_tag("martin", base) == tag


def test_derived_tag_distinguishes_digests_of_the_same_tag() -> None:
    other = "sha256:" + "cd34" * 16
    assert derived_tag("u", f"img:1@{DIGEST}") != derived_tag("u", f"img:1@{other}")
    assert derived_tag("u", f"img:1@{DIGEST}") != derived_tag("u", "img:1")


def test_parse_probe_existing_user() -> None:
    output = (
        "PASSWD vscode:1000:1000:/home/vscode:/bin/bash\nHOMEOK\n"
        "UIDMAP 0 1000 1\nUIDMAP 1 100000 65536\nHASBASH\n"
    )
    assert parse_probe(output) == Probe(
        name="vscode", gid=1000, home="/home/vscode", shell="/bin/bash", home_ok=True,
        has_bash=True, uid_map=((0, 1000, 1), (1, 100000, 65536)),
    )  # fmt: skip


def test_parse_probe_missing_user() -> None:
    probe = parse_probe("PASSWD \nUIDMAP 0 0 4294967295\n")
    assert probe.name is None and not probe.home_ok and not probe.has_bash
    assert probe.uid_map == ((0, 0, 4294967295),)


def test_host_uid_for_rootless_docker() -> None:
    uid_map = ((0, 1000, 1), (1, 100000, 65536))
    assert host_uid_for(uid_map, 0) == 1000
    assert host_uid_for(uid_map, 1000) == 100999
    assert host_uid_for(uid_map, 1) == 100000
    with pytest.raises(SandboxError):
        host_uid_for(uid_map, 65537)


def test_parse_uid_map() -> None:
    text = "         0       1000          1\n         1     100000      65536\n\n"
    assert parse_uid_map(text) == ((0, 1000, 1), (1, 100000, 65536))
    assert parse_uid_map("") == ()


def test_host_uid_for_identity_and_keep_id() -> None:
    assert host_uid_for(((0, 0, 4294967295),), 1000) == 1000
    keep_id = ((0, 1, 1000), (1000, 0, 1), (1001, 1001, 64536))
    assert host_uid_for(keep_id, 1000) == 0


def test_user_dockerfile_uses_base_and_appends_passwd() -> None:
    text = images.render_user_dockerfile("alpine:3")
    assert text.lstrip().startswith("FROM alpine:3\n")
    assert ">> /etc/passwd" in text and ">> /etc/group" in text
    assert "useradd" not in text and "adduser" not in text


def test_project_tag_keeps_the_whole_id() -> None:
    project_id = "a-very-long-project-directory-name-indeed-x-1a2b3c4d"
    assert images.project_tag("Martin", project_id, "extended", "abc") == (
        f"localhost/agent-sandbox/martin-{project_id}-extended:abc"
    )


def test_proxy_image_tag_depends_on_base() -> None:
    a, b = images.proxy_image_tag("alpine:3"), images.proxy_image_tag("mirror/alpine:3")
    assert a != b and a == images.proxy_image_tag("alpine:3")
    assert a.startswith("localhost/agent-sandbox/tinyproxy:")


def test_proxy_build_args(monkeypatch: pytest.MonkeyPatch) -> None:
    assert images.proxy_build_args() == []
    monkeypatch.setenv("HTTPS_PROXY", "http://p:3128")
    assert images.proxy_build_args() == ["--build-arg", "HTTPS_PROXY=http://p:3128"]


def test_ensure_user_image_refuses_root_and_odd_names() -> None:
    engine = images.Engine("docker", rootless=True)
    with pytest.raises(SandboxError, match="root"):
        images.ensure_user_image(engine, "x", user="root", uid=0, gid=0, group="root")
    with pytest.raises(SandboxError, match="odd names"):
        images.ensure_user_image(engine, "x", user="Bad User", uid=1000, gid=1000, group="g")


def test_ensure_user_image_refuses_odd_remote_user() -> None:
    engine = images.Engine("docker", rootless=True)
    with pytest.raises(SandboxError, match="odd name"):
        images.ensure_user_image(
            engine, "b", user="dev", uid=1000, gid=1000, group="dev", remote_user="Bad Name"
        )
