from __future__ import annotations

import io
import tarfile

import pytest

from agent_sandbox import engine as engine_mod
from agent_sandbox.config import UserConfig
from agent_sandbox.engine import Engine, EngineError, detect_engine, labels_of

from .fakes import FakeEngine, done


def test_base_cmd_context_only_for_docker() -> None:
    assert Engine("docker", rootless=True, context="rl").base_cmd() == ["docker", "--context", "rl"]
    assert Engine("podman", rootless=True, context="rl").base_cmd() == ["podman"]
    assert Engine("podman", rootless=False).mode == "podman (rootful)"


def test_labels_of() -> None:
    assert labels_of("container", {"Config": {"Labels": {"a": "1"}}}) == {"a": "1"}
    assert labels_of("image", {"Config": {"Labels": None}, "Labels": {"b": "2"}}) == {"b": "2"}
    assert labels_of("network", {"Labels": {"c": "3"}}) == {"c": "3"}
    assert labels_of("volume", {"Labels": None}) == {}


def test_network_subnet_docker_and_podman() -> None:
    fake = FakeEngine()
    fake.add("network", "d", {}, IPAM={"Config": [{"Subnet": "172.18.0.0/16"}]})
    fake.add("network", "p", {}, subnets=[{"subnet": "10.89.0.0/24", "gateway": "10.89.0.1"}])
    fake.add("network", "none", {}, IPAM={"Config": None})
    assert fake.network_subnet("d") == "172.18.0.0/16"
    assert fake.network_subnet("p") == "10.89.0.0/24"
    assert fake.network_subnet("none") is None
    assert fake.network_subnet("missing") is None


def test_image_id_and_status() -> None:
    fake = FakeEngine()
    fake.on(("image", "inspect"), lambda args: "sha256:x\n" if args[-1] == "a" else 1)
    assert fake.image_id("a") == "sha256:x"
    assert fake.image_id("b") is None
    fake.add("container", "c", {}, State={"Status": "exited"})
    assert fake.container_status("c") == "exited"
    assert fake.container_status("nope") is None


def test_run_raises_with_detail() -> None:
    real = Engine("definitely-not-an-engine-binary", rootless=True)
    with pytest.raises(EngineError, match="not installed"):
        real.run("info")


def _patch_probe(monkeypatch: pytest.MonkeyPatch, outputs: dict[str, str | None]) -> None:
    monkeypatch.setattr(
        engine_mod.shutil, "which", lambda name: f"/usr/bin/{name}" if name in outputs else None
    )

    def run(self: Engine, *args: str, **_kwargs: object):
        out = outputs[self.kind]
        return done(args, out or "", 0 if out is not None else 1)

    monkeypatch.setattr(Engine, "run", run)


def test_probe_rootless_docker(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_probe(monkeypatch, {"docker": '["name=seccomp,profile=builtin","name=rootless"]'})
    found = detect_engine(UserConfig())
    assert (found.kind, found.rootless) == ("docker", True)


def test_probe_prefers_podman(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_probe(monkeypatch, {"podman": "true\n", "docker": '["name=rootless"]'})
    assert detect_engine(UserConfig()).kind == "podman"
    assert detect_engine(UserConfig(engine="docker")).kind == "docker"
    assert [e.kind for e in engine_mod.probe_engines(UserConfig())] == ["podman", "docker"]


def test_unusable_engine_is_skipped(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_probe(monkeypatch, {"podman": None, "docker": '["name=rootless"]'})
    assert detect_engine(UserConfig()).kind == "docker"
    _patch_probe(monkeypatch, {})
    with pytest.raises(EngineError, match="No usable container engine"):
        detect_engine(UserConfig())


def test_rootful_needs_opt_in(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_probe(monkeypatch, {"docker": '["name=seccomp,profile=builtin"]'})
    monkeypatch.delenv(engine_mod.ENGINE_ENV_ROOTFUL, raising=False)
    with pytest.raises(EngineError, match="allow_rootful"):
        detect_engine(UserConfig())
    assert not detect_engine(UserConfig(allow_rootful=True)).rootless
    monkeypatch.setenv(engine_mod.ENGINE_ENV_ROOTFUL, "1")
    assert not detect_engine(UserConfig()).rootless
    _patch_probe(monkeypatch, {"podman": "false\n"})
    assert detect_engine(UserConfig()).kind == "podman"


def test_tar_archive_sets_owner_and_mode() -> None:
    data = engine_mod.tar_archive({"a.conf": "x\n", "deadline": "0\n"}, uid=65534, gid=65534)
    with tarfile.open(fileobj=io.BytesIO(data)) as tar:
        members = tar.getmembers()
        assert [m.name for m in members] == ["a.conf", "deadline"]
        assert all((m.uid, m.gid, m.mode) == (65534, 65534, 0o600) for m in members)
        handle = tar.extractfile("a.conf")
        assert handle is not None and handle.read() == b"x\n"
