import json
import os
import sys
import tempfile
from typing import cast


def _atomically_write_json_file(
    path: str, data: object, indent: int | str, uid: int, gid: int, mode: int = 0o644
) -> None:
    directory = os.path.dirname(path)
    with tempfile.NamedTemporaryFile(
        "w", encoding="utf-8", dir=directory, delete=False
    ) as temp_file:
        json.dump(data, temp_file, indent=indent)
        temp_file.write("\n")
        temporary_path = temp_file.name
    os.chown(temporary_path, uid, gid)
    os.chmod(temporary_path, mode)
    os.replace(temporary_path, path)


def configure_github_copilot_sandbox(settings_path: str, uid: int, gid: int) -> None:
    try:
        with open(settings_path, encoding="utf-8") as settings_file:
            settings: dict[str, object] = json.load(settings_file)
    except FileNotFoundError:
        settings = {}

    if not isinstance(settings, dict):
        raise SystemExit(f"{settings_path} must contain a JSON object")

    settings["chat.agent.sandbox.enabled"] = "on"
    settings["chat.agent.sandbox.allowNetwork"] = False

    runtime = settings.get("chat.agent.sandbox.advanced.runtime", {})
    if not isinstance(runtime, dict):
        runtime = {}
    runtime["enableWeakerNestedSandbox"] = True
    network = runtime.get("network", {})
    if not isinstance(network, dict):
        network = {}
    network["allowAllUnixSockets"] = True
    runtime["network"] = network
    settings["chat.agent.sandbox.advanced.runtime"] = runtime

    filesystem = settings.get("chat.agent.sandbox.fileSystem.linux", {})
    if not isinstance(filesystem, dict):
        filesystem = {}
    for key in ("denyRead", "denyWrite"):
        entries = filesystem.get(key, [])
        if not isinstance(entries, list):
            entries = []
        if "/tmp" not in entries:
            entries.append("/tmp")
        filesystem[key] = entries
    settings["chat.agent.sandbox.fileSystem.linux"] = filesystem

    # Configure the new Copilot harness sandbox
    settings["chat.agent.sandbox.network.allowNetwork"] = False
    paths = settings.get("chat.agent.sandbox.fileSystem.userConfiguredPaths", {})
    if not isinstance(paths, dict):
        paths = {}
    denied_paths = paths.get("deniedPaths", [])
    if not isinstance(denied_paths, list):
        denied_paths = []
    if "/tmp" not in denied_paths:
        denied_paths.append("/tmp")
    paths["deniedPaths"] = denied_paths
    readonly_paths = paths.get("readonlyPaths", [])
    if not isinstance(readonly_paths, list):
        readonly_paths = []
    if "~/.local/bin" not in readonly_paths:
        readonly_paths.append("~/.local/bin")
    if "~/.local/share/uv/python" not in readonly_paths:
        readonly_paths.append("~/.local/share/uv/python")
    paths["readonlyPaths"] = readonly_paths
    readwrite_paths = paths.get("readwritePaths", [])
    if not isinstance(readwrite_paths, list):
        readwrite_paths = []
    if "~/.cache/uv" not in readwrite_paths:
        readwrite_paths.append("~/.cache/uv")
    paths["readwritePaths"] = readwrite_paths
    settings["chat.agent.sandbox.fileSystem.userConfiguredPaths"] = paths

    _atomically_write_json_file(settings_path, settings, indent="\t", uid=uid, gid=gid)


def configure_claude_code_sandbox(settings_path: str, uid: int, gid: int) -> None:
    try:
        with open(settings_path, encoding="utf-8") as settings_file:
            settings: dict[str, object] = json.load(settings_file)
    except FileNotFoundError:
        settings = {}

    if not isinstance(settings, dict):
        raise SystemExit(f"{settings_path} must contain a JSON object")

    sandbox_settings = cast(dict[str, object], settings.get("sandbox", {}))
    if not isinstance(sandbox_settings, dict):
        sandbox_settings = {}

    sandbox_settings["enabled"] = True
    sandbox_settings["autoAllowBashIfSandboxed"] = True
    sandbox_settings["enableWeakerNestedSandbox"] = True

    fs_settings = sandbox_settings.get("filesystem", {})
    if not isinstance(fs_settings, dict):
        fs_settings = {}
    deny_read_rules = fs_settings.get("denyRead", [])
    if not isinstance(deny_read_rules, list):
        deny_read_rules = []
    if "~/.gnupg" not in deny_read_rules:
        deny_read_rules.append("~/.gnupg")
    if "/tmp" not in deny_read_rules:
        deny_read_rules.append("/tmp")
    fs_settings["denyRead"] = deny_read_rules
    deny_write_rules = fs_settings.get("denyWrite", [])
    if not isinstance(deny_write_rules, list):
        deny_write_rules = []
    if "~/.gnupg" not in deny_write_rules:
        deny_write_rules.append("~/.gnupg")
    if "/tmp" not in deny_write_rules:
        deny_write_rules.append("/tmp")
    fs_settings["denyWrite"] = deny_write_rules
    sandbox_settings["filesystem"] = fs_settings

    network_settings = sandbox_settings.get("network", {})
    if not isinstance(network_settings, dict):
        network_settings = {}
    network_settings["allowAllUnixSockets"] = True
    sandbox_settings["network"] = network_settings

    settings["sandbox"] = sandbox_settings

    _atomically_write_json_file(settings_path, settings, indent=2, uid=uid, gid=gid)


vs_code_settings_path, claude_settings_path, uid, gid = sys.argv[1:]
uid = int(uid)
gid = int(gid)

configure_github_copilot_sandbox(vs_code_settings_path, uid, gid)
configure_claude_code_sandbox(claude_settings_path, uid, gid)
