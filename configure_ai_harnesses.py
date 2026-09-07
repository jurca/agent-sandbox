import json
import os
import sys
import tempfile


def configure_github_copilot_sandbox(settings_path: str, uid: str, gid: str) -> None:
    try:
        with open(settings_path, encoding="utf-8") as settings_file:
            settings: dict[str, object] = json.load(settings_file)
    except FileNotFoundError:
        settings = {}

    if not isinstance(settings, dict):
        raise SystemExit(f"{settings_path} must contain a JSON object")

    settings["chat.agent.sandbox.enabled"] = "on"

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

    directory = os.path.dirname(settings_path)
    with tempfile.NamedTemporaryFile(
        "w", encoding="utf-8", dir=directory, delete=False
    ) as temp_file:
        json.dump(settings, temp_file, indent="\t")
        temp_file.write("\n")
        temporary_path = temp_file.name
    os.chown(temporary_path, int(uid), int(gid))
    os.chmod(temporary_path, 0o644)
    os.replace(temporary_path, settings_path)


vs_code_settings_path, uid, gid = sys.argv[1:]
configure_github_copilot_sandbox(vs_code_settings_path, uid, gid)
