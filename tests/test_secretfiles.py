from __future__ import annotations

import os
import stat
import subprocess
from pathlib import Path

import pytest

from agent_sandbox import secretfiles
from agent_sandbox.config import MountSpec, ProjectConfig, load_project_config
from agent_sandbox.project import host_git
from agent_sandbox.secretfiles import Finding, adopt, check, enforce, record_rotated, secrets_root
from agent_sandbox.util import SandboxError

from .conftest import git

ID = "repo-12345678"


def run_check(
    repo: Path, config: ProjectConfig | None = None, *, history: bool = False
) -> list[Finding]:
    return check(repo, ID, config or ProjectConfig(), history=history)


def subjects(findings: list[Finding]) -> list[str]:
    return [finding.subject for finding in findings]


def problems(findings: list[Finding]) -> str:
    return "\n".join(finding.problem for finding in findings)


def link(repo: Path, rel: str = ".env", secret: str = "stored") -> Path:
    target = secrets_root() / ID / secret
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("VALUE=fake\n")
    (repo / rel).parent.mkdir(parents=True, exist_ok=True)
    (repo / rel).symlink_to(target)
    return target


def commit(repo: Path, *paths: str) -> None:
    git(repo, "add", "-f", *paths)
    git(repo, "commit", "-q", "-m", "change")


def test_clean_workspace_passes_and_creates_private_directory(repo: Path) -> None:
    assert run_check(repo) == []
    assert stat.S_IMODE(secrets_root().stat().st_mode) == 0o700


def test_link_into_secrets_directory_passes_even_when_target_is_missing(repo: Path) -> None:
    target = link(repo)
    link(repo, "sub/prod.env", "other")
    assert run_check(repo) == []
    target.unlink()
    assert run_check(repo) == []


@pytest.mark.parametrize("name", [".env", ".env.local", "prod.env", "deep/er/.env"])
def test_real_file_is_a_finding(repo: Path, name: str) -> None:
    (repo / name).parent.mkdir(parents=True, exist_ok=True)
    (repo / name).write_text("VALUE=fake\n")
    (repo / name).chmod(0o600)  # the mode does not matter
    assert run_check(repo) == [
        Finding(name, "a real file in the workspace", "`agent-sandbox secrets adopt`")
    ]


def test_exempt_names_directories_and_isolated_paths_do_not_match(repo: Path) -> None:
    (repo / ".env.example").write_text("VALUE=\n")
    (repo / ".env").mkdir()  # a common virtualenv name
    (repo / ".env" / "pyvenv.cfg").write_text("")
    (repo / "node_modules" / "pkg").mkdir(parents=True)
    (repo / "node_modules" / "pkg" / ".env").write_text("fixture\n")
    (repo / "venv.env.txt").write_text("")
    assert run_check(repo) == []


def test_project_can_add_names_and_exempt_some(repo: Path) -> None:
    (repo / "api.secret").write_text("x")
    (repo / ".env.test").write_text("dummy")
    config = ProjectConfig(
        secrets=[".env", ".env.*", "*.env", "*.secret"],
        secrets_except=[".env.test"],
    )
    found = run_check(repo, config)
    assert "api.secret" in subjects(found)
    assert ".env.test" not in subjects(found)


@pytest.mark.parametrize("outside", ["inside", "home", "other-secrets"])
def test_link_elsewhere_is_a_finding(repo: Path, tmp_path: Path, outside: str) -> None:
    targets = {
        "inside": repo / "README",
        "home": tmp_path / "id_rsa",
        # A sibling sharing the prefix of the secrets directory is not inside it.
        "other-secrets": secrets_root().parent / "secrets-other" / "x",
    }
    (repo / ".env").symlink_to(targets[outside])
    found = run_check(repo)
    assert subjects(found) == [".env"]
    assert "outside" in found[0].problem


def test_link_through_a_secrets_path_with_dotdot_is_resolved(repo: Path, tmp_path: Path) -> None:
    (repo / ".env").symlink_to(secrets_root() / ".." / ".." / "escaped")
    assert subjects(run_check(repo)) == [".env"]


def test_symlink_loop_is_a_finding(repo: Path) -> None:
    (repo / ".env").symlink_to(repo / ".env")
    assert subjects(run_check(repo)) == [".env"]


@pytest.mark.skipif(os.getuid() == 0, reason="root reads everything")
def test_unreadable_directory_is_a_finding(repo: Path) -> None:
    locked = repo / "locked"
    locked.mkdir()
    locked.chmod(0)
    try:
        found = run_check(repo)
    finally:
        locked.chmod(0o700)
    assert subjects(found) == [str(locked)]


def test_workspace_holding_the_secrets_directory_is_refused(
    repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("AGENT_SANDBOX_CONFIG_DIR", str(repo / ".config"))
    with pytest.raises(SandboxError, match="contains the secrets directory"):
        run_check(repo)


def test_extra_mounts_are_checked_for_real_files_only(repo: Path, tmp_path: Path) -> None:
    mounted = tmp_path / "skills"
    mounted.mkdir()
    (mounted / ".env").write_text("x")
    (tmp_path / "single.env").write_text("x")
    config = ProjectConfig(
        mounts=[MountSpec(str(mounted), "/m"), MountSpec(str(tmp_path / "single.env"), "/n")]
    )
    found = run_check(repo, config)
    assert subjects(found) == [str(mounted / ".env"), str(tmp_path / "single.env")]
    assert "extra mount" in found[0].problem


# --- git --------------------------------------------------------------------------------


def write_rules(repo: Path, text: str, *, track: bool = True) -> None:
    (repo / ".gitignore").write_text(text)
    if track:
        commit(repo, ".gitignore")


def test_missing_rules_are_found_before_any_file_exists(repo: Path) -> None:
    write_rules(repo, "")
    found = run_check(repo)
    assert subjects(found) == ["rule for .env", "rule for .env.*", "rule for *.env"]
    assert "`.env.*`" in found[1].fix


def test_rule_anchored_to_the_root_is_not_enough(repo: Path) -> None:
    write_rules(repo, "/.env\n/.env.*\n/*.env\n")
    assert sorted(subjects(run_check(repo))) == [
        "rule for *.env",
        "rule for .env",
        "rule for .env.*",
    ]


def test_tracked_file_is_a_finding_even_when_listed(repo: Path) -> None:
    target = link(repo, "tracked.env")
    commit(repo, "tracked.env")
    found = run_check(repo)
    assert subjects(found) == ["tracked.env"]
    assert "tracked by git" in found[0].problem
    assert "git rm --cached tracked.env" in found[0].fix
    assert target.exists()


def test_negated_rule_is_not_ignored(repo: Path) -> None:
    write_rules(repo, ".env\n.env.*\n*.env\n!keep.env\n")
    link(repo, "keep.env")
    assert subjects(run_check(repo)) == ["keep.env"]


def test_directory_only_rule_does_not_cover_a_link(repo: Path) -> None:
    write_rules(repo, ".env.*\n*.env\ndir.env/\n!dir.env\n")
    link(repo, "dir.env")
    assert subjects(run_check(repo)) == ["dir.env"]


def test_rule_in_info_exclude_does_not_protect_clones(repo: Path) -> None:
    link(repo, "local.secret")
    (repo / ".git" / "info" / "exclude").write_text("local.secret\n")
    found = run_check(repo, ProjectConfig(secrets=[".env", ".env.*", "*.env", "local.secret"]))
    assert subjects(found) == ["local.secret", "rule for local.secret"]
    assert all(".git/info/exclude" in finding.problem for finding in found)


def test_global_excludes_file_named_gitignore_does_not_count(repo: Path, tmp_path: Path) -> None:
    write_rules(repo, "")
    outside = tmp_path / ".gitignore"
    outside.write_text(".env\n.env.*\n*.env\n")
    git(repo, "config", "core.excludesFile", str(outside))
    assert len(run_check(repo)) == 3


def test_rule_in_an_uncommitted_gitignore_does_not_count(repo: Path) -> None:
    git(repo, "rm", "-q", "--cached", ".gitignore")
    git(repo, "commit", "-q", "-m", "untrack")
    found = run_check(repo)
    assert len(found) == 3
    assert "which clones do not get" in found[0].problem


def test_rule_in_a_nested_tracked_gitignore_counts(repo: Path) -> None:
    (repo / "sub").mkdir()
    write_rules(repo, ".env\n.env.*\n*.env\n!sub/x.env\n")
    (repo / "sub" / ".gitignore").write_text("x.env\n")
    commit(repo, "sub/.gitignore")
    link(repo, "sub/x.env")
    assert run_check(repo) == []


def test_file_names_with_odd_characters(repo: Path) -> None:
    link(repo, "sp ace/*.env")
    assert run_check(repo) == []
    os.symlink(secrets_root() / "x", os.fsencode(repo) + b"/bad\xff.env")
    assert run_check(repo) == []


# --- history ----------------------------------------------------------------------------


def with_depth(depth: int | None) -> ProjectConfig:
    return ProjectConfig(secrets_history_depth=depth)


def commit_then_remove(repo: Path, rel: str = "old.env") -> None:
    (repo / rel).write_text("VALUE=fake\n")
    commit(repo, rel)
    git(repo, "rm", "-q", "--cached", rel)
    git(repo, "commit", "-q", "-m", "remove")
    (repo / rel).unlink()


def test_history_is_off_by_default(repo: Path) -> None:
    commit_then_remove(repo)
    assert run_check(repo, with_depth(None), history=True) == []


def test_history_finds_within_depth_and_misses_beyond_it(repo: Path) -> None:
    commit_then_remove(repo, "sub.env")
    found = run_check(repo, with_depth(2), history=True)
    assert subjects(found) == ["sub.env"]
    assert "secrets rotated sub.env" in found[0].fix
    git(repo, "commit", "-q", "--allow-empty", "-m", "newer")
    git(repo, "commit", "-q", "--allow-empty", "-m", "newer")
    assert run_check(repo, with_depth(2), history=True) == []


def test_history_only_runs_when_asked(repo: Path) -> None:
    commit_then_remove(repo)
    assert run_check(repo, with_depth(50), history=False) == []


def test_history_ignores_exempt_names_and_sees_other_refs(repo: Path) -> None:
    (repo / ".env.example").write_text("VALUE=\n")
    commit(repo, ".env.example")
    git(repo, "checkout", "-q", "-b", "other")
    commit_then_remove(repo, "branch.env")
    git(repo, "checkout", "-q", "main")
    assert subjects(run_check(repo, with_depth(50), history=True)) == ["branch.env"]


def test_history_in_the_root_commit(tmp_path: Path) -> None:
    from .conftest import make_repo

    repo = make_repo(tmp_path / "fresh")
    git(repo, "config", "log.showRoot", "false")
    (repo / "root.env").write_text("x")
    git(repo, "add", "-f", "root.env")
    git(repo, "commit", "-q", "--amend", "--no-edit")
    git(repo, "rm", "-q", "--cached", "root.env")
    git(repo, "commit", "-q", "-m", "remove")
    (repo / "root.env").unlink()
    assert subjects(run_check(repo, with_depth(5), history=True)) == ["root.env"]


def test_history_search_is_bounded_by_commits(repo: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[str, ...]] = []

    def spy(cwd: Path, *args: str, input: str | None = None) -> subprocess.CompletedProcess[str]:
        calls.append(args)
        return host_git(cwd, *args, input=input)

    monkeypatch.setattr(secretfiles, "host_git", spy)
    run_check(repo, with_depth(3), history=True)
    log = next(args for args in calls if "log" in args)
    assert "--max-count=3" in log
    # Either of these would make the limit count only matching commits.
    assert "--" not in log and not any(arg.startswith("--diff-filter") for arg in log)


def test_rotated_silences_the_path_only(repo: Path) -> None:
    commit_then_remove(repo, "a.env")
    commit_then_remove(repo, "b.env")
    config = with_depth(50)
    record_rotated(repo, ID, ["a.env", "./sub/../a.env"], config)
    assert subjects(run_check(repo, config, history=True)) == ["b.env"]
    record_rotated(repo, ID, [str(repo / "b.env")], config)
    assert run_check(repo, config, history=True) == []
    secretfiles.forget_rotated(ID)
    assert len(run_check(repo, config, history=True)) == 2


def test_new_commit_after_rotation_is_a_finding_again(repo: Path) -> None:
    config = with_depth(50)
    commit_then_remove(repo, "a.env")
    record_rotated(repo, ID, ["a.env"], config)
    assert run_check(repo, config, history=True) == []
    commit_then_remove(repo, "a.env")
    found = run_check(repo, config, history=True)
    assert subjects(found) == ["a.env"]
    assert git(repo, "log", "-2", "--format=%H").split()[1][:12] in found[0].problem
    record_rotated(repo, ID, ["a.env"], config)
    assert run_check(repo, config, history=True) == []


def test_removing_the_file_after_rotation_is_no_finding(repo: Path) -> None:
    config = with_depth(50)
    (repo / "a.env").write_text("VALUE=fake\n")
    commit(repo, "a.env")
    record_rotated(repo, ID, ["a.env"], config)
    git(repo, "rm", "-q", "--cached", "a.env")
    git(repo, "commit", "-q", "-m", "remove")
    (repo / "a.env").unlink()
    assert run_check(repo, config, history=True) == []


def test_removal_alone_does_not_count_as_a_commit_of_the_secret(repo: Path) -> None:
    commit_then_remove(repo)
    assert run_check(repo, with_depth(1), history=True) == []
    assert subjects(run_check(repo, with_depth(2), history=True)) == ["old.env"]


def test_rotation_covers_every_ref_and_merged_side_branches(repo: Path) -> None:
    config = with_depth(50)
    git(repo, "checkout", "-q", "-b", "side")
    commit_then_remove(repo, "a.env")
    git(repo, "checkout", "-q", "main")
    git(repo, "merge", "-q", "--no-ff", "-m", "merge", "side")
    git(repo, "branch", "-q", "other", "side~1")
    record_rotated(repo, ID, ["a.env"], config)
    assert run_check(repo, config, history=True) == []


def test_rotating_a_path_without_commits_is_refused(repo: Path) -> None:
    with pytest.raises(SandboxError, match="No commit adds or changes"):
        record_rotated(repo, ID, ["typo.env"], ProjectConfig())


@pytest.mark.parametrize("record", ["not json", '["a.env"]', '{"a.env": 1}'])
def test_unusable_rotation_record_acknowledges_nothing(repo: Path, record: str) -> None:
    config = with_depth(50)
    commit_then_remove(repo, "a.env")
    record_rotated(repo, ID, ["a.env"], config)
    secretfiles._rotated_file(ID).write_text(record)
    assert subjects(run_check(repo, config, history=True)) == ["a.env"]


def test_history_handles_odd_file_names(repo: Path) -> None:
    name = "new\nline.env"
    commit_then_remove(repo, name)
    assert subjects(run_check(repo, with_depth(5), history=True)) == [name]


@pytest.mark.parametrize("path", ["README", "../x.env", "/elsewhere/x.env"])
def test_rotated_refuses_other_paths(repo: Path, path: str) -> None:
    with pytest.raises(SandboxError):
        record_rotated(repo, ID, [path], ProjectConfig())


# --- enforce ----------------------------------------------------------------------------


def test_enforce_lists_everything_and_warns_about_running_sessions(repo: Path) -> None:
    (repo / ".env").write_text("VALUE=fake\n")
    (repo / "b.env").write_text("VALUE=fake\n")
    with pytest.raises(SandboxError) as info:
        enforce(repo, ID, ProjectConfig(), history=False)
    text = str(info.value)
    assert ".env:" in text and "b.env:" in text
    assert "VALUE" not in text
    assert "sessions can read" in text and "Nothing was started" in text


# --- adopt ------------------------------------------------------------------------------


def test_adopt_moves_files_and_passes_the_checks(repo: Path) -> None:
    (repo / "sub").mkdir()
    (repo / ".env").write_text("A=fake\n")
    (repo / "sub" / "prod.env").write_bytes(b"B=fake\xff\n")
    subprocess.run(["setfacl", "-m", "u:12345:r--", str(repo / ".env")], check=False)
    adopted = adopt(repo, ID, ProjectConfig(), dry_run=False)
    assert [item.relative for item in adopted] == [".env", "sub/prod.env"]
    assert (repo / ".env").is_symlink()
    stored = secrets_root().resolve() / ID / ".env"
    assert (repo / ".env").resolve() == stored
    assert stored.read_text() == "A=fake\n"
    assert (repo / "sub" / "prod.env").read_bytes() == b"B=fake\xff\n"
    assert stat.S_IMODE(stored.stat().st_mode) == 0o600
    acl = subprocess.run(
        ["getfacl", "-c", str(stored)], capture_output=True, text=True, check=False
    )
    assert "12345" not in acl.stdout
    assert run_check(repo) == []


def test_adopt_keeps_a_file_already_named_like_its_temporary_link(repo: Path) -> None:
    (repo / "prod.env").write_text("A=fake\n")
    taken = repo / ".prod.env.agent-sandbox-link-0"
    taken.write_text("not ours\n")
    adopt(repo, ID, ProjectConfig(), dry_run=False)
    assert taken.read_text() == "not ours\n"
    assert (repo / "prod.env").is_symlink()
    assert not (repo / ".prod.env.agent-sandbox-link-1").is_symlink()


def test_adopt_dry_run_changes_nothing(repo: Path) -> None:
    (repo / ".env").write_text("A=fake\n")
    adopted = adopt(repo, ID, ProjectConfig(), dry_run=True)
    assert adopted[0].target is not None
    assert not (repo / ".env").is_symlink()
    assert not adopted[0].target.exists()


def test_adopt_refuses_tracked_files(repo: Path) -> None:
    (repo / "t.env").write_text("A=fake\n")
    commit(repo, "t.env")
    adopted = adopt(repo, ID, ProjectConfig(), dry_run=False)
    assert adopted[0].target is None
    assert "git rm --cached t.env" in adopted[0].refused
    assert not (repo / "t.env").is_symlink()


def test_adopt_never_overwrites(repo: Path) -> None:
    (repo / ".env").write_text("new\n")
    stored = secrets_root() / ID / ".env"
    stored.parent.mkdir(parents=True)
    stored.write_text("old\n")
    adopted = adopt(repo, ID, ProjectConfig(), dry_run=False)
    assert "already exists" in adopted[0].refused
    assert stored.read_text() == "old\n"
    assert (repo / ".env").read_text() == "new\n"


def test_adopt_leaves_links_and_fifos_alone(repo: Path) -> None:
    link(repo)
    os.mkfifo(repo / "pipe.env")
    adopted = adopt(repo, ID, ProjectConfig(), dry_run=False)
    assert [(item.relative, item.refused) for item in adopted] == [
        ("pipe.env", "not a regular file")
    ]


# --- configuration ----------------------------------------------------------------------


def load(repo: Path, workspace: str) -> ProjectConfig:
    directory = repo / ".agent-sandbox"
    directory.mkdir(exist_ok=True)
    (directory / "config.toml").write_text(f'image = "x"\n[workspace]\n{workspace}\n')
    return load_project_config(repo)


def test_defaults(repo: Path) -> None:
    config = load(repo, "")
    assert config.secrets == [".env", ".env.*", "*.env"]
    assert config.secrets_except == [".env.example", ".env.sample", ".env.template"]
    assert config.secrets_history_depth is None


def test_project_settings_add_to_the_defaults(repo: Path) -> None:
    config = load(
        repo,
        'secrets = ["*.secret", ".env"]\nsecrets_except = [".env.test"]\n'
        "secrets_history_depth = 200",
    )
    assert config.secrets == [".env", ".env.*", "*.env", "*.secret"]
    assert config.secrets_except[-1] == ".env.test" and ".env.example" in config.secrets_except
    assert config.secrets_history_depth == 200


@pytest.mark.parametrize(
    "setting",
    [
        'secrets = ["*"]',
        'secrets = ["a/b.env"]',
        'secrets = ["[ab].env"]',
        'secrets_except = ["*.env"]',
        'secrets_except = [".env"]',
        'secrets_except = ["a/.env.x"]',
        "secrets_history_depth = 0",
        "secrets_history_depth = true",
        'secrets_history_depth = "5"',
    ],
)
def test_invalid_settings(repo: Path, setting: str) -> None:
    with pytest.raises(SandboxError):
        load(repo, setting)
