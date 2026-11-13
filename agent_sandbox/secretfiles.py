"""Secret files stay out of the sandbox: real ones live outside the workspace (PRD section 8).

A matching file in the workspace has to be a symlink into `<config dir>/secrets/`, which dangles
in the container, and has to be ignored by a rule every clone gets. The checks run on the host
before anything starts. They are by name only, and a file that appears during a session stays
readable until the next check.
"""

from __future__ import annotations

import itertools
import json
import os
import time
from dataclasses import dataclass
from dataclasses import field as dataclass_field
from fnmatch import fnmatchcase
from pathlib import Path, PurePosixPath

from .config import MountSpec, ProjectConfig
from .mounts import SCAN_MAX_ENTRIES, SCAN_MAX_SECONDS
from .project import host_git
from .util import SandboxError, config_dir, eprint, state_dir

PROBE = "agent-sandbox-probe"
COPY_CHUNK = 1 << 16
COMMIT_MARK = "\x01"  # starts each hash field of our `git log`; file names are read by position
COMMIT_FORMAT = "%x01%H"


@dataclass(frozen=True)
class Finding:
    subject: str
    problem: str
    fix: str

    def __str__(self) -> str:
        return f"  {self.subject}: {self.problem}\n    fix: {self.fix}"


@dataclass(frozen=True)
class Adoption:
    relative: str
    target: Path | None  # None: not moved, see `refused`
    refused: str = ""


def secrets_root() -> Path:
    return config_dir() / "secrets"


def is_secret_name(name: str, config: ProjectConfig) -> bool:
    if name in config.secrets_except:
        return False
    return any(fnmatchcase(name, pattern) for pattern in config.secrets)


@dataclass
class _Scan:
    matches: list[Path] = dataclass_field(default_factory=list)
    unreadable: list[Path] = dataclass_field(default_factory=list)
    complete: bool = True
    entries: int = 0


def _scan(
    root: Path,
    config: ProjectConfig,
    skip: frozenset[str] = frozenset(),
    *,
    max_entries: int | None = None,
    max_seconds: float | None = None,
) -> _Scan:
    """Matching non-directories below `root`, and the directories that could not be listed.

    Symlinks are never followed. `skip` holds directories relative to `root`. Every `.git` is
    left out: object names cannot match, and it is the slowest part of a workspace. With a
    budget, the scan stops once it has seen `max_entries` entries or spent `max_seconds`.
    """
    result = _Scan()
    deadline = None if max_seconds is None else time.monotonic() + max_seconds
    stack = [root]
    while stack:
        current = stack.pop()
        try:
            with os.scandir(current) as iterator:
                entries = list(iterator)
        except OSError:
            result.unreadable.append(current)
            continue
        for entry in entries:
            if (max_entries is not None and result.entries >= max_entries) or (
                deadline is not None and result.entries % 256 == 0 and time.monotonic() > deadline
            ):
                result.complete = False
                stack.clear()
                break
            result.entries += 1
            path = Path(entry.path)
            if entry.is_dir(follow_symlinks=False):
                if entry.name != ".git" and str(path.relative_to(root)) not in skip:
                    stack.append(path)
            elif is_secret_name(entry.name, config):
                result.matches.append(path)
    result.matches.sort()
    result.unreadable.sort()
    return result


def _link_finding(path: Path, shown: str) -> Finding | None:
    """Why the symlink `path` does not lead into the secrets directory, if it does not."""
    try:
        target = path.resolve()
    except (OSError, RuntimeError):
        target = None
    root = secrets_root().resolve()
    if target is not None and root in target.parents:
        return None
    return Finding(
        shown,
        f"a symlink to {os.readlink(path)}, outside {root}",
        f"move the secret into {root} and link to it there, or remove the link",
    )


def _tracked(root: Path, relative: list[str]) -> tuple[set[str], str]:
    """Which of these paths git tracks, and git's error if it could not say."""
    if not relative:
        return set(), ""
    specs = [f":(literal){rel}" for rel in relative]
    result = host_git(root, "ls-files", "-z", "--", *specs)
    if result.returncode != 0:
        return set(), result.stderr.strip()
    return {name for name in result.stdout.split("\0") if name}, ""


def _clone_safe(source: str) -> bool:
    """A rule every clone gets can only be in a `.gitignore` inside the repository."""
    path = PurePosixPath(source)
    return path.name == ".gitignore" and not path.is_absolute() and ".." not in path.parts


def _ignore_rules(root: Path, relative: list[str]) -> tuple[dict[str, tuple[str, str]], str]:
    """Path -> (rule source, pattern) from git, empty strings for no rule; and git's error.

    Tracked paths come back without a rule. The exit code cannot decide this: with `-v` it is 0
    for a negated rule too, so the caller has to look at the pattern.
    """
    result = host_git(
        root,
        "check-ignore", "-z", "-v", "-n", "--stdin",
        input="".join(f"{rel}\0" for rel in relative),
    )  # fmt: skip
    if result.returncode not in (0, 1):
        return {}, result.stderr.strip()
    fields = result.stdout.split("\0")
    rules: dict[str, tuple[str, str]] = {}
    for start in range(0, len(fields) - 3, 4):
        source, _line, pattern, path = fields[start : start + 4]
        rules[path] = (source, pattern)
    return rules, ""


def _probes(config: ProjectConfig) -> dict[str, str]:
    """Names that do not need to exist, to check the rules that will protect them. Name -> pattern.

    The first `git add` of a new secret file must already do nothing, so waiting for it to appear
    would be too late. One directory down catches a rule anchored to the root.
    """
    probes: dict[str, str] = {}
    for pattern in config.secrets:
        name = pattern.replace("*", PROBE).replace("?", "x")
        if name not in config.secrets_except:
            probes[name] = pattern
            probes[f"{PROBE}/{name}"] = pattern
    return probes


def _rule_fix(pattern: str) -> str:
    return f"add `{pattern}` to a .gitignore and commit it, so that clones get the rule too"


def _git_findings(root: Path, matches: list[str], config: ProjectConfig) -> list[Finding]:
    probes = _probes(config)
    paths = [*matches, *(probe for probe in probes if probe not in matches)]
    rules, error = _ignore_rules(root, paths)
    if error:
        return [Finding(str(root), f"git could not check the ignore rules: {error}", "fix git")]
    sources = sorted({source for source, _ in rules.values() if _clone_safe(source)})
    tracked_rules, error = _tracked(root, sources)
    if error:
        return [Finding(str(root), f"git could not list {sources}: {error}", "fix git")]
    tracked, error = _tracked(root, matches)
    if error:
        return [Finding(str(root), f"git could not list the secret files: {error}", "fix git")]

    findings: list[Finding] = []
    for path in paths:
        source, pattern = rules.get(path, ("", ""))
        shown = f"rule for {probes[path]}" if path in probes and path not in matches else path
        fix = _rule_fix(probes.get(path, PurePosixPath(path).name))
        if path in tracked:
            findings.append(
                Finding(
                    shown,
                    "tracked by git, so it is in the history the agent can read",
                    f"`git rm --cached {path}`, rotate what it holds, and {fix}",
                )
            )
        elif not source or pattern.startswith("!"):
            findings.append(Finding(shown, f"{path} is not ignored by git", fix))
        elif source not in tracked_rules:
            findings.append(
                Finding(shown, f"{path} is ignored only by {source}, which clones do not get", fix)
            )
    # One finding per pattern is enough; the probe one level down usually repeats the first.
    unique: dict[tuple[str, str], Finding] = {}
    for finding in findings:
        unique.setdefault((finding.subject, finding.fix), finding)
    return list(unique.values())


# --- history ----------------------------------------------------------------------------


def _rotated_file(project_id: str) -> Path:
    return state_dir() / "secrets-rotated" / f"{project_id}.json"


def rotated_commits(project_id: str) -> dict[str, set[str]]:
    """Path -> the commits whose content was rotated. An unusable record acknowledges nothing."""
    try:
        data = json.loads(_rotated_file(project_id).read_text())
        return {path: set(commits) for path, commits in data.items()}
    except (OSError, ValueError, AttributeError, TypeError):
        return {}


def _commits_touching(root: Path, relative: str) -> set[str]:
    """Every commit on any ref that adds or changes this path; deleting a file exposes nothing.

    Every status but D is listed instead of `--diff-filter=d`: git 2.43 (Ubuntu 24.04) matches
    no commit with an exclusion-only filter unless a diff output format is requested."""
    result = host_git(
        root,
        "-c", "log.showRoot=true",
        "log", "--all", "--full-history", "--no-renames", "--diff-filter=ACMRTUXB",
        "--format=%H",
        "--", f":(literal){relative}",
    )  # fmt: skip
    if result.returncode != 0:
        raise SandboxError(f"git could not read the history: {result.stderr.strip()}")
    return set(result.stdout.split())


def record_rotated(root: Path, project_id: str, paths: list[str], config: ProjectConfig) -> None:
    """Acknowledge the commits at these paths so far. The commits and not a point in time: refs
    need not be linear, clocks drift, and a later commit at the path is simply not in the set."""
    recorded = rotated_commits(project_id)
    for raw in paths:
        path = Path(raw)
        if path.is_absolute():
            path = path.relative_to(root) if path.is_relative_to(root) else path
        relative = PurePosixPath(os.path.normpath(path))
        if relative.is_absolute() or ".." in relative.parts:
            raise SandboxError(f"{raw} is not a path in this workspace.")
        if not is_secret_name(relative.name, config):
            raise SandboxError(f"{raw} is not a secret file name; nothing to record.")
        commits = _commits_touching(root, str(relative))
        if not commits:
            raise SandboxError(f"No commit adds or changes {relative}; nothing to record.")
        recorded.setdefault(str(relative), set()).update(commits)
    target = _rotated_file(project_id)
    target.parent.mkdir(parents=True, exist_ok=True)
    data = {path: sorted(commits) for path, commits in sorted(recorded.items())}
    target.write_text(json.dumps(data, indent=1) + "\n")


def forget_rotated(project_id: str) -> None:
    _rotated_file(project_id).unlink(missing_ok=True)


def _parse_history(output: str) -> dict[str, list[str]]:
    """Path -> commits adding or changing it, newest first, from `--name-status -z` with each
    commit's hash after COMMIT_MARK. Names are taken by position, so any file name is safe."""
    found: dict[str, list[str]] = {}
    fields = iter(output.split("\0"))
    commit = ""
    for field in fields:
        field = field.lstrip("\n")
        if field.startswith(COMMIT_MARK):
            commit = field[len(COMMIT_MARK) :].strip()
        elif field:
            name = next(fields, "")
            if field != "D":
                found.setdefault(name, []).append(commit)
    return found


def _history_findings(root: Path, project_id: str, config: ProjectConfig) -> list[Finding]:
    """Secret file names in the newest commits, filtered here and not by git: `-n` counts only
    the commits a pathspec or `--diff-filter` lets through, so either would walk all of a clean
    history."""
    depth = config.secrets_history_depth
    if depth is None:
        return []
    result = host_git(
        root,
        "-c", "log.showRoot=true",
        "log", "--all", f"--max-count={depth}", f"--format={COMMIT_FORMAT}", "--name-status",
        "--no-renames", "-z",
    )  # fmt: skip
    if result.returncode != 0:
        return [Finding(str(root), f"git could not read the history: {result.stderr}", "fix git")]
    rotated = rotated_commits(project_id)
    findings: list[Finding] = []
    for name, commits in sorted(_parse_history(result.stdout).items()):
        pending = [c for c in commits if c not in rotated.get(name, set())]
        if pending and is_secret_name(PurePosixPath(name).name, config):
            findings.append(
                Finding(
                    name,
                    f"committed in {pending[0][:12]} (within the newest {depth} commits), and the "
                    "agent can read .git",
                    f"rotate what it held, then run `agent-sandbox secrets rotated {name}`",
                )
            )
    return findings


# --- the checks -------------------------------------------------------------------------


def check(root: Path, project_id: str, config: ProjectConfig, *, history: bool) -> list[Finding]:
    """Everything that keeps this workspace from starting. `history`: creating the sandbox."""
    secrets = secrets_root().resolve()
    if root == secrets or root in secrets.parents:
        raise SandboxError(
            f"The workspace {root} contains the secrets directory {secrets}, so the sandbox "
            "would see every secret. Use another repository, or move the configuration directory."
        )
    secrets.mkdir(mode=0o700, parents=True, exist_ok=True)

    scan = _scan(root, config, frozenset(config.isolated))
    matches = scan.matches
    findings = [
        Finding(
            str(path),
            "this directory cannot be read, so it cannot be checked",
            "fix its permissions (`agent-sandbox repair` if the sandbox made it), "
            "or add it to [workspace] isolated",
        )
        for path in scan.unreadable
    ]
    relative = [str(path.relative_to(root)) for path in matches]
    for path, shown in zip(matches, relative, strict=True):
        if not path.is_symlink():
            findings.append(
                Finding(shown, "a real file in the workspace", "`agent-sandbox secrets adopt`")
            )
        elif finding := _link_finding(path, shown):
            findings.append(finding)
    for spec in config.mounts:
        findings += _mount_findings(spec, config)
    findings += _git_findings(root, relative, config)
    if history:
        findings += _history_findings(root, project_id, config)
    return findings


def _mount_findings(spec: MountSpec, config: ProjectConfig) -> list[Finding]:
    """An extra mount puts its files in the sandbox as well. Git rules do not apply to it.

    The scan is bounded like the socket scan: a mount can be a huge network file system.
    """
    source = Path(spec.source)
    if not spec.check_secrets:
        return []
    if source.is_dir():
        eprint(f"Scanning for secret files in {source}...")
        try:
            scan = _scan(
                source.resolve(), config, max_entries=SCAN_MAX_ENTRIES, max_seconds=SCAN_MAX_SECONDS
            )
        except KeyboardInterrupt:
            eprint("Interrupted.")
            raise
        if not scan.complete:
            eprint(
                f"note: scanning {source} for secret files stopped early after {scan.entries} "
                "entries; files deeper in the tree were not checked. Set `check_secrets = false` "
                "on this mount to skip the scan."
            )
        matches, unreadable = scan.matches, scan.unreadable
    elif source.exists() and is_secret_name(source.resolve().name, config):
        matches, unreadable = [source], []
    else:
        return []
    findings = [
        Finding(str(path), "this mounted directory cannot be read", "fix its permissions")
        for path in unreadable
    ]
    for path in matches:
        if not path.is_symlink():
            findings.append(
                Finding(
                    str(path),
                    "a real file in an extra mount",
                    "move it out of the mount, or remove the mount from [[mounts]]",
                )
            )
        elif finding := _link_finding(path, str(path)):
            findings.append(finding)
    return findings


def report(findings: list[Finding]) -> str:
    lines = "\n".join(str(finding) for finding in findings)
    return (
        f"Secret file checks found {len(findings)} problem(s):\n{lines}\n"
        "If this sandbox is running, its sessions can read any real file listed above. Stop them "
        "with `agent-sandbox stop`, and rotate what the agent may have read."
    )


def enforce(root: Path, project_id: str, config: ProjectConfig, *, history: bool) -> None:
    findings = check(root, project_id, config, history=history)
    if findings:
        raise SandboxError(f"{report(findings)}\nNothing was started.")


# --- adopt ------------------------------------------------------------------------------


def _copy_private(source: Path, target: Path) -> None:
    """Copy to a new `0600` file: no ACL or wide mode comes along, unlike with a rename."""
    source_fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        target_fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            while chunk := os.read(source_fd, COPY_CHUNK):
                os.write(target_fd, chunk)
            os.fsync(target_fd)
        finally:
            os.close(target_fd)
    finally:
        os.close(source_fd)


def _replace_with_link(path: Path, target: Path) -> None:
    """Atomically. `symlink_to` never replaces, so whatever holds a name stays untouched."""
    for attempt in itertools.count():
        temporary = path.with_name(f".{path.name}.agent-sandbox-link-{attempt}")
        try:
            temporary.symlink_to(target)
        except FileExistsError:
            continue
        break
    try:
        temporary.replace(path)
    except OSError:
        temporary.unlink(missing_ok=True)
        raise


def adopt(root: Path, project_id: str, config: ProjectConfig, *, dry_run: bool) -> list[Adoption]:
    """Move real secret files to the secrets directory and leave symlinks behind."""
    matches = _scan(root, config, frozenset(config.isolated)).matches
    real = [path for path in matches if not path.is_symlink()]
    relative = [str(path.relative_to(root)) for path in real]
    tracked, error = _tracked(root, relative)
    if error:
        raise SandboxError(f"git could not list the secret files: {error}")
    directory = secrets_root().resolve() / project_id
    adoptions: list[Adoption] = []
    for path, rel in zip(real, relative, strict=True):
        target = directory / rel
        if rel in tracked:
            refused = (
                f"tracked by git, so already in history: `git rm --cached {rel}`, rotate what it "
                "holds, add a rule to .gitignore, then adopt it (and run `agent-sandbox secrets "
                "rotated` if the history check is enabled)"
            )
        elif not path.is_file():
            refused = "not a regular file"
        elif target.exists() or target.is_symlink():
            refused = f"{target} already exists; compare the two and remove one"
        else:
            if not dry_run:
                target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                _copy_private(path, target)
                _replace_with_link(path, target)
            adoptions.append(Adoption(rel, target))
            continue
        adoptions.append(Adoption(rel, None, refused))
    return adoptions
