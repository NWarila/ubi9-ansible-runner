"""Validate immutable dependency pins and optionally verify their upstream tags."""

from __future__ import annotations

import argparse
import fnmatch
import os
import re
import subprocess
import sys
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Final, Never, TextIO

EXIT_CLEAN: Final = 0
EXIT_VIOLATION: Final = 1
EXIT_INDETERMINATE: Final = 2
EXIT_USAGE: Final = 64

PER_REMOTE_TIMEOUT_SECONDS: Final = 10.0
AGGREGATE_TIMEOUT_SECONDS: Final = 60.0

MATCH: Final = "match"
MISMATCH: Final = "mismatch"
ABSENT: Final = "absent"
AMBIGUOUS: Final = "ambiguous"
INDETERMINATE: Final = "indeterminate"

SHA_PATTERN: Final = re.compile(r"[0-9a-f]{40}")
HASH_PATTERN: Final = re.compile(r"--hash=sha256:[0-9a-f]{64}")
SEMVER_TEXT: Final = (
    r"v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)"
    r"(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?"
)
SEMVER_PATTERN: Final = re.compile(SEMVER_TEXT)
GITHUB_REPOSITORY_TEXT: Final = (
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?"
    r"/[A-Za-z0-9](?:[A-Za-z0-9_.-]*[A-Za-z0-9_.])?"
)
GITHUB_URL_PATTERN: Final = re.compile(
    rf"https://github\.com/(?P<repository>{GITHUB_REPOSITORY_TEXT})(?:\.git)?"
)
ACTION_TARGET_PATTERN: Final = re.compile(
    rf"(?P<repository>{GITHUB_REPOSITORY_TEXT})"
    r"(?P<path>(?:/[A-Za-z0-9_.-]+)*)"
    r"@(?P<sha>[0-9a-f]{40})"
)
REQUIREMENT_PATTERN: Final = re.compile(
    r"(?P<name>[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?)"
    r"(?:\[[A-Za-z0-9_.-]+(?:,[A-Za-z0-9_.-]+)*\])?"
    r"==(?P<version>[^<>=!~,*;\s]+)"
)

Resolver = Callable[[str, str, float], tuple[str, str]]
Clock = Callable[[], float]


@dataclass(frozen=True)
class Pin:
    """One external repository, immutable commit, and declared upstream tag."""

    path: str
    line: int
    repository_url: str
    sha: str
    tag: str


@dataclass(frozen=True)
class InspectionFailure:
    """An input that could not be inspected."""

    path: str
    reason: str


@dataclass
class Inspection:
    """All findings from local input inspection."""

    violations: list[str]
    failures: list[InspectionFailure]
    pins: list[Pin]
    requirement_records: int = 0


@dataclass(frozen=True)
class RunResult:
    """Process-compatible result and stable diagnostic lines."""

    exit_code: int
    lines: tuple[str, ...]


class UsageParser(argparse.ArgumentParser):
    """Argument parser whose failures use the checker contract's exit code."""

    def error(self, message: str) -> Never:
        raise ValueError(message)


def _violation(path: str, line: int, message: str) -> str:
    return f"POLICY VIOLATION {path}:{line}: {message}"


def _read_lines(root: Path, relative_path: str) -> tuple[list[str] | None, str | None]:
    candidate = root / relative_path
    try:
        if candidate.is_symlink():
            return None, "input is a symbolic link, not a regular file"
        if not candidate.exists():
            return None, "cannot read input: file does not exist"
        resolved_root = root.resolve(strict=True)
        resolved_candidate = candidate.resolve(strict=True)
        resolved_candidate.relative_to(resolved_root)
        if not candidate.is_file():
            return None, "input is not a regular file"
        return candidate.read_text(encoding="utf-8").splitlines(), None
    except UnicodeError as error:
        return None, f"input is not valid UTF-8: {error}"
    except (OSError, ValueError) as error:
        return None, f"cannot read input: {error}"


def _canonical_github_url(value: str) -> tuple[str | None, str | None]:
    match = GITHUB_URL_PATTERN.fullmatch(value)
    if match is None:
        return None, None
    repository = match.group("repository")
    return f"https://github.com/{repository}", repository


def _unquote_scalar(value: str) -> str | None:
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        unquoted = value[1:-1]
        if value[0] in unquoted or "\\" in unquoted:
            return None
        return unquoted
    if value.startswith(("'", '"')) or value.endswith(("'", '"')):
        return None
    return value


def _comment_tags(line: str) -> list[str]:
    return re.findall(rf"#\s*({SEMVER_TEXT})(?=\s|$)", line)


def _parse_pre_commit(root: Path, inspection: Inspection) -> None:
    path = ".pre-commit-config.yaml"
    lines, failure = _read_lines(root, path)
    if failure is not None or lines is None:
        inspection.failures.append(
            InspectionFailure(path, failure or "unknown read failure")
        )
        return

    repo_starts = [
        index
        for index, line in enumerate(lines)
        if re.match(r"^  - repo\s*:", line) is not None
    ]
    if not any(line == "repos:" for line in lines):
        inspection.failures.append(
            InspectionFailure(path, "cannot parse top-level repos list")
        )
        return

    for position, start in enumerate(repo_starts):
        end = (
            repo_starts[position + 1] if position + 1 < len(repo_starts) else len(lines)
        )
        block = lines[start:end]
        repo_line = block[0]
        repo_match = re.fullmatch(r"  - repo:\s*([^#]+?)\s*", repo_line)
        if repo_match is None:
            inspection.violations.append(
                _violation(path, start + 1, "repo must be one scalar value")
            )
            continue
        repo_value = _unquote_scalar(repo_match.group(1))
        if repo_value is None or any(character.isspace() for character in repo_value):
            inspection.violations.append(
                _violation(path, start + 1, "repo must be one scalar value")
            )
            continue
        if repo_value in {"local", "meta"}:
            continue

        repository_url, _ = _canonical_github_url(repo_value)
        if repository_url is None:
            inspection.violations.append(
                _violation(
                    path,
                    start + 1,
                    "remote repo must be a canonical public https://github.com/owner/repo URL",
                )
            )

        rev_fields = [
            (start + offset + 1, line)
            for offset, line in enumerate(block)
            if re.match(r"^\s+rev\s*:", line) is not None
        ]
        if len(rev_fields) != 1:
            inspection.violations.append(
                _violation(
                    path,
                    start + 1,
                    f"remote repo must declare exactly one rev field (found {len(rev_fields)})",
                )
            )
            continue

        rev_line_number, rev_line = rev_fields[0]
        scalar_match = re.match(r"^\s+rev:\s*([^#\s]+)", rev_line)
        raw_scalar = (
            scalar_match.group(1) if scalar_match is not None else "<non-scalar>"
        )
        scalar = _unquote_scalar(raw_scalar) or "<non-scalar>"
        sha_valid = SHA_PATTERN.fullmatch(scalar) is not None
        if not sha_valid:
            inspection.violations.append(
                _violation(
                    path,
                    rev_line_number,
                    "rev must be a 40-character lowercase hexadecimal SHA "
                    f"(found '{scalar}')",
                )
            )

        tags = _comment_tags(rev_line)
        exact_line = re.fullmatch(
            rf"\s+rev:\s*{re.escape(raw_scalar)}\s+#\s*(?P<tag>{SEMVER_TEXT})\s*",
            rev_line,
        )
        if len(tags) != 1 or exact_line is None:
            inspection.violations.append(
                _violation(
                    path,
                    rev_line_number,
                    "rev must have exactly one canonical '# vX.Y.Z' comment "
                    f"(found {len(tags)})",
                )
            )
            continue

        if sha_valid and repository_url is not None:
            inspection.pins.append(
                Pin(
                    path=path,
                    line=rev_line_number,
                    repository_url=repository_url,
                    sha=scalar,
                    tag=exact_line.group("tag"),
                )
            )


def _workflow_paths(tracked_paths: Sequence[str]) -> list[str]:
    return sorted(
        path
        for path in tracked_paths
        if PurePosixPath(path).parent == PurePosixPath(".github/workflows")
        and PurePosixPath(path).suffix in {".yaml", ".yml"}
    )


def _parse_workflow(root: Path, path: str, inspection: Inspection) -> None:
    lines, failure = _read_lines(root, path)
    if failure is not None or lines is None:
        inspection.failures.append(
            InspectionFailure(path, failure or "unknown read failure")
        )
        return

    for line_number, line in enumerate(lines, start=1):
        if "uses" not in line:
            continue
        uses_match = re.match(r"^\s*(?:-\s+)?uses\s*:\s*(.*?)\s*$", line)
        if uses_match is None:
            continue
        value = uses_match.group(1)
        raw_target = _remove_inline_comment(value).strip()
        target = _unquote_scalar(raw_target)
        if target is None:
            inspection.violations.append(
                _violation(path, line_number, "uses must be one scalar value")
            )
            continue
        if target.startswith("./"):
            continue
        if target.startswith("docker://"):
            inspection.violations.append(
                _violation(
                    path,
                    line_number,
                    "docker:// uses references are unsupported in this repository",
                )
            )
            continue

        target_match = ACTION_TARGET_PATTERN.fullmatch(target)
        if target_match is None:
            inspection.violations.append(
                _violation(
                    path,
                    line_number,
                    "external uses reference must be "
                    "owner/repo[/path]@<40-character lowercase hexadecimal SHA> "
                    f"(found '{target}')",
                )
            )

        tags = _comment_tags(value)
        exact_value = re.fullmatch(
            rf"{re.escape(raw_target)}\s+#\s*(?P<tag>{SEMVER_TEXT})\s*",
            value,
        )
        if len(tags) != 1 or exact_value is None:
            inspection.violations.append(
                _violation(
                    path,
                    line_number,
                    "external uses reference must have exactly one canonical "
                    f"'# vX.Y.Z' comment (found {len(tags)})",
                )
            )
            continue

        if target_match is not None:
            repository = target_match.group("repository")
            inspection.pins.append(
                Pin(
                    path=path,
                    line=line_number,
                    repository_url=f"https://github.com/{repository}",
                    sha=target_match.group("sha"),
                    tag=exact_value.group("tag"),
                )
            )


def _remove_inline_comment(line: str) -> str:
    quote: str | None = None
    escaped = False
    for index, character in enumerate(line):
        if escaped:
            escaped = False
            continue
        if character == "\\":
            escaped = True
            continue
        if quote is not None:
            if character == quote:
                quote = None
            continue
        if character in {"'", '"'}:
            quote = character
            continue
        if character == "#" and (index == 0 or line[index - 1].isspace()):
            return line[:index]
    return line


def _logical_requirement_records(lines: Sequence[str]) -> list[tuple[int, str]]:
    records: list[tuple[int, str]] = []
    current_line = 0
    current_parts: list[str] = []
    continued = False

    def finish() -> None:
        nonlocal current_line, current_parts
        if current_parts:
            records.append((current_line, " ".join(current_parts)))
        current_line = 0
        current_parts = []

    for line_number, physical_line in enumerate(lines, start=1):
        content = _remove_inline_comment(physical_line).strip()
        if not content:
            continue
        has_continuation = content.endswith("\\")
        if has_continuation:
            content = content[:-1].rstrip()
        is_hash_option = content.startswith("--hash")
        if not current_parts:
            current_line = line_number
        elif not continued and not is_hash_option:
            finish()
            current_line = line_number
        current_parts.append(content)
        continued = has_continuation
    finish()
    return records


def _normalized_distribution_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _parse_requirement_record(
    path: str,
    line: int,
    record: str,
    seen_names: dict[str, int],
    inspection: Inspection,
) -> None:
    tokens = record.split()
    hash_tokens = [token for token in tokens if token.startswith("--hash")]
    valid_hashes = [
        token for token in hash_tokens if HASH_PATTERN.fullmatch(token) is not None
    ]
    for token in hash_tokens:
        if HASH_PATTERN.fullmatch(token) is None:
            inspection.violations.append(
                _violation(
                    path,
                    line,
                    "hash must use --hash=sha256:<64 lowercase hexadecimal characters> "
                    f"(found '{token}')",
                )
            )

    unsupported_options = [
        token
        for token in tokens
        if token.startswith("-") and not token.startswith("--hash")
    ]
    for token in unsupported_options:
        inspection.violations.append(
            _violation(
                path,
                line,
                f"only --hash=sha256:<digest> options are permitted (found '{token}')",
            )
        )

    requirement_tokens = [
        token
        for token in tokens
        if not token.startswith("--hash") and not token.startswith("-")
    ]
    requirement_text = " ".join(requirement_tokens)
    specifier = requirement_text.split(";", maxsplit=1)[0].strip()
    marker = (
        requirement_text.split(";", maxsplit=1)[1].strip()
        if ";" in requirement_text
        else None
    )
    requirement_match = REQUIREMENT_PATTERN.fullmatch(specifier)
    if requirement_match is None:
        inspection.violations.append(
            _violation(
                path,
                line,
                "requirement must be a named distribution with exactly one == version pin "
                f"(found '{specifier or record}')",
            )
        )
    else:
        name = _normalized_distribution_name(requirement_match.group("name"))
        if name in seen_names:
            inspection.violations.append(
                _violation(
                    path,
                    line,
                    f"duplicate requirement name '{name}' "
                    f"(first declared at line {seen_names[name]})",
                )
            )
        else:
            seen_names[name] = line

    if marker is not None and not marker:
        inspection.violations.append(
            _violation(path, line, "environment marker must not be empty")
        )
    if not valid_hashes:
        inspection.violations.append(
            _violation(
                path,
                line,
                "requirement must include at least one "
                "--hash=sha256:<64 lowercase hexadecimal characters>",
            )
        )


def _requirement_paths(tracked_paths: Sequence[str]) -> list[str]:
    return sorted(
        path
        for path in tracked_paths
        if fnmatch.fnmatchcase(PurePosixPath(path).name, "requirements*.txt")
    )


def _parse_requirements(root: Path, path: str, inspection: Inspection) -> None:
    lines, failure = _read_lines(root, path)
    if failure is not None or lines is None:
        inspection.failures.append(
            InspectionFailure(path, failure or "unknown read failure")
        )
        return

    records = _logical_requirement_records(lines)
    inspection.requirement_records += len(records)
    seen_names: dict[str, int] = {}
    for line, record in records:
        _parse_requirement_record(path, line, record, seen_names, inspection)


def discover_tracked_paths(
    root: Path,
) -> tuple[list[str] | None, InspectionFailure | None]:
    """Return repository-relative tracked paths without consulting the network."""

    try:
        completed = subprocess.run(
            ["git", "-C", str(root), "ls-files", "-z"],
            check=False,
            capture_output=True,
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError) as error:
        return None, InspectionFailure(
            "<repository>", f"cannot enumerate tracked files: {error}"
        )
    if completed.returncode != 0:
        stderr = completed.stderr.decode("utf-8", errors="replace").strip()
        reason = stderr or f"git ls-files exited {completed.returncode}"
        return None, InspectionFailure(
            "<repository>", f"cannot enumerate tracked files: {reason}"
        )
    try:
        paths = completed.stdout.decode("utf-8").rstrip("\0").split("\0")
    except UnicodeDecodeError as error:
        return None, InspectionFailure(
            "<repository>", f"tracked path is not valid UTF-8: {error}"
        )
    return [path for path in paths if path], None


def inspect_repository(root: Path, tracked_paths: Sequence[str]) -> Inspection:
    """Inspect all pin-bearing inputs and return every deterministic finding."""

    inspection = Inspection(violations=[], failures=[], pins=[])
    _parse_pre_commit(root, inspection)
    for path in _workflow_paths(tracked_paths):
        _parse_workflow(root, path, inspection)
    for path in _requirement_paths(tracked_paths):
        _parse_requirements(root, path, inspection)
    return inspection


def _parse_remote_output(output: str) -> tuple[str, str]:
    refs: dict[str, set[str]] = {}
    for line in output.splitlines():
        fields = line.split()
        if len(fields) != 2 or SHA_PATTERN.fullmatch(fields[0]) is None:
            return AMBIGUOUS, "remote returned malformed ref data"
        refs.setdefault(fields[1], set()).add(fields[0])
    if not refs:
        return ABSENT, "declared tag is absent"
    if any(len(shas) != 1 for shas in refs.values()) or len(refs) > 2:
        return AMBIGUOUS, "declared tag resolved ambiguously"
    peeled_refs = [shas for ref, shas in refs.items() if ref.endswith("^{}")]
    direct_refs = [shas for ref, shas in refs.items() if not ref.endswith("^{}")]
    if len(peeled_refs) > 1 or len(direct_refs) > 1:
        return AMBIGUOUS, "declared tag resolved ambiguously"
    selected = (
        peeled_refs[0] if peeled_refs else direct_refs[0] if direct_refs else set()
    )
    if len(selected) != 1:
        return AMBIGUOUS, "declared tag resolved ambiguously"
    return MATCH, next(iter(selected))


def resolve_upstream(repository_url: str, tag: str, timeout: float) -> tuple[str, str]:
    """Resolve one public GitHub tag without credentials or shell evaluation."""

    if _canonical_github_url(repository_url)[0] is None:
        return INDETERMINATE, "repository URL is not canonical public GitHub HTTPS"
    direct_ref = f"refs/tags/{tag}"
    peeled_ref = f"{direct_ref}^{{}}"
    environment = {
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_TERMINAL_PROMPT": "0",
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": os.environ.get("PATH", ""),
    }
    try:
        completed = subprocess.run(
            [
                "git",
                "-c",
                "credential.helper=",
                "-c",
                "core.askPass=",
                "-c",
                "http.followRedirects=false",
                "ls-remote",
                repository_url,
                direct_ref,
                peeled_ref,
            ],
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
            env=environment,
        )
    except subprocess.TimeoutExpired:
        return INDETERMINATE, f"remote resolution exceeded {timeout:.1f}s timeout"
    except (OSError, subprocess.SubprocessError) as error:
        return INDETERMINATE, f"remote resolution failed: {error}"
    if completed.returncode != 0:
        detail = completed.stderr.strip().replace("\n", " ")
        return (
            INDETERMINATE,
            detail or f"git ls-remote exited {completed.returncode}",
        )
    return _parse_remote_output(completed.stdout)


def _static_result(inspection: Inspection) -> RunResult:
    if inspection.failures:
        lines = tuple(
            f"INSPECTION ERROR {failure.path}: {failure.reason}"
            for failure in inspection.failures
        ) + tuple(inspection.violations)
        return RunResult(EXIT_INDETERMINATE, lines)
    if inspection.violations:
        return RunResult(EXIT_VIOLATION, tuple(inspection.violations))
    record_label = (
        "requirement record"
        if inspection.requirement_records == 1
        else "requirement records"
    )
    reference_label = (
        "external reference" if len(inspection.pins) == 1 else "external references"
    )
    message = (
        f"Pin integrity check passed: {len(inspection.pins)} {reference_label}, "
        f"{inspection.requirement_records} {record_label}"
    )
    return RunResult(EXIT_CLEAN, (message,))


def _upstream_result(
    inspection: Inspection,
    resolver: Resolver,
    clock: Clock,
) -> RunResult:
    mismatch_lines = list(inspection.violations)
    indeterminate_lines = [
        f"UPSTREAM INPUT INDETERMINATE {failure.path}: {failure.reason}"
        for failure in inspection.failures
    ]
    match_lines: list[str] = []
    deadline = clock() + AGGREGATE_TIMEOUT_SECONDS

    for pin in inspection.pins:
        remaining = deadline - clock()
        location = f"{pin.path}:{pin.line}"
        if remaining <= 0:
            indeterminate_lines.append(
                f"UPSTREAM INDETERMINATE {location}: aggregate 60.0s timeout exceeded"
            )
            continue
        timeout = min(PER_REMOTE_TIMEOUT_SECONDS, remaining)
        status, detail = resolver(pin.repository_url, pin.tag, timeout)
        identity = f"{pin.repository_url} tag {pin.tag}"
        if status == MATCH:
            if detail == pin.sha:
                match_lines.append(
                    f"UPSTREAM MATCH {location}: {identity} resolves to {detail}"
                )
            else:
                mismatch_lines.append(
                    f"UPSTREAM MISMATCH {location}: {identity} resolves to {detail}, "
                    f"expected {pin.sha}"
                )
        elif status == MISMATCH:
            mismatch_lines.append(
                f"UPSTREAM MISMATCH {location}: {identity} resolves to {detail}, "
                f"expected {pin.sha}"
            )
        elif status == ABSENT:
            mismatch_lines.append(f"UPSTREAM MISMATCH {location}: {identity} is absent")
        elif status == AMBIGUOUS:
            mismatch_lines.append(
                f"UPSTREAM MISMATCH {location}: {identity} is ambiguous ({detail})"
            )
        else:
            indeterminate_lines.append(
                f"UPSTREAM INDETERMINATE {location}: {identity}: {detail}"
            )

    if mismatch_lines:
        return RunResult(
            EXIT_VIOLATION,
            tuple(mismatch_lines + indeterminate_lines + match_lines),
        )
    if indeterminate_lines:
        return RunResult(
            EXIT_INDETERMINATE,
            tuple(indeterminate_lines + match_lines),
        )
    return RunResult(EXIT_CLEAN, tuple(match_lines))


def check_repository(
    root: Path,
    *,
    verify_upstream: bool = False,
    tracked_paths: Sequence[str] | None = None,
    resolver: Resolver = resolve_upstream,
    clock: Clock = time.monotonic,
) -> RunResult:
    """Run one checker mode with injectable discovery and resolution seams."""

    paths = tracked_paths
    if paths is None:
        paths, failure = discover_tracked_paths(root)
        if failure is not None or paths is None:
            inspection = Inspection(
                violations=[],
                failures=[
                    failure or InspectionFailure("<repository>", "unknown failure")
                ],
                pins=[],
            )
            return (
                _upstream_result(inspection, resolver, clock)
                if verify_upstream
                else _static_result(inspection)
            )
    inspection = inspect_repository(root, paths)
    if verify_upstream:
        return _upstream_result(inspection, resolver, clock)
    return _static_result(inspection)


def _parse_arguments(arguments: Sequence[str]) -> tuple[bool | None, RunResult | None]:
    parser = UsageParser(add_help=False, prog="check-pins.py")
    parser.add_argument("--help", action="store_true")
    parser.add_argument("--verify-upstream", action="store_true")
    try:
        namespace = parser.parse_args(arguments)
    except ValueError as error:
        return None, RunResult(EXIT_USAGE, (f"USAGE ERROR: {error}",))
    if namespace.help:
        return None, RunResult(
            EXIT_CLEAN,
            (
                "usage: check-pins.py [--verify-upstream]",
                "default: deterministic static validation with no network access",
            ),
        )
    return bool(namespace.verify_upstream), None


def run(
    arguments: Sequence[str],
    *,
    root: Path | None = None,
    tracked_paths: Sequence[str] | None = None,
    resolver: Resolver = resolve_upstream,
    clock: Clock = time.monotonic,
) -> RunResult:
    """Parse arguments and run the checker; exposed for hermetic self-tests."""

    verify_upstream, early_result = _parse_arguments(arguments)
    if early_result is not None:
        return early_result
    return check_repository(
        root or Path.cwd(),
        verify_upstream=bool(verify_upstream),
        tracked_paths=tracked_paths,
        resolver=resolver,
        clock=clock,
    )


def main(arguments: Sequence[str] | None = None) -> int:
    """CLI entry point."""

    result = run(sys.argv[1:] if arguments is None else arguments)
    emit_result(result, sys.stdout, sys.stderr)
    return result.exit_code


def emit_result(
    result: RunResult,
    stdout: TextIO,
    stderr: TextIO,
) -> None:
    """Write a result to the contractually correct process stream."""

    stream = stdout if result.exit_code == EXIT_CLEAN else stderr
    for line in result.lines:
        print(line, file=stream)


if __name__ == "__main__":
    raise SystemExit(main())
