"""Hermetic, focused tests for every pin-integrity policy rule."""

from __future__ import annotations

import importlib.util
import io
import os
import sys
import tempfile
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Protocol, cast

SHA_HOOK = "cba56bcde1fdd01c1deb3f945e69764c291a6530"
SHA_ACTION = "9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0"
HASH_A = "a" * 64
HASH_B = "b" * 64

Resolver = Callable[[str, str, float], tuple[str, str]]
Clock = Callable[[], float]


class Result(Protocol):
    """Structural type returned by the checker."""

    exit_code: int
    lines: tuple[str, ...]


class Checker(Protocol):
    """Functions imported from the hyphenated checker filename."""

    def run(
        self,
        arguments: Sequence[str],
        *,
        root: Path | None = None,
        tracked_paths: Sequence[str] | None = None,
        expected_reference_count: int = ...,
        resolver: Resolver = ...,
        clock: Clock = ...,
    ) -> Result: ...

    def emit_result(
        self,
        result: Result,
        stdout: io.TextIOBase,
        stderr: io.TextIOBase,
    ) -> None: ...

    def _parse_remote_output(self, output: str) -> tuple[str, str]: ...


def _load_checker() -> Checker:
    checker_path = Path(__file__).with_name("check-pins.py")
    spec = importlib.util.spec_from_file_location("check_pins", checker_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {checker_path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return cast(Checker, module)


CHECKER = _load_checker()


def _base_config() -> str:
    return (
        "repos:\n"
        "  - repo: https://github.com/adrienverge/yamllint\n"
        f"    rev: {SHA_HOOK} # v1.38.0\n"
        "    hooks:\n"
        "      - id: yamllint\n"
    )


def _base_workflow() -> str:
    return (
        "name: Test\n"
        "on: push\n"
        "jobs:\n"
        "  test:\n"
        "    runs-on: ubuntu-24.04\n"
        "    steps:\n"
        f"      - uses: actions/checkout@{SHA_ACTION} # v7.0.0\n"
        "      - uses: ./local-action\n"
    )


def _base_requirements() -> str:
    return (
        'demo[cli]==1.0.0 ; python_version >= "3.12" \\\n'
        f"    --hash=sha256:{HASH_A} \\\n"
        "    # hashes may be separated by comments and blank lines\n"
        "\n"
        f"    --hash=sha256:{HASH_A}\n"
    )


def _scratch_root() -> Path:
    configured = os.environ.get("TMPDIR")
    root = Path(configured) if configured else Path.cwd() / ".cache" / "tmp"
    root.mkdir(parents=True, exist_ok=True)
    return root


def _write_fixture(
    root: Path,
    *,
    config: str | None = None,
    workflow: str | None = None,
    requirements: str | None = None,
) -> None:
    config_path = root / ".pre-commit-config.yaml"
    workflow_path = root / ".github" / "workflows" / "test.yaml"
    requirements_path = root / "requirements-test.txt"
    workflow_path.parent.mkdir(parents=True)
    config_path.write_text(
        config if config is not None else _base_config(), encoding="utf-8"
    )
    workflow_path.write_text(
        workflow if workflow is not None else _base_workflow(),
        encoding="utf-8",
    )
    requirements_path.write_text(
        requirements if requirements is not None else _base_requirements(),
        encoding="utf-8",
    )


def _tracked(
    *, workflow: bool = True, missing_workflow: bool = False
) -> tuple[str, ...]:
    paths = [".pre-commit-config.yaml", "requirements-test.txt"]
    if workflow:
        paths.append(".github/workflows/test.yaml")
    if missing_workflow:
        paths.append(".github/workflows/missing.yaml")
    return tuple(paths)


def _fixture_result(
    *,
    arguments: Sequence[str] = (),
    config: str | None = None,
    workflow: str | None = None,
    requirements: str | None = None,
    tracked_paths: Sequence[str] | None = None,
    expected_reference_count: int | None = None,
    resolver: Resolver | None = None,
    clock: Clock | None = None,
    remove_config: bool = False,
    invalid_config_utf8: bool = False,
) -> Result:
    with tempfile.TemporaryDirectory(
        dir=_scratch_root(), prefix="check-pins-"
    ) as temporary:
        root = Path(temporary)
        _write_fixture(
            root,
            config=config,
            workflow=workflow,
            requirements=requirements,
        )
        if remove_config:
            (root / ".pre-commit-config.yaml").unlink()
        if invalid_config_utf8:
            (root / ".pre-commit-config.yaml").write_bytes(b"\xff")
        effective_tracked_paths = (
            tracked_paths if tracked_paths is not None else _tracked()
        )
        effective_expected_count = (
            expected_reference_count
            if expected_reference_count is not None
            else (
                2
                if ".github/workflows/test.yaml" in effective_tracked_paths
                else 1
            )
        )
        options: dict[str, object] = {
            "root": root,
            "tracked_paths": effective_tracked_paths,
            "expected_reference_count": effective_expected_count,
        }
        if resolver is not None:
            options["resolver"] = resolver
        if clock is not None:
            options["clock"] = clock
        return CHECKER.run(arguments, **options)  # type: ignore[arg-type]


def _assert_result(
    name: str,
    result: Result,
    exit_code: int,
    *expected_lines: str,
) -> None:
    if result.exit_code != exit_code:
        raise AssertionError(
            f"{name}: expected exit {exit_code}, got {result.exit_code}: {result.lines}"
        )
    for expected in expected_lines:
        if expected not in result.lines:
            raise AssertionError(
                f"{name}: missing exact diagnostic {expected!r}: {result.lines}"
            )

    stdout = io.StringIO()
    stderr = io.StringIO()
    CHECKER.emit_result(result, stdout, stderr)
    rendered = "".join(f"{line}\n" for line in result.lines)
    expected_stdout = rendered if exit_code == 0 else ""
    expected_stderr = "" if exit_code == 0 else rendered
    if stdout.getvalue() != expected_stdout or stderr.getvalue() != expected_stderr:
        raise AssertionError(
            f"{name}: wrong output stream: stdout={stdout.getvalue()!r}, "
            f"stderr={stderr.getvalue()!r}"
        )
    details = " | ".join(expected_lines)
    print(f"PASS {name} [exit {exit_code}]: {details}")


def _assert_value(name: str, actual: object, expected: object) -> None:
    if actual != expected:
        raise AssertionError(f"{name}: expected {expected!r}, got {actual!r}")
    print(f"PASS {name}: {expected!r}")


def _static_cases() -> None:
    clean = "Pin integrity check passed: 2 external references, 1 requirement record"
    _assert_result("clean_tree", _fixture_result(), 0, clean)

    def reject_network(_url: str, _tag: str, _timeout: float) -> tuple[str, str]:
        raise AssertionError("static mode attempted upstream resolution")

    _assert_result(
        "static_mode_no_network",
        _fixture_result(resolver=reject_network),
        0,
        clean,
    )

    tag_config = _base_config().replace(SHA_HOOK, "v1.38.0")
    _assert_result(
        "hook_tag_instead_of_sha",
        _fixture_result(config=tag_config),
        1,
        "POLICY VIOLATION .pre-commit-config.yaml:3: rev must be a 40-character "
        "lowercase hexadecimal SHA (found 'v1.38.0')",
    )
    short_config = _base_config().replace(SHA_HOOK, SHA_HOOK[:12])
    _assert_result(
        "hook_short_sha",
        _fixture_result(config=short_config),
        1,
        "POLICY VIOLATION .pre-commit-config.yaml:3: rev must be a 40-character "
        f"lowercase hexadecimal SHA (found '{SHA_HOOK[:12]}')",
    )
    uppercase_config = _base_config().replace(SHA_HOOK, SHA_HOOK.upper())
    _assert_result(
        "hook_uppercase_sha",
        _fixture_result(config=uppercase_config),
        1,
        "POLICY VIOLATION .pre-commit-config.yaml:3: rev must be a 40-character "
        f"lowercase hexadecimal SHA (found '{SHA_HOOK.upper()}')",
    )
    missing_rev = _base_config().replace(f"    rev: {SHA_HOOK} # v1.38.0\n", "")
    _assert_result(
        "hook_missing_rev",
        _fixture_result(config=missing_rev),
        1,
        "POLICY VIOLATION .pre-commit-config.yaml:2: remote repo must declare "
        "exactly one rev field (found 0)",
    )
    duplicate_rev = _base_config().replace(
        f"    rev: {SHA_HOOK} # v1.38.0\n",
        f"    rev: {SHA_HOOK} # v1.38.0\n    rev: {SHA_HOOK} # v1.38.0\n",
    )
    _assert_result(
        "hook_duplicate_rev",
        _fixture_result(config=duplicate_rev),
        1,
        "POLICY VIOLATION .pre-commit-config.yaml:2: remote repo must declare "
        "exactly one rev field (found 2)",
    )
    missing_comment = _base_config().replace(" # v1.38.0", "")
    _assert_result(
        "hook_missing_comment",
        _fixture_result(config=missing_comment),
        1,
        "POLICY VIOLATION .pre-commit-config.yaml:3: rev must have exactly one "
        "canonical '# vX.Y.Z' comment (found 0)",
    )
    duplicate_comment = _base_config().replace(
        "# v1.38.0",
        "# v1.38.0 # v1.38.0",
    )
    _assert_result(
        "hook_duplicate_comment",
        _fixture_result(config=duplicate_comment),
        1,
        "POLICY VIOLATION .pre-commit-config.yaml:3: rev must have exactly one "
        "canonical '# vX.Y.Z' comment (found 2)",
    )
    bad_repo = _base_config().replace(
        "https://github.com/adrienverge/yamllint",
        "git@github.com:adrienverge/yamllint",
    )
    _assert_result(
        "hook_noncanonical_remote",
        _fixture_result(config=bad_repo),
        1,
        "POLICY VIOLATION .pre-commit-config.yaml:2: remote repo must be a "
        "canonical public https://github.com/owner/repo URL",
    )
    flow_config = (
        "repos:\n"
        "  - {repo: 'https://github.com/adrienverge/yamllint', "
        "rev: v1.38.0, hooks: [{id: yamllint}]}\n"
    )
    _assert_result(
        "hook_flow_mapping_tag",
        _fixture_result(config=flow_config),
        1,
        "POLICY VIOLATION .pre-commit-config.yaml:2: rev must be a 40-character "
        "lowercase hexadecimal SHA (found 'v1.38.0')",
    )
    zero_space_config = (
        "repos:\n"
        "- repo: https://github.com/adrienverge/yamllint\n"
        "  rev: v1.38.0\n"
        "  hooks:\n"
        "    - id: yamllint\n"
    )
    _assert_result(
        "hook_zero_space_indent",
        _fixture_result(config=zero_space_config),
        1,
        "POLICY VIOLATION .pre-commit-config.yaml:3: rev must be a 40-character "
        "lowercase hexadecimal SHA (found 'v1.38.0')",
    )
    four_space_config = (
        "repos:\n"
        "    - repo: https://github.com/adrienverge/yamllint\n"
        "      rev: v1.38.0\n"
        "      hooks:\n"
        "        - id: yamllint\n"
    )
    _assert_result(
        "hook_four_space_indent",
        _fixture_result(config=four_space_config),
        1,
        "POLICY VIOLATION .pre-commit-config.yaml:3: rev must be a 40-character "
        "lowercase hexadecimal SHA (found 'v1.38.0')",
    )

    action_v7 = _base_workflow().replace(f"@{SHA_ACTION}", "@v7")
    _assert_result(
        "action_tag_instead_of_sha",
        _fixture_result(workflow=action_v7),
        1,
        "POLICY VIOLATION .github/workflows/test.yaml:7: external uses reference "
        "must be owner/repo[/path]@<40-character lowercase hexadecimal SHA> "
        "(found 'actions/checkout@v7')",
    )
    flow_workflow = _base_workflow().replace(
        f"      - uses: actions/checkout@{SHA_ACTION} # v7.0.0\n",
        "      - {name: Check out, uses: 'actions/checkout@v7'}\n",
    )
    _assert_result(
        "action_flow_mapping_tag",
        _fixture_result(workflow=flow_workflow),
        1,
        "POLICY VIOLATION .github/workflows/test.yaml:7: external uses reference "
        "must be owner/repo[/path]@<40-character lowercase hexadecimal SHA> "
        "(found 'actions/checkout@v7')",
    )
    action_short = _base_workflow().replace(SHA_ACTION, SHA_ACTION[:12])
    _assert_result(
        "action_short_sha",
        _fixture_result(workflow=action_short),
        1,
        "POLICY VIOLATION .github/workflows/test.yaml:7: external uses reference "
        "must be owner/repo[/path]@<40-character lowercase hexadecimal SHA> "
        f"(found 'actions/checkout@{SHA_ACTION[:12]}')",
    )
    action_upper = _base_workflow().replace(SHA_ACTION, SHA_ACTION.upper())
    _assert_result(
        "action_uppercase_sha",
        _fixture_result(workflow=action_upper),
        1,
        "POLICY VIOLATION .github/workflows/test.yaml:7: external uses reference "
        "must be owner/repo[/path]@<40-character lowercase hexadecimal SHA> "
        f"(found 'actions/checkout@{SHA_ACTION.upper()}')",
    )
    action_missing_comment = _base_workflow().replace(" # v7.0.0", "")
    _assert_result(
        "action_missing_comment",
        _fixture_result(workflow=action_missing_comment),
        1,
        "POLICY VIOLATION .github/workflows/test.yaml:7: external uses reference "
        "must have exactly one canonical '# vX.Y.Z' comment (found 0)",
    )
    action_duplicate_comment = _base_workflow().replace(
        "# v7.0.0",
        "# v7.0.0 # v7.0.0",
    )
    _assert_result(
        "action_duplicate_comment",
        _fixture_result(workflow=action_duplicate_comment),
        1,
        "POLICY VIOLATION .github/workflows/test.yaml:7: external uses reference "
        "must have exactly one canonical '# vX.Y.Z' comment (found 2)",
    )
    docker_action = _base_workflow().replace(
        f"actions/checkout@{SHA_ACTION} # v7.0.0",
        "docker://example.invalid/tool:1.0.0",
    )
    _assert_result(
        "docker_action_unsupported",
        _fixture_result(workflow=docker_action),
        1,
        "POLICY VIOLATION .github/workflows/test.yaml:7: docker:// uses references "
        "are unsupported in this repository",
    )
    local_workflow = _base_workflow().replace(
        f"      - uses: actions/checkout@{SHA_ACTION} # v7.0.0\n",
        "",
    )
    _assert_result(
        "local_action_exempt",
        _fixture_result(
            workflow=local_workflow,
            expected_reference_count=1,
        ),
        0,
        "Pin integrity check passed: 1 external reference, 1 requirement record",
    )
    quoted_local_workflow = local_workflow.replace("./local-action", '"./local-action"')
    _assert_result(
        "quoted_local_action_exempt",
        _fixture_result(
            workflow=quoted_local_workflow,
            expected_reference_count=1,
        ),
        0,
        "Pin integrity check passed: 1 external reference, 1 requirement record",
    )
    run_block_workflow = _base_workflow().replace(
        "      - uses: ./local-action\n",
        "      - run: |\n"
        "          cat <<'PIN_TEXT'\n"
        "          uses: actions/setup-python@v6\n"
        "          PIN_TEXT\n"
        "      - uses: ./local-action\n",
    )
    _assert_result(
        "workflow_run_block_uses_text",
        _fixture_result(workflow=run_block_workflow),
        0,
        clean,
    )
    _assert_result(
        "external_reference_count_drop",
        _fixture_result(
            workflow=local_workflow,
            expected_reference_count=2,
        ),
        1,
        "POLICY VIOLATION <repository>:1: expected exactly 2 external references, "
        "discovered 1",
    )

    _assert_result(
        "requirement_unhashed",
        _fixture_result(requirements="demo==1.0.0\n"),
        1,
        "POLICY VIOLATION requirements-test.txt:1: requirement must include at "
        "least one --hash=sha256:<64 lowercase hexadecimal characters>",
    )
    _assert_result(
        "requirement_unpinned",
        _fixture_result(requirements=f"demo>=1.0.0 --hash=sha256:{HASH_A}\n"),
        1,
        "POLICY VIOLATION requirements-test.txt:1: requirement must be a named "
        "distribution with exactly one == version pin (found 'demo>=1.0.0')",
    )
    _assert_result(
        "requirement_missing_version",
        _fixture_result(requirements=f"demo --hash=sha256:{HASH_A}\n"),
        1,
        "POLICY VIOLATION requirements-test.txt:1: requirement must be a named "
        "distribution with exactly one == version pin (found 'demo')",
    )
    malformed_hashes = (
        ("requirement_hash_algorithm", f"--hash=sha512:{HASH_A}"),
        ("requirement_hash_length", f"--hash=sha256:{HASH_A[:-1]}"),
        ("requirement_hash_uppercase", f"--hash=sha256:{HASH_A.upper()}"),
        ("requirement_hash_missing_sha256", f"--hash={HASH_A}"),
    )
    for name, hash_option in malformed_hashes:
        _assert_result(
            name,
            _fixture_result(requirements=f"demo==1.0.0 {hash_option}\n"),
            1,
            "POLICY VIOLATION requirements-test.txt:1: hash must use "
            "--hash=sha256:<64 lowercase hexadecimal characters> "
            f"(found '{hash_option}')",
        )

    forbidden_options = (
        ("requirement_editable", "-e"),
        ("requirement_include", "-r"),
        ("requirement_constraint", "-c"),
        ("requirement_index_url", "--index-url"),
        ("requirement_find_links", "--find-links"),
    )
    for name, option in forbidden_options:
        requirement = f"{option} demo==1.0.0 --hash=sha256:{HASH_A}\n"
        _assert_result(
            name,
            _fixture_result(requirements=requirement),
            1,
            "POLICY VIOLATION requirements-test.txt:1: only "
            f"--hash=sha256:<digest> options are permitted (found '{option}')",
        )

    _assert_result(
        "requirement_vcs",
        _fixture_result(
            requirements=(
                "git+https://github.com/example/demo.git@"
                f"{SHA_HOOK} --hash=sha256:{HASH_A}\n"
            )
        ),
        1,
        "POLICY VIOLATION requirements-test.txt:1: requirement must be a named "
        "distribution with exactly one == version pin "
        f"(found 'git+https://github.com/example/demo.git@{SHA_HOOK}')",
    )
    _assert_result(
        "requirement_direct_url",
        _fixture_result(
            requirements=(
                f"demo @ https://example.invalid/demo.whl --hash=sha256:{HASH_A}\n"
            )
        ),
        1,
        "POLICY VIOLATION requirements-test.txt:1: requirement must be a named "
        "distribution with exactly one == version pin "
        "(found 'demo @ https://example.invalid/demo.whl')",
    )
    _assert_result(
        "requirement_range",
        _fixture_result(requirements=f"demo>=1,<2 --hash=sha256:{HASH_A}\n"),
        1,
        "POLICY VIOLATION requirements-test.txt:1: requirement must be a named "
        "distribution with exactly one == version pin (found 'demo>=1,<2')",
    )
    _assert_result(
        "requirement_wildcard",
        _fixture_result(requirements=f"demo==1.* --hash=sha256:{HASH_A}\n"),
        1,
        "POLICY VIOLATION requirements-test.txt:1: requirement must be a named "
        "distribution with exactly one == version pin (found 'demo==1.*')",
    )
    _assert_result(
        "requirement_extras_and_marker",
        _fixture_result(
            requirements=(
                f'demo[cli]==1.0.0 ; python_version >= "3.12" --hash=sha256:{HASH_A}\n'
            )
        ),
        0,
        clean,
    )
    _assert_result(
        "requirement_duplicate_hash_allowed",
        _fixture_result(
            requirements=(
                f"demo==1.0.0 --hash=sha256:{HASH_A} --hash=sha256:{HASH_A}\n"
            )
        ),
        0,
        clean,
    )
    duplicate_name = (
        f"demo==1.0.0 --hash=sha256:{HASH_A}\nDemo[cli]==1.0.1 --hash=sha256:{HASH_B}\n"
    )
    _assert_result(
        "requirement_duplicate_name",
        _fixture_result(requirements=duplicate_name),
        1,
        "POLICY VIOLATION requirements-test.txt:2: duplicate requirement name "
        "'demo' (first declared at line 1)",
    )

    _assert_result(
        "invalid_invocation",
        _fixture_result(arguments=("--unknown",)),
        64,
        "USAGE ERROR: unrecognized arguments: --unknown",
    )
    _assert_result(
        "static_unreadable_input_precedence",
        _fixture_result(
            requirements="demo>=1\n",
            tracked_paths=_tracked(missing_workflow=True),
        ),
        2,
        "INSPECTION ERROR .github/workflows/missing.yaml: cannot read input: "
        "file does not exist",
        "POLICY VIOLATION requirements-test.txt:1: requirement must be a named "
        "distribution with exactly one == version pin (found 'demo>=1')",
    )


def _upstream_cases() -> None:
    tracked = _tracked(workflow=False)
    location = ".pre-commit-config.yaml:3"
    identity = "https://github.com/adrienverge/yamllint tag v1.38.0"

    def matching(_url: str, _tag: str, _timeout: float) -> tuple[str, str]:
        return "match", SHA_HOOK

    _assert_result(
        "upstream_match",
        _fixture_result(
            arguments=("--verify-upstream",),
            tracked_paths=tracked,
            resolver=matching,
        ),
        0,
        f"UPSTREAM MATCH {location}: {identity} resolves to {SHA_HOOK}",
    )

    observed_timeouts: list[float] = []

    def record_timeout(_url: str, _tag: str, timeout: float) -> tuple[str, str]:
        observed_timeouts.append(timeout)
        return "match", SHA_HOOK

    _fixture_result(
        arguments=("--verify-upstream",),
        tracked_paths=tracked,
        resolver=record_timeout,
    )
    _assert_value("upstream_per_remote_timeout", observed_timeouts, [10.0])

    def mismatch(_url: str, _tag: str, _timeout: float) -> tuple[str, str]:
        return "mismatch", "f" * 40

    _assert_result(
        "upstream_mismatch",
        _fixture_result(
            arguments=("--verify-upstream",),
            tracked_paths=tracked,
            resolver=mismatch,
        ),
        1,
        f"UPSTREAM MISMATCH {location}: {identity} resolves to {'f' * 40}, "
        f"expected {SHA_HOOK}",
    )

    outcomes = (
        ("upstream_absent", "absent", "tag absent", 1, f"{identity} is absent"),
        (
            "upstream_ambiguous",
            "ambiguous",
            "multiple refs",
            1,
            f"{identity} is ambiguous (multiple refs)",
        ),
        (
            "upstream_timeout",
            "indeterminate",
            "remote resolution exceeded 10.0s timeout",
            2,
            f"{identity}: remote resolution exceeded 10.0s timeout",
        ),
        (
            "upstream_auth_failure",
            "indeterminate",
            "authentication failed",
            2,
            f"{identity}: authentication failed",
        ),
    )
    for name, status, detail, code, expected in outcomes:

        def fake(
            _url: str,
            _tag: str,
            _timeout: float,
            *,
            result_status: str = status,
            result_detail: str = detail,
        ) -> tuple[str, str]:
            return result_status, result_detail

        prefix = "UPSTREAM MISMATCH" if code == 1 else "UPSTREAM INDETERMINATE"
        _assert_result(
            name,
            _fixture_result(
                arguments=("--verify-upstream",),
                tracked_paths=tracked,
                resolver=fake,
            ),
            code,
            f"{prefix} {location}: {expected}",
        )

    lightweight_output = f"{SHA_HOOK}\trefs/tags/v1.38.0\n"
    _assert_value(
        "resolver_lightweight_tag",
        CHECKER._parse_remote_output(lightweight_output),
        ("match", SHA_HOOK),
    )
    annotated_output = (
        f"{'d' * 40}\trefs/tags/v1.38.0\n{SHA_HOOK}\trefs/tags/v1.38.0^{{}}\n"
    )
    _assert_value(
        "resolver_annotated_tag_uses_peeled_commit",
        CHECKER._parse_remote_output(annotated_output),
        ("match", SHA_HOOK),
    )
    _assert_value(
        "resolver_missing_tag",
        CHECKER._parse_remote_output(""),
        ("absent", "declared tag is absent"),
    )
    malformed_output = "not-a-sha\trefs/tags/v1.38.0\n"
    _assert_value(
        "resolver_malformed_output",
        CHECKER._parse_remote_output(malformed_output),
        ("ambiguous", "remote returned malformed ref data"),
    )

    def mixed(url: str, _tag: str, _timeout: float) -> tuple[str, str]:
        if url.endswith("/yamllint"):
            return "mismatch", "f" * 40
        return "indeterminate", "transport unavailable"

    action_identity = "https://github.com/actions/checkout tag v7.0.0"
    _assert_result(
        "upstream_mismatch_precedes_indeterminate",
        _fixture_result(
            arguments=("--verify-upstream",),
            resolver=mixed,
        ),
        1,
        f"UPSTREAM MISMATCH {location}: {identity} resolves to {'f' * 40}, "
        f"expected {SHA_HOOK}",
        "UPSTREAM INDETERMINATE .github/workflows/test.yaml:7: "
        f"{action_identity}: transport unavailable",
    )

    class SequenceClock:
        def __init__(self) -> None:
            self._values = iter((0.0, 61.0))

        def __call__(self) -> float:
            return next(self._values)

    _assert_result(
        "upstream_aggregate_timeout",
        _fixture_result(
            arguments=("--verify-upstream",),
            tracked_paths=tracked,
            resolver=matching,
            clock=SequenceClock(),
        ),
        2,
        f"UPSTREAM INDETERMINATE {location}: aggregate 60.0s timeout exceeded",
    )

    malformed_config = _base_config().replace(SHA_HOOK, "v1.38.0")
    _assert_result(
        "upstream_readable_malformed_declaration",
        _fixture_result(
            arguments=("--verify-upstream",),
            config=malformed_config,
            tracked_paths=tracked,
            resolver=matching,
        ),
        1,
        "POLICY VIOLATION .pre-commit-config.yaml:3: rev must be a 40-character "
        "lowercase hexadecimal SHA (found 'v1.38.0')",
    )
    _assert_result(
        "upstream_unreadable_input",
        _fixture_result(
            arguments=("--verify-upstream",),
            tracked_paths=tracked,
            resolver=matching,
            remove_config=True,
        ),
        2,
        "UPSTREAM INPUT INDETERMINATE .pre-commit-config.yaml: cannot read input: "
        "file does not exist",
    )
    _assert_result(
        "upstream_unparseable_input",
        _fixture_result(
            arguments=("--verify-upstream",),
            tracked_paths=tracked,
            resolver=matching,
            invalid_config_utf8=True,
        ),
        2,
        "UPSTREAM INPUT INDETERMINATE .pre-commit-config.yaml: input is not valid "
        "UTF-8: 'utf-8' codec can't decode byte 0xff in position 0: invalid start byte",
    )


def main() -> int:
    """Run every focused fixture without public network access."""

    _static_cases()
    _upstream_cases()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
