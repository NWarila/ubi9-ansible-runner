# Contributing

This repository will build the UBI 9 Ansible execution environment used by
deployment repositories. Keep contributions focused, reproducible, and consistent
with the decisions under `docs/decision-records/`.

## Prerequisites

- Git with commit signing configured.
- Python 3.12.3.
- Network access when the hook environments are first installed.

The lint tool installer is hash-locked in `requirements-lint.txt`. The hook
repositories are pinned to immutable commits in `.pre-commit-config.yaml`.
The required pin-integrity hook checks pin and hash structure without accessing
the network. It makes malformed or absent version comments, mutable action or
hook references, and unpinned or unhashed requirement records merge-blocking.
Upstream tag truth is separate maintainer evidence, not part of the required
status.

## Local verification

Run the same installation and lint commands used by continuous integration:

```sh
python3 -m pip install \
  --disable-pip-version-check \
  --require-hashes \
  --target .lint-tools \
  -r requirements-lint.txt
mkdir -p "${PWD}/.cache/tmp"
GOCACHE="${PWD}/.cache/go-build" \
  GOPATH="${PWD}/.cache/go" \
  npm_config_cache="${PWD}/.cache/npm" \
  PRE_COMMIT_HOME="${PWD}/.cache/pre-commit" \
  PYTHONPATH="${PWD}/.lint-tools" \
  TMPDIR="${PWD}/.cache/tmp" \
  python3 -m pre_commit run --all-files --show-diff-on-failure
```

The default-deny `.gitignore` leaves `.lint-tools/` and `.cache/` untracked.

When changing an external pin, maintainers can separately compare each declared
tag to its commit. This command is fail-closed evidence: exit 1 reports a
confirmed mismatch, while exit 2 means verification was indeterminate.

```sh
PYTHONPATH="${PWD}/.lint-tools" \
  python3 tools/check-pins.py --verify-upstream
```

## Updating lint tools

Regenerate the hash lock under Python 3.12.3 with pip-tools 7.6.0. The temporary
input preserves every currently selected version, so adding a tool cannot
silently move the audited closure:

```sh
python3 -m pip install \
  --disable-pip-version-check \
  --target .cache/lock-tools \
  pip-tools==7.6.0
printf '%s\n' \
  'cfgv==3.5.0' \
  'distlib==0.4.3' \
  'filelock==3.32.0' \
  'identify==2.6.19' \
  'mypy==2.3.0' \
  'nodeenv==1.10.0' \
  'platformdirs==4.11.0' \
  'pre-commit==4.6.1' \
  'python-discovery==1.5.0' \
  'pyyaml==6.0.3' \
  'ruff==0.16.0' \
  'virtualenv==21.7.0' \
  >.cache/requirements-lint.in
PYTHONPATH="${PWD}/.cache/lock-tools" \
  python3 -m piptools compile \
  --cache-dir "${PWD}/.cache/pip-tools" \
  --generate-hashes \
  --no-strip-extras \
  --output-file requirements-lint.txt \
  .cache/requirements-lint.in
```

## Pull requests

Before opening a pull request:

1. Keep the change within one coherent purpose.
2. Sign every commit.
3. Run the full lint command and include the result in the pull request.
4. Update documentation and decision records when behavior or policy changes.
5. Add the narrowest `.gitignore` allowlist entries needed for new tracked files.

Do not file public issues or pull requests for vulnerabilities. Follow
[SECURITY.md](SECURITY.md) instead.
