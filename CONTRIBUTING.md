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

## Local verification

Run the same installation and lint commands used by continuous integration:

```sh
python3 -m pip install \
  --disable-pip-version-check \
  --require-hashes \
  --target .lint-tools \
  -r requirements-lint.txt
GOCACHE="${PWD}/.cache/go-build" \
  GOPATH="${PWD}/.cache/go" \
  npm_config_cache="${PWD}/.cache/npm" \
  PRE_COMMIT_HOME="${PWD}/.cache/pre-commit" \
  PYTHONPATH="${PWD}/.lint-tools" \
  python3 -m pre_commit run --all-files --show-diff-on-failure
```

The default-deny `.gitignore` leaves `.lint-tools/` and `.cache/` untracked.

## Pull requests

Before opening a pull request:

1. Keep the change within one coherent purpose.
2. Sign every commit.
3. Run the full lint command and include the result in the pull request.
4. Update documentation and decision records when behavior or policy changes.
5. Add the narrowest `.gitignore` allowlist entries needed for new tracked files.

Do not file public issues or pull requests for vulnerabilities. Follow
[SECURITY.md](SECURITY.md) instead.
