# ADR-0001: Treat the Runtime as a Tool Image

- Status: Accepted
- Date: 2026-07-28
- Scope: repo

## Context

Minimal base images in this family can omit both a shell and a language runtime.
An Ansible execution environment has a different responsibility: Python executes
the controller and modules, while Bash remains necessary for established
deployment tooling and task orchestration.

Removing either runtime would prevent the image from performing its intended
function. Adding them without documenting the different image class would also
make the deviation from the minimal base contract easy to mistake for accidental
bloat.

## Decision

The runtime image will include Python and Bash as deliberate tool-image
capabilities. Their presence is a repository-owned exception to the
shell-free and Python-free `base-micro` runtime class.

The exception does not authorize package managers or unrelated command-line
tools in the runtime. Later image work must define and test the smallest
dependency set that supports the Ansible controller and its declared helpers.

## Consequences

- Ansible and the repository's runtime helpers can execute in the image.
- The runtime has a larger attack surface than `base-micro`, so dependency
  pinning, vulnerability gates, and runtime assertions must cover both Bash and
  Python.
- Minimal-runtime expectations must be evaluated against this tool-image class,
  not against a shell-free application base.
