# ADR-0003: Version Ansible Core Streams Explicitly

- Status: Accepted
- Date: 2026-07-28
- Scope: repo

## Context

The first consumers manage RHEL 8 and Rocky Linux 8 targets. Their platform
Python compatibility requires the `ansible-core` 2.16 line, with `2.16.19` as
the launch floor. That line needs a clear distinction between immutable release
identity, convenient stream discovery, and the reference consumers trust in
automation.

A moving stream tag alone cannot identify the exact bytes a consumer ran.
Conversely, immutable full-version tags alone do not provide a convenient way
to discover the newest reviewed build within a compatible stream.

## Decision

The image tag scheme has three separate roles:

1. A full-version tag such as `:2.16.19` is immutable. Once published, it never
   moves to different image content.
2. The `:2.16` tag is a moving discovery tag for the newest reviewed release in
   the 2.16 stream. It is not a stable deployment reference.
3. Consumers use a registry digest for execution. The digest, not either tag,
   is the authoritative immutable image reference in deployment workflows.

Only streams with a real consumer are published. The 2.16 stream exists for
RHEL 8 and Rocky Linux 8 target compatibility and carries the maintenance
obligation in [TD-1](../../TECH-DEBT.md#td-1-ansible-core-216-stream).

## Consequences

- Full-version tags provide human-readable immutable release identities.
- The moving stream tag supports discovery without weakening consumer
  immutability.
- Digest updates remain explicit, reviewable consumer changes.
- Maintainers must monitor 2.16 security maintenance and apply the TD-1 exit
  condition when the target constraint ends or fixes become unacceptable.
