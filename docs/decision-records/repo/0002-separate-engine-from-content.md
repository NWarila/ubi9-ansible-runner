# ADR-0002: Separate the Engine From Consumer Content

- Status: Accepted
- Date: 2026-07-28
- Scope: repo

## Context

Deployment repositories need a consistent Ansible controller, but they do not
all move their framework and playbooks at the same cadence. Baking that content
into the execution image would couple image releases to consumer repositories,
duplicate each consumer's source of truth, and make a digest pin insufficient
to explain which playbook revision ran.

Consumers already identify their framework revision with an immutable commit
pin. Preserving that boundary keeps application delivery decisions with the
repository that owns the deployment.

## Decision

The image is the execution engine only. It will provide Ansible, its pinned
runtime dependencies, approved collections, and repository-owned helper
interfaces.

The shared Ansible framework and all consumer playbooks are never baked into the
image. At run time, each consumer composes its content from that repository's
immutable framework commit pin and its own checked-out playbooks.

## Consequences

- One image release can serve consumers on different content revisions.
- Image provenance describes the engine, while the workflow and checked-out
  commits describe the content used for a deployment.
- Consumers must retain and review immutable content pins.
- Composition must fail closed when a declared commit cannot be resolved or
  does not match the requested revision.
