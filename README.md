# UBI 9 Ansible Runner

This repository is the scaffold for a UBI 9 Ansible execution-environment image.
The planned image will provide the Ansible runtime used by deployment repositories
while keeping each consumer's framework and playbooks outside the image.

No image has been published, and no container build exists in this repository yet.
The current contents establish governance, documentation, decision records,
dependency-update policy, and a deterministic lint gate for later implementation.

## Repository status

- Repository version: `0.1.0`
- Published image: none
- Build and release workflows: not yet present
- Available quality gate: lint

## Documentation

Start with the [documentation index](docs/README.md). Design decisions are recorded
under [`docs/decision-records/`](docs/decision-records/), and known maintenance
obligations are tracked in [`docs/TECH-DEBT.md`](docs/TECH-DEBT.md).

Contributions should follow [CONTRIBUTING.md](CONTRIBUTING.md). Security reports
should follow [SECURITY.md](SECURITY.md).
