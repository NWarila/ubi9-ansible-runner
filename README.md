# ubi9-ansible-runner
Hardened UBI9 Ansible execution-environment image: runs deploy playbooks on ARC in the Talos cluster and extracts per-repo secrets from HashiCorp Vault via GitHub-OIDC JWT auth. FROM ubi9-base-python, SLSA-L3, cosign keyless signing, per-repo least-privilege secret access.
