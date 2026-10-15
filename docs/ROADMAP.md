# Public edition roadmap

This is a sanitized adaptation of the existing toolkit. An implemented feature stays implemented when private deployment bindings are removed; it is not reclassified as a future feature merely to simplify this edition.

## Available implementation

- Rust/npm/Bun Dockerfile and Compose scaffolding with no-overwrite behavior.
- Shared onboarding: no-TOML defaults, typed configuration, explicit overrides, workload selection, and path boundaries.
- Doctor/list/validate, local build/test-stage execution, OCI label comparison, and Trivy scans.
- Committed-source archives, candidate publication, digest checks, SBOM/provenance, and sealed retry evidence.
- Public Veriv-backed quality checks.
- Digest-pinned Compose delivery, pending/current/previous state, readiness, and rollback.
- PostgreSQL 17 checksummed backup, archive verification, and guarded restore.
- Development-only Kubernetes apply/status/rollback code.

## Validation boundaries

Local tests and disposable fixtures are the public edition's evidence. Private application acceptance records do not establish public support for arbitrary hosts or workloads. The local test commands are in the README; Linux-only publication/supervision tests require a Linux binary.

## Next verification work

- Exercise public publication/recovery paths against an isolated local registry and PostgreSQL instance.
- Verify Linux native execution of the sanitized edition and its operational deadline tests.
- Add isolated Kubernetes fixtures before claiming cluster acceptance.
- Rebuild and scan the sanitized toolbox image before distributing it.

## Future capabilities

- Podman publication and multiarchitecture manifests, after matching source/digest/retry tests.
- Additional PostgreSQL majors, with version and restore compatibility tests.
- Broader GitOps/Kubernetes and CI examples driven by reproducible public requirements.

No Production deployment, live infrastructure change, or automatic CI workflow is part of this cleanup.
