# Publication and recovery

These commands retain the original safety contracts. They need reviewed inputs and authority over the selected local engine, registry, service, or database. The public examples do not include credentials or private endpoints.

## Publish committed source

`publish` accepts the same workload selection and defaults as build. It requires a clean committed Git context, Docker Buildx, Linux amd64, Trivy, and registry authentication configured outside the repository.

```sh
devops-tool publish --registry localhost:5000/demo --evidence-dir /path/outside/checkout/evidence
```

This previews only. Review the plan before adding `--execute`. Use an isolated local registry for testing; the CLI does not start one automatically. Evidence storage must be private, durable, and outside the whole source checkout.

Publication archives the exact committed context, builds one candidate, scans its digest, records SBOM/provenance and checksums, and promotes that same digest. Ignored/untracked files are excluded; committed sensitive files would still be included. Symlinks, submodules, and archive-changing Git attributes are rejected. Keep build inputs free of secrets.

`scan` and `publish` remove inherited `TRIVY_*` variables and run Trivy from a fresh private, empty directory. They explicitly disable project configuration/ignore files; the empty directory also prevents fallback file loading with older Trivy versions. Docker credentials, proxy settings, and the normal home-directory cache remain available. Vulnerabilities gate HIGH/CRITICAL findings; a separate secret gate checks every severity and is not narrowed by `--os-only` or `--ignore-unfixed`. Detected secrets and raw child output are never printed automatically. Publication retains private reports and seals the effective policy plus the secret report. Legacy publication inputs cannot silently reuse this newer policy.

On Windows, publication evidence and delivery state must be owned by and grant access only to the current user. Unsafe existing ACLs fail closed and are not silently rewritten. Newly created delivery directories receive a protected, inheritable owner-only ACL. Provision private evidence/lock roots before use. Raw evidence can contain secrets; do not upload it unreviewed.

Interrupted builds, conflicting tags, changed source or inputs, incomplete metadata, and altered seals stop for review. Do not delete state or retag images to force a retry. A matching completed candidate may be rescanned and reused. A hash seal detects changes; it does not defend against an administrator able to replace both evidence and its seal.

## Compose delivery and rollback

`deploy` and `rollback` operate on one explicitly selected Compose service, an explicit local Docker context, durable private state, and sealed publication evidence with an independently transferred checksum. Deployment uses a digest, checks readiness, and retains current/previous state. Failed readiness restores the previous release; pending state requires explicit recovery before retrying.

Use one designated publisher host per daemon/project/service. All writers must share its lock root: `/var/lib/devops-tool/delivery-locks` on Linux or `%ProgramData%\devops-tool\delivery-locks` on Windows. Provision private permissions before use. Moving a lock root or state directory can break mutual exclusion and recovery.

Run `devops-tool deploy --help` and `devops-tool rollback --help` for required options. Keep live service configuration and environment files outside this public repository. No supplied example targets an existing deployment.

## PostgreSQL 17 recovery

Database commands use `[postgres]` in configuration or standard PostgreSQL connection environment variables. Passwords are read from a named environment variable; do not put them in command arguments, example files, or logs. Require appropriate TLS when connecting beyond a disposable local fixture.

Backup reserves a private file without overwriting, runs `pg_dump` in custom format, and writes a SHA-256 sidecar. `verify-backup` checks both the hash and archive structure. Restore checks supported client/server versions and the selected target, then requires `--execute`, an exact database-name confirmation, and an exact host:port/database confirmation. It uses a single transaction and does not silently turn a restore failure into success.

Use only disposable databases for local recovery tests. Roles, grants, other PostgreSQL majors, and application migrations are outside the current recovery contract. Never edit a deployed migration as part of backup or restore work.

## Development Kubernetes commands

Kubernetes commands require an explicit context and a namespace ending in `-development`. They validate local inputs before optional server-side checks or apply, retain digest-pinned workload expectations, and offer status/rollback.

Dry-run and apply receive the same validated bytes on stdin, not a reread file. Deployments must disable host networking/PID/IPC, privileged/root execution, and privilege escalation; drop all capabilities (only `NET_BIND_SERVICE` may be added) and select RuntimeDefault/Localhost seccomp. A namespace suffix is only an input convention, not proof of cluster identity. Operators must independently verify the context/cluster, restrict RBAC, and enforce the appropriate Pod Security Admission policy; local validation is not an admission controller.

The commands are implemented, but broad cluster acceptance and Production use are not claimed. Do not point test fixtures at a real cluster. GitOps reconciliation remains the responsibility of the selected GitOps controller.
