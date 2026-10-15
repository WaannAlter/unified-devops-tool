# Unified DevOps Tool — Public Edition

`devops-tool` is a modified public edition of a private DevOps toolkit built by Shafwan Taqiyuddin Abror. It retains the reusable CLI and its safety checks. Private credentials, application profiles, host configuration, and deployment history are excluded.

The tool coordinates Docker/Podman, Git, Trivy, PostgreSQL clients, Compose, Kubernetes, and Veriv. Those tools do the underlying work; this CLI adds consistent inputs, previews, source and image checks, and guarded recovery.

## Build locally

Rust 1.98.0 is pinned in `rust-toolchain.toml`. Keep [the public Veriv project](https://github.com/WaannAlter/veriv-toolkit) beside this project; Cargo uses that local library instead of the private Git dependency:

```text
private project/
  unified-devops-tool/
  veriv-toolkit/
```

```sh
git clone https://github.com/WaannAlter/veriv-toolkit.git
git clone https://github.com/WaannAlter/unified-devops-tool.git
cd unified-devops-tool
cargo build --locked
cargo run --locked -- --help
cargo install --locked --path .
```

Install the external tools needed for the commands you use. Local builds need Docker Buildx or Podman; publication needs Git, Docker Buildx and Trivy; database recovery needs PostgreSQL 17 clients. The CLI does not provision hosts or configure registry credentials. No paid service or GitHub Actions run is required.

## Start with an existing project

From a Git project containing a Dockerfile:

```sh
devops-tool doctor
devops-tool validate
devops-tool check --target test
devops-tool check --target test --execute
devops-tool build
devops-tool build --execute
devops-tool verify
devops-tool scan
```

Mutating operations preview their plan until `--execute` is supplied. `check` requires a real Dockerfile test stage. `doctor` checks tool availability; it does not certify engine connectivity or application health. `verify` compares local OCI revision/component labels, not cryptographic provenance. `scan --execute` requires Trivy and gates HIGH/CRITICAL findings.

The onboarding layer works without TOML. Flags override configuration, then defaults. Select paths with `--context` and `--dockerfile`, and use `--project-name`, `--kind`, `--engine`, `--platform`, or `--registry` when needed. Multiple configured workloads require `--workload`; bare `validate` checks all of them. An explicit missing or invalid `--config` fails rather than silently falling back.

Local `build` uses the working tree and tags with Git HEAD, or a supplied `--commit` (required when no Git HEAD is available). That label does not prove the context matches the commit. Use `publish` when committed-source evidence is required.

## Generate Dockerfile and Compose starters

In an existing application directory:

```sh
devops-tool scaffold --template rust --context api
devops-tool scaffold --template rust --context api --health-path /healthz --execute
devops-tool scaffold --template npm-static --context web --execute
devops-tool scaffold --template bun-static --context web --execute
```

The generator creates `Dockerfile`, `.dockerignore`, `compose.yaml`, and a static-server config where needed. Preview writes nothing; execution refuses to replace existing files or symlinks. Templates use pinned base images, non-root runtime users, test stages, and constrained Compose settings.

Rust requires a locked single-package project and an identifiable binary. Static frontend templates require the matching npm/Bun lockfile and a build script producing `dist/`; an application-owned test script must exist. Templates do not invent business tests. Workspaces, SSR, glibc dependencies, and extra native libraries need application-specific Dockerfile changes.

## Configuration and examples

`examples/hello` is a runnable synthetic health service. `examples/demo/devops.toml` demonstrates backend/frontend selection, optional Veriv checks, and database settings with a named password environment variable.

```sh
devops-tool --config examples/demo/devops.toml list
devops-tool --config examples/demo/devops.toml validate
devops-tool --config examples/demo/devops.toml build --workload api --commit 0123456789abcdef0123456789abcdef01234567
devops-tool --config examples/demo/devops.toml quality --group demo --execute
```

Paths resolve relative to the configured project root and must remain inside it. Unknown keys fail validation. Local builds support a single selected platform. See the example file for the full schema.

Build arguments are for public build settings. Their values are hidden in plan output but may be exposed by Docker metadata, history, logs, or process inspection. Secret-like names are rejected; never put credentials in build arguments or committed files.

## Commands retained in this edition

| Command | Purpose |
| --- | --- |
| `scaffold` | Generate Rust, npm-static, or Bun-static Dockerfile/Compose starters. |
| `validate`, `doctor`, `list` | Validate inputs, inspect tool availability, and select workloads. |
| `build`, `check` | Build a local image or run an application-owned Dockerfile test stage. |
| `verify`, `scan` | Compare local labels and run Trivy gates. |
| `publish` | Build committed source, scan the candidate digest, and seal publication evidence. |
| `quality` | Run a project-owned profile through the public Veriv runner. |
| `deploy`, `rollback` | Deliver one Compose service by digest and recover a previous release. |
| `database backup`, `verify-backup`, `restore` | Create checksummed archives and guard PostgreSQL recovery. |
| `kube apply`, `status`, `rollback` | Work with an explicit Development context and namespace. |

Use `devops-tool COMMAND --help` for the full interface. [Operations](docs/OPERATIONS.md) describes publication and recovery requirements. [The roadmap](docs/ROADMAP.md) separates available code, local validation, and remaining work.

## Local tests

```sh
cargo fmt --all --check
cargo test --locked --all-targets
cargo clippy --locked --all-targets -- -D warnings
python tests/scaffold.py PATH_TO_DEVOPS_TOOL
```

The Rust tests cover configuration, onboarding, source boundaries, generators, publication inputs, recovery guards, and CLI behavior. The scaffold harness checks all three generators, preview behavior, and overwrite refusal. Add `--execute` to build and run only its disposable local Docker/Compose fixtures. That can download public images and toolchain dependencies.

Linux has two additional offline harnesses; neither contacts a real registry or application:

```sh
python3 tests/publish.py PATH_TO_LINUX_DEVOPS_TOOL
python3 tests/operations.py PATH_TO_LINUX_DEVOPS_TOOL
```

Each harness has a distinct purpose. Organization-specific migration rehearsals, duplicated host adapters, release diaries, and runner installers are excluded.

## Optional local toolbox image

The generic toolbox recipe is retained, including pinned tool sources and upstream license copies:

```sh
docker build --build-context veriv=../veriv-toolkit -t devops-tool:local .
```

This named context supplies only the public Veriv source; no private Git token or SSH agent is used. The image bundles the CLI and its external tools. The sanitized recipe still needs a full local rebuild and image scan before distribution; native CLI tests do not establish image acceptance.

## Limits

Guarded publication is Docker/Linux amd64 only. Podman and additional architectures have code paths or configurable inputs but are not accepted as equivalent publication targets. PostgreSQL recovery currently supports major 17 only. Kubernetes commands retain their Development-only guard and have not been accepted for general public cluster use.

The whole-operation deadline uses GNU `timeout` on Linux, including child processes. Native Windows execution does not provide that supervisor. A cancelled engine client does not prove daemon-side work stopped. Use the documented supported path and inspect retained state before retrying a failed operational command.

Profiles, Dockerfiles, and manifests are trusted execution inputs. Image scans and passing checks do not prove an application has no vulnerabilities. Keep registry authentication in the engine's credential configuration and database passwords in local environment variables.

Licensed under [MIT](LICENSE). Copyright (c) 2026 Shafwan Taqiyuddin Abror.
