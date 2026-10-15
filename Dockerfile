# syntax=docker/dockerfile:1.7

ARG RUST_IMAGE=docker.io/library/rust:1.98.0-alpine3.24@sha256:a10e64dd139b7387337c7fbe8aca31b959b57b2fd4c8ae20a02cf1d6ea424dce
ARG GO_IMAGE=docker.io/library/golang:1.26.9-alpine3.24@sha256:3082400e369fa24d5fc60bca20edab3f6d604e0c5a690ec66b295eff4dd87ade
ARG RUNTIME_IMAGE=docker.io/library/docker:29.9.0-cli-alpine3.24@sha256:1a4c7cb63513f349bdad01fcc6e0f3f2f67d37b9da86f14dc0d4a0942eecda00

# Supply the public sibling as a named build context: --build-context veriv=../veriv-toolkit
FROM ${RUST_IMAGE} AS source
WORKDIR /src/public-devops-tool
ENV CARGO_BUILD_JOBS=2
RUN rustup component add rustfmt clippy \
    && apk add --no-cache ca-certificates coreutils=9.11-r0 git musl-dev python3
COPY --from=veriv Cargo.toml Cargo.lock /src/veriv-toolkit/
COPY --from=veriv src /src/veriv-toolkit/src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY examples ./examples
COPY tests ./tests

FROM source AS quality
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/src/public-devops-tool/target,sharing=locked \
    cargo fmt --all --check \
    && cargo test --locked --all-targets \
    && cargo clippy --locked --all-targets -- -D warnings

FROM quality AS builder
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/src/public-devops-tool/target,sharing=locked \
    cargo build --locked --release \
    && mkdir /out && cp target/release/devops-tool /out/devops-tool
RUN python3 tests/publish.py /out/devops-tool \
    && python3 tests/operations.py /out/devops-tool \
    && python3 tests/scaffold.py /out/devops-tool

# Pinned upstream rebuilds remove known vulnerable modules, not scanner findings.
# Go is build-only; devops-tool itself remains Rust and the runtime has no SDKs.
# Trivy 0.74 uses the Go 1.26 JSON experiment API; Go 1.27 removed SkipFunc.
FROM ${GO_IMAGE} AS security-tools
ENV CGO_ENABLED=0 GOTOOLCHAIN=local GOFLAGS=-mod=readonly GOMAXPROCS=2
RUN apk add --no-cache patch
ADD --checksum=sha256:6cde1a7bb6368114b5319f0aa2f29c821c85a107cbf4f252646ba0e1c105840b https://codeload.github.com/docker/buildx/tar.gz/0b265a9f62db554fa9aba6dd19e1bd5704bc7d8a /tmp/buildx.tar.gz
ADD --checksum=sha256:285594b257470eb444fd2836be95a835565ee600382320c977b3993d8efbb767 https://codeload.github.com/aquasecurity/trivy/tar.gz/e1fd17a0ea4a8cf24bc4b4dd7e2cfbf4bb31b994 /tmp/trivy.tar.gz
COPY packaging/patches/buildx-security.patch packaging/patches/trivy-security.patch /tmp/
RUN mkdir -p /src/buildx /src/trivy /out \
    && tar -xzf /tmp/buildx.tar.gz -C /src/buildx --strip-components=1 \
    && tar -xzf /tmp/trivy.tar.gz -C /src/trivy --strip-components=1 \
    && cd /src/buildx && patch -p1 --fuzz=0 < /tmp/buildx-security.patch \
    && cd /src/trivy && patch -p1 --fuzz=0 < /tmp/trivy-security.patch
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    cd /src/buildx \
    && GOFLAGS=-mod=mod go get golang.org/x/net@v0.60.0 \
    && go mod verify \
    && go test -p 2 ./store \
    && go build -p 2 -trimpath -ldflags='-s -w -X github.com/docker/buildx/version.Version=v0.37.1-public.1 -X github.com/docker/buildx/version.Revision=0b265a9f62db554fa9aba6dd19e1bd5704bc7d8a-public.1' -o /out/docker-buildx ./cmd/buildx
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    cd /src/trivy \
    && GOFLAGS=-mod=mod go get golang.org/x/net@v0.60.0 \
    && go mod verify \
    && GOEXPERIMENT=jsonv2 go test -p 2 ./pkg/x/json \
    && GOEXPERIMENT=jsonv2 go build -p 2 -trimpath -ldflags='-s -w -X github.com/aquasecurity/trivy/pkg/version/app.ver=0.74.0-public.1' -o /out/trivy ./cmd/trivy

# The latest upstream Gitleaks binary was built with vulnerable Go modules.
# Retain its exact source/rules and rebuild with the same pinned toolchain.
FROM security-tools AS gitleaks
ADD --checksum=sha256:6b2638a733b85619dc80bdf28e84e4fed7e526a761ab5c148fbf67695aea2115 https://codeload.github.com/gitleaks/gitleaks/tar.gz/83d9cd684c87d95d656c1458ef04895a7f1cbd8e /tmp/gitleaks.tar.gz
COPY packaging/patches/gitleaks-security.patch /tmp/
# Git fixture directory renames must stay in one layer (OverlayFS lowerdir
# renames otherwise fail with EXDEV). Do not skip the upstream detection tests.
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    apk add --no-cache bash git \
    && mkdir -p /src/gitleaks \
    && tar -xzf /tmp/gitleaks.tar.gz -C /src/gitleaks --strip-components=1 \
    && cd /src/gitleaks && patch -p1 --fuzz=0 < /tmp/gitleaks-security.patch \
    && go mod verify \
    && go test -p 2 ./config ./detect ./report ./sources \
    && go build -p 2 -trimpath -ldflags='-s -w -X github.com/zricethezav/gitleaks/v8/version.Version=8.30.1-public.1' -o /out/gitleaks .

# Preserve the Kubernetes client minor, rebuilding its unpatched upstream binary.
FROM ${GO_IMAGE} AS kubectl
ENV CGO_ENABLED=0 GOTOOLCHAIN=local GOFLAGS=-mod=readonly GOWORK=off GOMAXPROCS=2
ADD --checksum=sha256:b390f0c5446a9414e8f0a7019ca54f858251187d193217a8051687bf7a960d01 https://codeload.github.com/kubernetes/kubernetes/tar.gz/refs/tags/v1.35.9 /tmp/kubernetes.tar.gz
RUN mkdir -p /src/kubernetes /out \
    && tar -xzf /tmp/kubernetes.tar.gz -C /src/kubernetes --strip-components=1 --exclude='*/vendor'
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    cd /src/kubernetes \
    && GOFLAGS=-mod=mod go get golang.org/x/net@v0.60.0 \
    && go mod verify \
    && go test -p 2 ./cmd/kubectl \
    && go build -p 2 -trimpath -ldflags='-s -w -X k8s.io/component-base/version.gitVersion=v1.35.9-public.1 -X k8s.io/component-base/version.gitMajor=1 -X k8s.io/component-base/version.gitMinor=35 -X k8s.io/client-go/pkg/version.gitVersion=v1.35.9-public.1 -X k8s.io/client-go/pkg/version.gitMajor=1 -X k8s.io/client-go/pkg/version.gitMinor=35' -o /out/kubectl ./cmd/kubectl

FROM ${GO_IMAGE} AS compose
ENV CGO_ENABLED=0 GOTOOLCHAIN=local GOFLAGS=-mod=readonly GOMAXPROCS=2
ADD --checksum=sha256:51ad60cc28d38a0850678053f0a259dfee931d150dd1d50ee9e6d758125b1d47 https://codeload.github.com/docker/compose/tar.gz/refs/tags/v5.6.0 /tmp/compose.tar.gz
RUN mkdir -p /src/compose /out \
    && tar -xzf /tmp/compose.tar.gz -C /src/compose --strip-components=1
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    cd /src/compose \
    && GOFLAGS=-mod=mod go get golang.org/x/net@v0.60.0 \
    && go mod verify \
    && go test -p 2 ./internal/sync \
    && go build -p 2 -trimpath -ldflags='-s -w -X github.com/docker/compose/v5/internal.Version=v5.6.0-public.1' -o /out/docker-compose ./cmd

FROM ${RUNTIME_IMAGE} AS runtime
ARG TOOL_VERSION=0.1.0
ARG SOURCE_REVISION=unknown
ARG SOURCE_URL=https://github.com/WaannAlter/unified-devops-tool

LABEL org.opencontainers.image.title="devops-tool" \
      org.opencontainers.image.description="Unified self-hosted FE and BE delivery toolkit" \
      org.opencontainers.image.source="${SOURCE_URL}" \
      org.opencontainers.image.revision="${SOURCE_REVISION}" \
      org.opencontainers.image.version="${TOOL_VERSION}" \
      org.opencontainers.image.licenses="MIT"

RUN apk add --no-cache \
      bash=5.3.9-r1 \
      ca-certificates=20260909-r0 \
      coreutils=9.11-r0 \
      git=2.54.0-r0 \
      jq=1.8.2-r0 \
      libexpat=2.8.5-r0 \
      pcre2=10.49-r0 \
      postgresql17-client=17.11-r0 \
      python3=3.14.8-r0 \
    && addgroup -S -g 10001 devops \
    && adduser -S -D -H -u 10001 -G devops devops \
    && install -d -o devops -g devops /home/devops/.cache/trivy /home/devops/.docker /workspace \
    && rm -rf /var/cache/apk/*

COPY --from=builder --chown=devops:devops /out/devops-tool /usr/local/bin/devops-tool
COPY --from=security-tools /out/trivy /usr/local/bin/trivy
COPY --from=gitleaks /out/gitleaks /usr/local/bin/gitleaks
COPY --from=gitleaks /src/gitleaks/LICENSE /usr/share/licenses/devops-tool/gitleaks-LICENSE
COPY --from=security-tools /out/docker-buildx /usr/local/libexec/docker/cli-plugins/docker-buildx
COPY --from=security-tools /src/buildx/LICENSE /usr/share/licenses/devops-tool/buildx-LICENSE
COPY --from=security-tools /src/trivy/LICENSE /usr/share/licenses/devops-tool/trivy-LICENSE
COPY --from=compose /out/docker-compose /usr/local/libexec/docker/cli-plugins/docker-compose
COPY --from=compose /src/compose/LICENSE /usr/share/licenses/devops-tool/compose-LICENSE
COPY --from=kubectl /out/kubectl /usr/local/bin/kubectl
COPY --from=kubectl /src/kubernetes/LICENSE /usr/share/licenses/devops-tool/kubectl-LICENSE

# Direct job containers retain the existing source-secret and Bash contract gates.
RUN bash --version >/dev/null && gitleaks version

ENV HOME=/home/devops \
    TRIVY_CACHE_DIR=/home/devops/.cache/trivy

USER devops
WORKDIR /workspace
ENTRYPOINT ["devops-tool"]
CMD ["--help"]
