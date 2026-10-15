# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e
FROM rust:1.98.0-alpine3.24@sha256:a10e64dd139b7387337c7fbe8aca31b959b57b2fd4c8ae20a02cf1d6ea424dce AS source
WORKDIR /app
ENV CARGO_BUILD_JOBS=2
RUN apk add --no-cache musl-dev
COPY Cargo.toml Cargo.lock ./
COPY . .
FROM source AS test
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/app/target,sharing=locked \
    cargo test --locked

FROM test AS build
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/app/target,sharing=locked \
    cargo build --locked --release --bin @BINARY@ && \
    mkdir -p /out && cp target/release/@BINARY@ /out/app

FROM alpine:3.24.2@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6
RUN apk add --no-cache ca-certificates@EXTRA_PACKAGES@
COPY --from=build /out/app /app
USER 65532:65532
ENV PORT=@PORT@
EXPOSE @PORT@
@HEALTHCHECK@
ENTRYPOINT ["/app"]
