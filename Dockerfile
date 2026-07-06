# syntax=docker/dockerfile:1
#
# Godzilla scan-ready images. Two runtime targets:
#   slim (default / :latest) — Go, JavaScript/TS, Python, Ruby, and secrets.
#   full (:full)             — slim + Java (JDK 25) + Rust.
# C/C++ (the opt-in cgo/libLLVM backend) is deliberately not included; the
# default binary compiles the C/C++ stub, so no cgo is needed here.
#
# The frontends shell out to a language toolchain at scan time, and the scan
# pipeline degrades per-language: an image missing a toolchain simply skips that
# language (with a stderr warning) and still runs every other frontend plus the
# secrets scanner. So slim scans Go/JS/Python/Ruby out of the box; use :full for
# Java/Rust.
#
# Base images are pinned on purpose (see the release workflow's Dependabot config
# for automated bumps): the runtime `go` must track go.mod's `go 1.25.5`, and the
# Java frontend hard-requires a JDK 24+ (Temurin 25).

# ---------------------------------------------------------------------------
# builder — compile the pure-Go binary (CGO disabled: portable, static).
# ---------------------------------------------------------------------------
FROM golang:1.26-bookworm AS builder
WORKDIR /src

# Warm the module cache in its own layer so source-only edits don't re-download.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

# Stamped into `godzilla version` and the SARIF/JSON report metadata, matching
# the Makefile's -ldflags contract (main.version). Overridden by the release
# workflow with the tag/edge version.
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath \
      -ldflags "-s -w -X main.version=${VERSION}" \
      -o /out/godzilla ./cmd/godzilla

# ---------------------------------------------------------------------------
# slim — Go + JavaScript/TS + Python + Ruby (+ secrets). ~600-700 MB.
# ---------------------------------------------------------------------------
FROM debian:bookworm-slim AS slim

# The Go frontend loads packages via `go list` (golang.org/x/tools), so the Go
# toolchain must be present at scan time — copy the exact version used to build.
COPY --from=golang:1.25-bookworm /usr/local/go /usr/local/go
ENV PATH="/usr/local/go/bin:${PATH}"

# python3 (stdlib ast) and ruby (stdlib Ripper) are the Python/Ruby frontends'
# interpreters; ca-certificates + git support `go list` module resolution.
RUN apt-get update \
    && apt-get install -y --no-install-recommends python3 ruby ca-certificates git \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /out/godzilla /usr/local/bin/godzilla

# Run as a non-root user; give `go` writable cache dirs under /tmp. GOTOOLCHAIN
# is pinned local so scanning never triggers a surprise toolchain download
# (override with -e GOTOOLCHAIN=auto to scan a project that needs newer Go).
RUN useradd --create-home --uid 1000 --shell /usr/sbin/nologin godzilla
ENV HOME=/home/godzilla \
    GOCACHE=/tmp/gocache \
    GOMODCACHE=/tmp/gomodcache \
    GOTOOLCHAIN=local
USER godzilla
WORKDIR /src

# `docker run -v "$PWD:/src" ghcr.io/bytevet/godzilla` scans the mounted repo;
# any argument (version, scan --sarif …) overrides the default CMD.
ENTRYPOINT ["godzilla"]
CMD ["scan", "."]

# ---------------------------------------------------------------------------
# full — slim + Java (JDK 25) + Rust. ~1.5-2 GB.
# ---------------------------------------------------------------------------
FROM slim AS full
USER root

# Java frontend: a full JDK 24+ (java.lang.classfile + in-process javac). Pinned
# Temurin 25, copied from the official multi-arch image.
COPY --from=eclipse-temurin:25-jdk /opt/java/openjdk /opt/java/openjdk
ENV JAVA_HOME=/opt/java/openjdk
ENV PATH="${JAVA_HOME}/bin:${PATH}"

# Rust frontend: a stable rustc (the frontend sets RUSTC_BOOTSTRAP=1 to unlock
# the -Zmir-include-spans flag on stable). Installed system-wide via rustup;
# gcc is the linker used only by opt-in `cargo` dependency builds.
ENV RUSTUP_HOME=/opt/rustup \
    CARGO_HOME=/opt/cargo \
    PATH="/opt/cargo/bin:${PATH}"
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl gcc \
    && curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
       | sh -s -- -y --no-modify-path --profile minimal --default-toolchain stable \
    && chmod -R a+rX "$RUSTUP_HOME" "$CARGO_HOME" \
    && apt-get purge -y curl && apt-get autoremove -y \
    && rm -rf /var/lib/apt/lists/*

USER godzilla
# ENTRYPOINT, CMD, WORKDIR inherited from slim.
