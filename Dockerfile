# syntax=docker/dockerfile:1
#
# Godzilla scan-ready images. Two runtime targets:
#   slim (default / :latest) — Go, JavaScript/TS, Python, Ruby, and secrets.
#   full (:full)             — slim + Java (JDK 25) + Rust + C/C++.
# Both carry the `godzilla` scanner and the `godzilla-playground` gIR/rule
# explorer; see the ENTRYPOINT note at the end of the slim stage for running it.
#
# C/C++ is the one frontend that is not merely a toolchain away: it binds libLLVM
# through cgo under the `llvm` build tag, so it needs a DIFFERENT binary, not
# just another package. full therefore replaces slim's static binaries with cgo
# ones from builder-llvm. That is why full is a superset in languages but not in
# linkage.
#
# The frontends shell out to a language toolchain at scan time, and the scan
# pipeline degrades per-language: an image missing a toolchain simply skips that
# language (with a stderr warning) and still runs every other frontend plus the
# secrets scanner. So slim scans Go/JS/Python/Ruby out of the box; use :full for
# Java, Rust and C/C++. scripts/smoke-image.sh holds that list and asserts it.
#
# Base images are pinned on purpose (see the release workflow's Dependabot config
# for automated bumps): the runtime `go` must track go.mod's `go 1.26.5`, and the
# Java frontend hard-requires a JDK 24+ (Temurin 25).

# The LLVM major the C/C++ frontend binds. Declared once, before the first FROM,
# so the builder's libLLVM and the runtime's clang cannot drift apart; each stage
# opts in with a bare `ARG LLVM_MAJOR`. It must match the major that
# tinygo.org/x/go-llvm targets (go.mod) and the pin in ci.yml's test-llvm job.
ARG LLVM_MAJOR=22

# ---------------------------------------------------------------------------
# builder — compile the pure-Go binaries (CGO disabled: portable, static).
# ---------------------------------------------------------------------------
FROM golang:1.27-bookworm AS builder
WORKDIR /src

# Warm the module cache in its own layer so source-only edits don't re-download.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

# Stamped into `godzilla version` and the SARIF/JSON report metadata, matching
# the Makefile's -ldflags contract (main.version). Overridden by the release
# workflow with the tag/edge version.
# ./cmd/... rather than a named package: every command is built and stamped, so
# adding one does not need a matching edit here. Both declare main.version.
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath \
      -ldflags "-s -w -X main.version=${VERSION}" \
      -o /out/ ./cmd/...

# ---------------------------------------------------------------------------
# builder-llvm — the same commands, built with the C/C++ frontend compiled in.
#
# Only the `full` stage consumes this, and BuildKit skips stages nothing depends
# on, so a `--target slim` build never pays for it.
#
# LLVM_MAJOR must match the major that tinygo.org/x/go-llvm binds (go.mod), and
# the same number is pinned in .github/workflows/ci.yml's test-llvm job. The
# `byollvm` tag means "use the CGO flags I give you" rather than go-llvm's own
# per-version build tags, so llvm-config is the only thing that has to agree.
# ---------------------------------------------------------------------------
FROM golang:1.27-bookworm AS builder-llvm
ARG LLVM_MAJOR
WORKDIR /src

# Installed BEFORE the source copy, and the source is not copied until after: an
# edit to any .go file must not re-run a multi-minute apt install.
COPY scripts/install-llvm.sh /tmp/
RUN /tmp/install-llvm.sh "${LLVM_MAJOR}" "llvm-${LLVM_MAJOR}-dev" && rm /tmp/install-llvm.sh

COPY go.mod go.sum ./
RUN go mod download
COPY . .

ARG VERSION=dev
RUN LC="llvm-config-${LLVM_MAJOR}" \
    && CGO_ENABLED=1 \
       CGO_CPPFLAGS="$($LC --cppflags)" \
       CGO_CXXFLAGS="-std=c++17" \
       CGO_LDFLAGS="$($LC --ldflags --libs --system-libs all)" \
       go build -trimpath -tags "llvm byollvm" \
         -ldflags "-s -w -X main.version=${VERSION}" \
         -o /out/ ./cmd/...

# ---------------------------------------------------------------------------
# slim — Go + JavaScript/TS + Python + Ruby (+ secrets). ~600-700 MB.
# ---------------------------------------------------------------------------
FROM debian:bookworm-slim AS slim

# The Go frontend loads packages via `go list` (golang.org/x/tools), so a Go
# toolchain must be present at SCAN time. Taken from the builder rather than
# pinned again: a second `golang:` reference is a second thing for Dependabot to
# bump, and the two had already drifted (builder 1.27, runtime 1.26) under a
# comment claiming they matched. GOTOOLCHAIN=local below makes this the only
# toolchain a scan can use, so newer is strictly safer.
COPY --from=builder /usr/local/go /usr/local/go
ENV PATH="/usr/local/go/bin:${PATH}"

# python3 (stdlib ast) and ruby (stdlib Ripper) are the Python/Ruby frontends'
# interpreters; ca-certificates + git support `go list` module resolution.
RUN apt-get update \
    && apt-get install -y --no-install-recommends python3 ruby ca-certificates git \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /out/ /usr/local/bin/

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
#
# The playground is the other binary, reached by overriding the entrypoint. It
# must be told to bind 0.0.0.0 — its 127.0.0.1 default is the CONTAINER's
# loopback, which no port publish can reach — and browsed as localhost, since it
# serves only loopback Host headers:
#   docker run --rm -p 7391:7391 -v "$PWD:/src" \
#     --entrypoint godzilla-playground ghcr.io/bytevet/godzilla \
#     -addr 0.0.0.0:7391 -open=false /src
ENTRYPOINT ["godzilla"]
CMD ["scan", "."]

# ---------------------------------------------------------------------------
# full — slim + Java (JDK 25) + Rust + C/C++. ~2-2.5 GB.
# ---------------------------------------------------------------------------
FROM slim AS full
ARG LLVM_MAJOR
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

# C/C++ frontend. Two halves, and both are needed: clang to emit the IR at scan
# time, and libLLVM because these binaries are linked against it — slim's are
# static, these are not.
#
# GODZILLA_CC/CXX pin the versioned drivers. Left to find plain `clang`, the
# frontend would use whatever the base image happens to ship, which may emit a
# bitcode version the linked libLLVM cannot read.
COPY scripts/install-llvm.sh /tmp/
# The purge is here, not in the script: it is right in a layer and wrong on a CI
# runner, where a later step may still want wget. Same RUN, so it still shrinks.
RUN /tmp/install-llvm.sh "${LLVM_MAJOR}" "clang-${LLVM_MAJOR}" "libllvm${LLVM_MAJOR}" \
    && apt-get purge -y wget gnupg && apt-get autoremove -y \
    && rm -rf /var/lib/apt/lists/* /tmp/install-llvm.sh
ENV GODZILLA_CC=clang-${LLVM_MAJOR} \
    GODZILLA_CXX=clang++-${LLVM_MAJOR}

# The cgo binaries REPLACE the static ones copied into slim. Last write wins, so
# this must come after every other stage that puts something in /usr/local/bin.
COPY --from=builder-llvm /out/ /usr/local/bin/

USER godzilla
# ENTRYPOINT, CMD, WORKDIR inherited from slim.
