# Godzilla build/test targets.
#
# The default targets are pure Go (no cgo): they cover the Go, Python, JavaScript,
# Java and Rust frontends. The `*-llvm` targets additionally build the C/C++
# frontend, which binds libLLVM via cgo (tinygo.org/x/go-llvm) under the `llvm`
# build tag. That needs an LLVM install, plus clang on PATH to produce IR at scan
# time. Without it a scan still runs and reports `cpp=FAILED` in its coverage.
#
#   make            → binaries in bin/ (no C/C++)
#   make build-llvm → binaries in bin/ WITH the C/C++ frontend
#   make gate       → what CI blocks on
#
# `build` writes binaries; `check` is the compile sweep over every package. They
# are separate because `go build ./...` over a package PATTERN compiles and then
# discards the results — it never writes an executable, which is what made the
# old `build` target produce nothing.

.DEFAULT_GOAL := build

# Tool version stamped into the binary (and SARIF/JSON reports). Defaults to the
# current git description; override with `make build VERSION=v1.2.3`.
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
VERSION_LDFLAGS = -ldflags "-X main.version=$(VERSION)"

# Binaries land in bin/, which .gitignore already covers — one rule for both
# commands, and the repo root stays clean.
BINDIR = bin

# llvm-config is keg-only under Homebrew, so it is usually NOT on PATH. Look it
# up rather than making every caller pass LLVM_CONFIG= by hand. Recursive (`=`,
# via `?=`) so nothing shells out on a default-target build.
LLVM_CONFIG ?= $(shell command -v llvm-config 2>/dev/null || echo "$$(brew --prefix llvm 2>/dev/null)/bin/llvm-config")
LLVM_LIBDIR = $(shell $(LLVM_CONFIG) --libdir 2>/dev/null)
LLVM_ENV = CGO_ENABLED=1 \
	CGO_CPPFLAGS="$(shell $(LLVM_CONFIG) --cppflags 2>/dev/null)" \
	CGO_CXXFLAGS="-std=c++17" \
	CGO_LDFLAGS="$(shell $(LLVM_CONFIG) --ldflags --libs --system-libs all 2>/dev/null)" \
	DYLD_LIBRARY_PATH="$(LLVM_LIBDIR)" LD_LIBRARY_PATH="$(LLVM_LIBDIR)"
LLVM_TAGS = -tags "llvm byollvm"

.PHONY: build check test fmt vet lint gate \
	build-llvm check-llvm test-llvm gate-llvm require-llvm \
	clean help

# --- default (pure Go: Go/Python/JS/Java/Rust) ---
build:
	@mkdir -p $(BINDIR)
	go build $(VERSION_LDFLAGS) -o $(BINDIR)/ ./cmd/...
	@echo "built: $$(ls $(BINDIR) | tr '\n' ' ')"
check:
	go build $(VERSION_LDFLAGS) ./...
test:
	go test ./...
fmt:
	gofmt -l cmd converters internal test/corpus
vet:
	go vet ./...
# CI's blocking check, and a strict superset of `go vet`. golangci-lint refuses to
# run when it was built with an older Go than this module targets, so an outdated
# binary fails closed with a config-load error rather than a clean report:
#   GOTOOLCHAIN=go1.26.5 go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.12.2
#
# `go install` puts it in GOPATH/bin, which is frequently not on PATH — so look
# there too rather than failing with a bare "No such file or directory".
GOBIN ?= $(shell go env GOPATH)/bin
GOLANGCI ?= $(shell command -v golangci-lint 2>/dev/null || echo $(GOBIN)/golangci-lint)
lint:
	@test -x "$(GOLANGCI)" || { \
		echo "golangci-lint not found at: $(GOLANGCI)"; \
		echo "install it with: GOTOOLCHAIN=go1.26.5 go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.12.2"; \
		exit 1; }
	$(GOLANGCI) run
gate: fmt vet lint check test

# --- with the C/C++ LLVM frontend (cgo + libLLVM) ---
# Fails with an actionable message rather than letting cgo report a missing
# header a hundred lines later.
require-llvm:
	@command -v $(LLVM_CONFIG) >/dev/null 2>&1 || test -x "$(LLVM_CONFIG)" || { \
		echo "llvm-config not found at: $(LLVM_CONFIG)"; \
		echo "install LLVM (macOS: brew install llvm) or set LLVM_CONFIG=/path/to/llvm-config"; \
		exit 1; }

build-llvm: require-llvm
	@mkdir -p $(BINDIR)
	$(LLVM_ENV) go build $(LLVM_TAGS) $(VERSION_LDFLAGS) -o $(BINDIR)/ ./cmd/...
	@echo "built with C/C++: $$(ls $(BINDIR) | tr '\n' ' ')"
check-llvm: require-llvm
	$(LLVM_ENV) go build $(LLVM_TAGS) ./...
test-llvm: require-llvm
	$(LLVM_ENV) go test $(LLVM_TAGS) ./...
# check-llvm compiles every package under the tag; vet runs over everything. The
# `llvm` tag only affects the C/C++ frontend, though — Go/Python/JS/Java/Rust are
# tag-agnostic and covered by the default `test` target — so gate only the C/C++
# corpus here. This keeps the cgo job from needing the Java/Rust toolchains (a
# bare `go test ./...` would run the Java samples against whatever old JDK is on
# PATH and fail).
gate-llvm: check-llvm
	$(LLVM_ENV) go vet $(LLVM_TAGS) ./...
	$(LLVM_ENV) go test $(LLVM_TAGS) ./converters/llvm/ ./converters/cpp/
	$(LLVM_ENV) go test $(LLVM_TAGS) ./test/corpus/ -run 'TestCorpus/(c|cpp)/'

clean:
	rm -rf $(BINDIR)
	rm -f godzilla godzilla.exe godzilla-playground

help:
	@echo "build       binaries into $(BINDIR)/ (default)"
	@echo "build-llvm  same, with the C/C++ frontend (needs libLLVM)"
	@echo "check       compile every package (no output)"
	@echo "test        run the test suite"
	@echo "gate        fmt + vet + lint + check + test — what CI blocks on"
	@echo "gate-llvm   the cgo half of CI"
	@echo "clean       remove built binaries"
