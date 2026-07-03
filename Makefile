# Godzilla build/test targets.
#
# The default targets are pure Go (no cgo): they cover the Go, Python, JavaScript,
# and Java frontends. The `*-llvm` targets additionally build the C/C++/Rust
# frontends, which bind libLLVM via cgo (tinygo.org/x/go-llvm) under the `llvm`
# build tag. They need an LLVM install; point LLVM_CONFIG at its llvm-config
# (Homebrew keeps it keg-only, e.g. /opt/homebrew/opt/llvm/bin/llvm-config), plus
# clang/rustc on PATH to produce IR at scan time.

LLVM_CONFIG ?= llvm-config
LLVM_LIBDIR := $(shell $(LLVM_CONFIG) --libdir 2>/dev/null)
LLVM_ENV = CGO_ENABLED=1 \
	CGO_CPPFLAGS="$(shell $(LLVM_CONFIG) --cppflags 2>/dev/null)" \
	CGO_CXXFLAGS="-std=c++17" \
	CGO_LDFLAGS="$(shell $(LLVM_CONFIG) --ldflags --libs --system-libs all 2>/dev/null)" \
	DYLD_LIBRARY_PATH="$(LLVM_LIBDIR)" LD_LIBRARY_PATH="$(LLVM_LIBDIR)"
LLVM_TAGS = -tags "llvm byollvm"

.PHONY: build test fmt vet gate build-llvm test-llvm gate-llvm

# --- default (pure Go: Go/Python/JS/Java) ---
build:
	go build ./...
test:
	go test ./...
fmt:
	gofmt -l cmd converters internal test/corpus
vet:
	go vet ./...
gate: fmt vet build test

# --- with the C/C++/Rust LLVM frontends (cgo + libLLVM) ---
build-llvm:
	$(LLVM_ENV) go build $(LLVM_TAGS) ./...
test-llvm:
	$(LLVM_ENV) go test $(LLVM_TAGS) ./...
# build-llvm compiles every package under the tag (a full compile check); vet
# runs over everything. The `llvm` tag only affects the C/C++ frontend, though —
# Go/Python/JS/Java/Rust are tag-agnostic and covered by the default `test`
# target — so gate only the C/C++ corpus here. This keeps the cgo job from
# needing the Java/Rust toolchains (a bare `go test ./...` would run the Java
# samples against whatever old JDK is on PATH and fail).
gate-llvm: build-llvm
	$(LLVM_ENV) go vet $(LLVM_TAGS) ./...
	$(LLVM_ENV) go test $(LLVM_TAGS) ./test/corpus/ -run 'TestCorpus/(c|cpp)/'
