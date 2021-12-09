# These variables get inserted into ./build/commit.go
BUILD_TIME=$(shell date)
GIT_REVISION=$(shell git rev-parse --short HEAD)
GIT_DIRTY=$(shell git diff-index --quiet HEAD -- || echo "✗-")

ldflags= -X github.com/skynetlabs/abuse-scanner/build.GitRevision=${GIT_DIRTY}${GIT_REVISION} \
-X "github.com/skynetlabs/abuse-scanner/build.BuildTime=${BUILD_TIME}"

# all will build and install release binaries
all: release

# pkgs changes which packages the makefile calls operate on
pkgs = ./ ./database ./email

# fmt calls go fmt on all packages.
fmt:
	gofmt -s -l -w $(pkgs)

# vet calls go vet on all packages.
# We don't check composite literals because we need to use unkeyed fields for
# MongoDB's BSONs and that sets vet off.
# NOTE: go vet requires packages to be built in order to obtain type info.
vet:
	go vet -composites=false $(pkgs)

# markdown-spellcheck runs codespell on all markdown files that are not
# vendored.
markdown-spellcheck:
	pip install codespell 1>/dev/null 2>&1
	git ls-files "*.md" :\!:"vendor/**" | xargs codespell --check-filenames

# lint runs golangci-lint (which includes golint, a spellcheck of the codebase,
# and other linters), the custom analyzers, and also a markdown spellchecker.
lint: fmt markdown-spellcheck vet
	golint ./...
	golangci-lint run -c .golangci.yml
	go mod tidy
	analyze -lockcheck -- $(pkgs)

# lint-ci runs golint.
lint-ci:

# golint is skipped on Windows.
ifneq ("$(OS)","Windows_NT")
# Linux
	go get -d golang.org/x/lint/golint
	golint -min_confidence=1.0 -set_exit_status $(pkgs)
	go mod tidy
endif

# release builds and installs release binaries.
release:
	go install -tags='netgo' -ldflags='-s -w $(ldflags)' $(release-pkgs)

.PHONY: all
