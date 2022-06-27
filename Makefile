# These variables get inserted into ./build/commit.go
BUILD_TIME=$(shell date)
GIT_REVISION=$(shell git rev-parse --short HEAD)
GIT_DIRTY=$(shell git diff-index --quiet HEAD -- || echo "✗-")

ldflags= -X github.com/skynetlabs/abuse-scanner/build.GitRevision=${GIT_DIRTY}${GIT_REVISION} \
-X "github.com/skynetlabs/abuse-scanner/build.BuildTime=${BUILD_TIME}"

# all will build and install release binaries
all: release

deps:
	go mod download
	go mod tidy

# count says how many times to run the tests.
count = 1
# pkgs changes which packages the makefile calls operate on
pkgs = ./ ./accounts ./database ./email ./test

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
	golangci-lint run -c .golangci.yml
	go mod tidy
	analyze -lockcheck -- $(pkgs)


# Define docker container name our test MongoDB instance.
MONGO_TEST_CONTAINER_NAME=blocker-mongo-test-db

# start-mongo starts a local mongoDB container with no persistence.
# We first prepare for the start of the container by making sure the test
# keyfile has the right permissions, then we clear any potential leftover
# containers with the same name. After we start the container we initialise a
# single node replica set. All the output is discarded because it's noisy and
# if it causes a failure we'll immediately know where it is even without it.
start-mongo:
	./test/setup.sh $(MONGO_TEST_CONTAINER_NAME)

stop-mongo:
	-docker stop $(MONGO_TEST_CONTAINER_NAME)
	
# release builds and installs release binaries.
release:
	go install -tags='netgo' -ldflags='-s -w $(ldflags)' $(release-pkgs)

test:
	go test -short -tags='debug testing netgo' -timeout=5s $(pkgs) -run=. -count=$(count)

# test-long runs test with a mongo container
test-long: lint start-mongo test-long-ci stop-mongo

# test-long-ci is for running tests on the CI where the mongo container needs to
# be initailized separately
test-long-ci:
	@mkdir -p cover
	GORACE='$(racevars)' go test -race --coverprofile='./cover/cover.out' -v -failfast -tags='testing debug netgo' -timeout=60s $(pkgs) -run=$(run) -count=$(count)

.PHONY: all deps fmt vet lint release start-mongo stop-mongo markdown-spellcheck test test-long test-long-ci
