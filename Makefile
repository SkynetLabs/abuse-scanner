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
	golangci-lint run -c .golangci.yml
	go mod tidy
	analyze -lockcheck -- $(pkgs)


# Credentials and port we are going to use for our test MongoDB instance.
MONGO_USER=admin
MONGO_PASSWORD=aO4tV5tC1oU3oQ7u
MONGO_PORT=37017

# call_mongo is a helper function that executes a query in an `eval` call to the
# test mongo instance.
define call_mongo
    docker exec blocker-mongo-test-db mongo -u $(MONGO_USER) -p $(MONGO_PASSWORD) --port $(MONGO_PORT) --eval $(1)
endef

# start-mongo starts a local mongoDB container with no persistence.
# We first prepare for the start of the container by making sure the test
# keyfile has the right permissions, then we clear any potential leftover
# containers with the same name. After we start the container we initialise a
# single node replica set. All the output is discarded because it's noisy and
# if it causes a failure we'll immediately know where it is even without it.
start-mongo:
	-docker stop blocker-mongo-test-db 1>/dev/null 2>&1
	-docker rm blocker-mongo-test-db 1>/dev/null 2>&1
	docker run \
     --rm \
     --detach \
     --name blocker-mongo-test-db \
     -p $(MONGO_PORT):$(MONGO_PORT) \
     -e MONGO_INITDB_ROOT_USERNAME=$(MONGO_USER) \
     -e MONGO_INITDB_ROOT_PASSWORD=$(MONGO_PASSWORD) \
	mongo:4.4.1 mongod --port=$(MONGO_PORT) --replSet=skynet 1>/dev/null 2>&1
	# wait for mongo to start before we try to configure it
	status=1 ; while [[ $$status -gt 0 ]]; do \
		sleep 1 ; \
		$(call call_mongo,"") 1>/dev/null 2>&1 ; \
		status=$$? ; \
	done
	# Initialise a single node replica set.
	$(call call_mongo,"rs.initiate({_id: \"skynet\", members: [{ _id: 0, host: \"localhost:$(MONGO_PORT)\" }]})") 1>/dev/null 2>&1

stop-mongo:
	-docker stop blocker-mongo-test-db
	
# release builds and installs release binaries.
release:
	go install -tags='netgo' -ldflags='-s -w $(ldflags)' $(release-pkgs)

.PHONY: all
