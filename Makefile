VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
ARCHES  ?= amd64 arm64

# Reproducible build flags (spec A8.4). CGO disabled => statically linked.
# VCS stamping is off and the commit goes in through -X instead, so a build
# from a source tarball or inside Docker (no .git) gives the same bytes.
export CGO_ENABLED := 0
GOBUILD := go build -trimpath -buildvcs=false -ldflags="-s -w -buildid= -X main.version=$(VERSION) -X main.commit=$(COMMIT)"

.PHONY: all agent dist test lint fmt checksums clean

all: agent

## agent: static xnux-agent for every arch in ARCHES -> bin/
agent:
	@for arch in $(ARCHES); do \
	  echo "building bin/xnux-agent-linux-$$arch"; \
	  GOOS=linux GOARCH=$$arch $(GOBUILD) -o bin/xnux-agent-linux-$$arch ./cmd/xnux-agent || exit 1; \
	done

## dist: everything a release publishes -> bin/
dist: agent
	cp deploy/install.sh deploy/uninstall.sh bin/
	cp relay/src/worker.js bin/xnux-relay.js
	cp relay/bark/worker.js bin/xnux-bark-relay.js
	$(MAKE) checksums

## checksums: sha256 of everything in bin/
checksums:
	cd bin && sha256sum $$(find . -maxdepth 1 -type f ! -name 'SHA256SUMS*' ! -name '*.sig' ! -name '*.pem' -printf '%f\n' | sort) > SHA256SUMS

test:
	go test -race ./...
	node --test relay/test/*.test.mjs

lint:
	golangci-lint run ./...

fmt:
	gofmt -w cmd internal

clean:
	rm -rf bin
