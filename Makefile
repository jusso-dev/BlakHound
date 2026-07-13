BINARY := blakhound
PKG := github.com/jusso-dev/BlakHound
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
DATE ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS := -X $(PKG)/internal/version.Version=$(VERSION) \
           -X $(PKG)/internal/version.Commit=$(COMMIT) \
           -X $(PKG)/internal/version.BuildDate=$(DATE)

.PHONY: build test lint run snapshot release-snapshot vet tidy clean vulncheck

build:
	go build -ldflags "$(LDFLAGS)" -o bin/$(BINARY) ./cmd/$(BINARY)

test:
	go test ./...

vet:
	go vet ./...

lint:
	golangci-lint run ./...

vulncheck:
	govulncheck ./...

run: build
	./bin/$(BINARY) $(ARGS)

snapshot:
	goreleaser release --snapshot --clean

release-snapshot: snapshot

tidy:
	go mod tidy

clean:
	rm -rf bin dist

# Opt-in live AWS integration tests (requires BLAKHOUND_AWS_INTEGRATION=1).
.PHONY: test-aws-integration
test-aws-integration:
	BLAKHOUND_AWS_INTEGRATION=1 go test -tags=awsintegration ./...
