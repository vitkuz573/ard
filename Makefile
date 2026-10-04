# ARD developer workflow.
#
# The gateway has no Go toolchain, so everything deploys as a static cross-build.

GOOS_TARGET := linux/amd64
BINARIES    := ard-server ard-proxy ard-agent ard-tap ard-ca

.PHONY: all build test race vet fmt clean dist pki-demo

all: build

build:
	go build ./...

test:
	go test ./... -timeout 120s

race:
	go test ./... -race -timeout 300s

vet:
	go vet ./...

fmt:
	gofmt -l -w .

dist:
	@mkdir -p dist/$(GOOS_TARGET)
	@for b in $(BINARIES); do \
		if [ -d cmd/$$b ]; then \
			CGO_ENABLED=0 GOOS=$(GOOS_TARGET) \
				go build -trimpath -ldflags "-s -w" -o dist/$(GOOS_TARGET)/$$b ./cmd/$$b && \
			echo "  $$b"; \
		fi; \
	done

clean:
	rm -rf dist
	go clean -testcache

# Generates a throwaway PKI under /tmp for local experiments.
pki-demo:
	go run ./cmd/ard-ca init -dir /tmp/ard-pki
	go run ./cmd/ard-ca device -dir /tmp/ard-pki -id dev-001
	go run ./cmd/ard-ca operator -dir /tmp/ard-pki -name alice
	go run ./cmd/ard-ca list -dir /tmp/ard-pki
