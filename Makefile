VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: build test check clean

build:
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/patchwarden ./cmd/patchwarden

test:
	go test -race ./...

check: test
	go vet ./...
	@test -z "$$(gofmt -l .)" || (echo "Fichiers non formatés :"; gofmt -l .; exit 1)
	shellcheck -S warning tools/sonde.sh deploy/patchwarden-wrapper

clean:
	rm -rf bin
