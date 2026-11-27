VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: build test check ci clean

build:
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/patchwarden ./cmd/patchwarden

test:
	go test -race ./...

check: test
	go vet ./...
	@test -z "$$(gofmt -l .)" || (echo "Fichiers non formatés :"; gofmt -l .; exit 1)
	shellcheck -S warning tools/sonde.sh deploy/patchwarden-wrapper

# Mêmes vérifications que .github/workflows/ci.yml, en local (CT 103 compris).
# -race demande un compilateur C (paquet gcc) : sans lui, tests sans -race.
# shellcheck est sauté s'il n'est pas installé (apt install shellcheck).
ci:
	@echo "== gofmt"; f="$$(gofmt -l .)"; if [ -n "$$f" ]; then echo "Fichiers non formatés (gofmt -w) :"; echo "$$f"; exit 1; fi
	@echo "== go vet"; go vet ./...
	@if command -v gcc >/dev/null 2>&1; then echo "== go test -race"; CGO_ENABLED=1 go test -race -count=1 ./...; \
	else echo "== go test (gcc absent : sans -race)"; go test -count=1 ./...; fi
	@if command -v shellcheck >/dev/null 2>&1; then echo "== shellcheck"; shellcheck -S warning tools/sonde.sh deploy/patchwarden-wrapper; \
	else echo "== shellcheck absent : sauté (apt install shellcheck)"; fi
	@echo "== compilation"; $(MAKE) --no-print-directory build
	@echo "Toutes les vérifications sont passées."

clean:
	rm -rf bin
