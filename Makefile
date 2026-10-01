GO        ?= go
BIN       ?= bin
IMAGE     ?= vettid-relay:dev
PLATFORMS ?= linux/amd64,linux/arm64
FUZZTIME  ?= 20s
LDFLAGS   := -s -w -buildid=

.PHONY: all build test race lint vet staticcheck fuzz scan image image-multiarch tidy clean

all: lint test build

build:
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o $(BIN)/relay ./cmd/relay
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o $(BIN)/relayctl ./cmd/relayctl

test:
	$(GO) test ./...

race:
	$(GO) test -race ./...

vet:
	$(GO) vet ./...

# staticcheck is run at a pinned version via `go run` (fetched on first use).
staticcheck:
	$(GO) run honnef.co/go/tools/cmd/staticcheck@v0.8.1 ./...

lint: vet staticcheck

# Each fuzz target runs for FUZZTIME. Seed corpora live in testdata/fuzz.
fuzz:
	$(GO) test ./internal/auth -run '^$$' -fuzz '^FuzzParseToken$$' -fuzztime $(FUZZTIME)
	$(GO) test ./internal/auth -run '^$$' -fuzz '^FuzzCanonical$$' -fuzztime $(FUZZTIME)
	$(GO) test ./internal/auth -run '^$$' -fuzz '^FuzzVerifyRequest$$' -fuzztime $(FUZZTIME)

scan:
	gitleaks git --redact .

image:
	docker build -t $(IMAGE) .

image-multiarch:
	docker buildx build --platform $(PLATFORMS) -t $(IMAGE) .

tidy:
	$(GO) mod tidy

clean:
	rm -rf $(BIN)
