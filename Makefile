GO        ?= go
BIN       ?= bin
IMAGE     ?= vettid-relay:dev
PLATFORMS ?= linux/amd64,linux/arm64
FUZZTIME  ?= 20s
LDFLAGS   := -s -w -buildid=

.PHONY: all build test race lint vet staticcheck fuzz scan image image-multiarch tidy clean test-dynamo test-shared deps-up deps-down

all: lint test build

build:
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o $(BIN)/relay ./cmd/relay
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o $(BIN)/relayctl ./cmd/relayctl

test:
	$(GO) test ./...

race:
	$(GO) test -race ./...

# ---- Multi-process backend (DynamoDB + Valkey) -------------------------
# One container stack at a time, memory-capped: DynamoDB Local (in memory)
# and Valkey, on loopback only. `make test-dynamo` starts them, runs every
# test that needs them (DynamoDB conformance, coord, API suite on DynamoDB,
# multi-process e2e) and always tears them down.
CONTAINER      ?= $(shell command -v docker || command -v podman)
DDB_IMAGE      ?= docker.io/amazon/dynamodb-local:3.3.1@sha256:ff89bd48ff32cd8d9be5fee8873b65b8854dc408f1afe881be6eb00247bc0dab
VALKEY_IMAGE   ?= docker.io/valkey/valkey:8.1.10-alpine@sha256:081c2f5cb575efc901aa80ff9cdbd1ec6a301682fd35e1ebb4b0990a4a4a8507
DDB_PORT       ?= 18000
VALKEY_PORT    ?= 16379
SHARED_ENV      = RELAY_TEST_DYNAMODB_ENDPOINT=http://127.0.0.1:$(DDB_PORT) RELAY_TEST_VALKEY_ADDR=127.0.0.1:$(VALKEY_PORT)
GOTEST_LIGHT    = $(GO) test -p 1 -parallel 2 -count=1

deps-up:
	$(CONTAINER) run -d --rm --name relay-test-ddb --memory 1g -p 127.0.0.1:$(DDB_PORT):8000 $(DDB_IMAGE) -jar DynamoDBLocal.jar -inMemory -sharedDb
	$(CONTAINER) run -d --rm --name relay-test-valkey --memory 256m -p 127.0.0.1:$(VALKEY_PORT):6379 $(VALKEY_IMAGE)
	@for i in $$(seq 1 50); do curl -s -o /dev/null http://127.0.0.1:$(DDB_PORT) && break; sleep 0.2; done

deps-down:
	-$(CONTAINER) rm -f relay-test-ddb relay-test-valkey >/dev/null 2>&1

# Tests against already-running dependencies (CI services, or deps-up).
test-shared:
	$(SHARED_ENV) $(GOTEST_LIGHT) ./internal/store/... ./internal/coord/ ./test/e2e/
	$(SHARED_ENV) RELAY_TEST_API_STORE=dynamodb $(GOTEST_LIGHT) ./internal/api/

test-dynamo:
	$(MAKE) deps-up
	$(MAKE) test-shared; status=$$?; $(MAKE) deps-down; exit $$status

vet:
	$(GO) vet ./...

# staticcheck is run at a pinned version via `go run` (fetched on first use).
staticcheck:
	$(GO) run honnef.co/go/tools/cmd/staticcheck@v0.8.1 ./...

lint: vet staticcheck

# Each fuzz target runs for FUZZTIME. Seed corpora are the f.Add seeds in the
# tests (plus any regression inputs saved under testdata/fuzz).
fuzz:
	$(GO) test ./relayauth -run '^$$' -fuzz '^FuzzParseToken$$' -fuzztime $(FUZZTIME)
	$(GO) test ./relayauth -run '^$$' -fuzz '^FuzzCanonical$$' -fuzztime $(FUZZTIME)
	$(GO) test ./relayauth -run '^$$' -fuzz '^FuzzVerifyRequest$$' -fuzztime $(FUZZTIME)
	$(GO) test ./relayauth -run '^$$' -fuzz '^FuzzParseClaims$$' -fuzztime $(FUZZTIME)
	$(GO) test ./relayauth -run '^$$' -fuzz '^FuzzParseClaimID$$' -fuzztime $(FUZZTIME)

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
