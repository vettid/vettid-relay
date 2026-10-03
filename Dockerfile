# syntax=docker/dockerfile:1
# VettID relay — small, non-root, static image.
#   docker build -t vettid-relay .
#   docker buildx build --platform linux/amd64,linux/arm64 -t vettid-relay .
# Binary path is stable: /relay. Container health check: /relay -healthcheck

FROM --platform=$BUILDPLATFORM docker.io/library/golang:1.26-alpine@sha256:8ac98ca534ac3f51e1f420a1dd2c15e74c75cfa0f23f3ad27eb5d7236c349a0c AS build
ARG TARGETOS
ARG TARGETARCH
ARG VERSION=""
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download && go mod verify
COPY . .
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags "-s -w -buildid= -X main.version=${VERSION}" -o /out/relay ./cmd/relay \
 && mkdir -p /out/data

FROM gcr.io/distroless/static-debian13:nonroot@sha256:e2e927ec666bae08560abb3c55d0659eceabb657f56b6782ab500a9fc7f555e3
COPY --from=build /out/relay /relay
# /data is where the single SQLite file lives (RELAY_STORE=sqlite); mount
# persistent storage here. Unused with RELAY_STORE=dynamodb.
COPY --from=build --chown=65532:65532 /out/data /data
USER 65532:65532
ENV RELAY_LISTEN_ADDR=:8080 \
    RELAY_DB_PATH=/data/relay.db \
    RELAY_METRICS_ADDR=127.0.0.1:9090
EXPOSE 8080
HEALTHCHECK --interval=15s --timeout=5s --start-period=10s --retries=3 CMD ["/relay", "-healthcheck"]
ENTRYPOINT ["/relay"]
