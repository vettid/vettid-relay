# syntax=docker.io/docker/dockerfile:1@sha256:4edf897a3ffa55b89f906fc8cc78afdb3f1834cc9c7083565e611a8a7d5fe99e
# VettID relay — small, non-root, static image.
#   docker build -t vettid-relay .
#   docker buildx build --platform linux/amd64,linux/arm64 -t vettid-relay .
# Binary path is stable: /relay. Container health check: /relay -healthcheck

FROM --platform=$BUILDPLATFORM docker.io/library/golang:1.26.10-alpine@sha256:9ce231b28998b32e116927c61aa5c406183061d4f3f2d61b292c88e7f6bdf7ca AS build
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
