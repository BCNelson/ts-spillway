# syntax=docker/dockerfile:1

# ── Builder ──────────────────────────────────────────────────────────────────
FROM --platform=$BUILDPLATFORM golang:1.25-bookworm AS builder

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG TARGETOS TARGETARCH
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -ldflags="-s -w" -o /out/spillway-server ./cmd/spillway-server

# ── Runtime ──────────────────────────────────────────────────────────────────
FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=builder /out/spillway-server /usr/local/bin/spillway-server

ENV SPILLWAY_TS_STATE_DIR=/var/lib/spillway/tsnet
VOLUME ["/var/lib/spillway/tsnet"]

EXPOSE 443 8000-9000

ENTRYPOINT ["spillway-server"]
