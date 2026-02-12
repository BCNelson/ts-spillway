# ts-spillway

Expose local ports to the public internet via Tailscale with automatic TLS.

## How it works

Spillway consists of a **server** and a **client**, both connected over a [Tailscale](https://tailscale.com/) tailnet.

1. The client (`spillway`) registers one or more local ports with the server over the Tailscale network.
2. The server (`spillway-server`) accepts public HTTPS traffic, resolves the target user/machine/port from the request hostname, and proxies the connection back to the client through Tailscale.
3. TLS certificates are automatically issued via ACME (Let's Encrypt) using DNS-01 challenges with AWS Route 53.

Registrations are stored in Redis and kept alive with a heartbeat; when the client disconnects, the registration expires automatically.

## URL formats

Spillway supports two ways to reach an exposed port (examples use `example.com` as the base domain):

| Format | URL |
|---|---|
| **Subdomain** | `https://8080.mypc.alice.example.com` |
| **Port-based** | `https://mypc.alice.example.com:8080` |

The subdomain format encodes the port as the leftmost DNS label. The port-based format uses the host port directly.

## Prerequisites

- **Tailscale** — both the server and client must be on the same tailnet
- **Redis** — used by the server for registration storage and certificate caching
- **AWS credentials** — for Route 53 DNS-01 ACME challenges (standard `AWS_*` env vars)
- **Go 1.25+** — for building from source

## Installation

Install both binaries with `go install`:

```sh
go install github.com/bcnelson/ts-spillway/cmd/spillway@latest
go install github.com/bcnelson/ts-spillway/cmd/spillway-server@latest
```

Or build from source:

```sh
git clone https://github.com/bcnelson/ts-spillway.git
cd ts-spillway
make build      # outputs bin/spillway and bin/spillway-server
```

## Server setup

Configure the server with environment variables:

| Variable | Default | Description |
|---|---|---|
| `SPILLWAY_BASE_DOMAIN` | `example.com` | Base domain for routing |
| `SPILLWAY_REDIS_ADDR` | `localhost:6379` | Redis address |
| `SPILLWAY_PORT_RANGE` | `8000-9000` | Public port range for port-based access |
| `SPILLWAY_ACME_EMAIL` | *(none)* | ACME registration email (required for TLS) |
| `SPILLWAY_ACME_DIRECTORY` | Let's Encrypt production | ACME directory URL |
| `SPILLWAY_TS_STATE_DIR` | `tsnet-spillway` | Tailscale state directory |
| `SPILLWAY_API_PORT` | `9090` | Registration API port (Tailscale-side) |
| `SPILLWAY_HEARTBEAT_TTL` | `90` | Registration TTL in seconds |

Run the server:

```sh
export SPILLWAY_BASE_DOMAIN=example.com
export SPILLWAY_ACME_EMAIL=admin@example.com
spillway-server
```

## Client usage

The client communicates with the server over Tailscale.

| Variable | Default | Description |
|---|---|---|
| `SPILLWAY_SERVER` | `spillway:9090` | Tailscale address of the spillway server |

Expose a single port:

```sh
spillway start 8080
```

Expose a range of ports:

```sh
spillway start 8000-8050
```

Check active registrations:

```sh
spillway status
```

The client sends a heartbeat every 30 seconds and deregisters cleanly on Ctrl+C.

## Development

### Nix / devenv

The project includes a [devenv](https://devenv.sh/) configuration that provides Go, golangci-lint, delve, and a local Redis instance:

```sh
devenv shell
```

### Make targets

```
make build      # Build both binaries to bin/
make test       # Run unit tests
make test-race  # Run tests with race detector
make test-cover # Run tests with coverage report
make test-e2e   # Run end-to-end tests (requires Tailscale + real network)
make lint       # Run go vet + golangci-lint
make clean      # Remove build artifacts
```
