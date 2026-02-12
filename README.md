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
| `SPILLWAY_TS_HOSTNAME` | `spillway` | Tailscale hostname for this instance |
| `SPILLWAY_SERVICE_NAME` | `svc:spillway` | Tailscale Service name for discovery |
| `SPILLWAY_TS_AUTH_KEY` | *(none)* | Tailscale auth key |
| `SPILLWAY_TS_CLIENT_ID` | *(none)* | OAuth / WIF client ID |
| `SPILLWAY_TS_CLIENT_SECRET` | *(none)* | OAuth client secret |
| `SPILLWAY_TS_ID_TOKEN` | *(none)* | WIF OIDC ID token |
| `SPILLWAY_TS_AUDIENCE` | *(none)* | WIF OIDC audience |
| `SPILLWAY_TS_EPHEMERAL` | `false` | Mark node as ephemeral (`true`/`false`) |

Every `SPILLWAY_TS_*` variable (except `SPILLWAY_TS_EPHEMERAL`) also supports a `_FILE` suffix (e.g., `SPILLWAY_TS_AUTH_KEY_FILE=/run/secrets/ts-auth-key`) that reads the value from a file. This is useful for Docker secrets and Kubernetes secret volumes. If both the direct variable and the `_FILE` variant are set, the direct variable takes priority.

### Tailscale authentication

The server joins the tailnet using `tsnet`. Three authentication methods are supported:

**Auth Key** — simplest option for automated deployments:
```sh
export SPILLWAY_TS_AUTH_KEY=tskey-auth-...
# or via file:
export SPILLWAY_TS_AUTH_KEY_FILE=/run/secrets/ts-auth-key
```

**OAuth Client** — for headless servers using Tailscale OAuth credentials:
```sh
export SPILLWAY_TS_CLIENT_ID=oidc-client-id
export SPILLWAY_TS_CLIENT_SECRET=oidc-client-secret
```

**Workload Identity Federation** — OIDC-based authentication using `ClientID` with either an `IDToken` or `Audience`:
```sh
export SPILLWAY_TS_CLIENT_ID=oidc-client-id
export SPILLWAY_TS_ID_TOKEN=eyJhbGci...    # or SPILLWAY_TS_AUDIENCE=https://...
```

If none of the `SPILLWAY_TS_*` auth variables are set, the server falls back to tsnet's native behavior: reading `TS_AUTHKEY` / `TS_AUTH_KEY` env vars, or using persisted state / interactive login.

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
