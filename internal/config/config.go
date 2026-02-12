package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

// ServerConfig holds all server configuration from environment variables.
type ServerConfig struct {
	// BaseDomain is the base domain for spillway (e.g., "spillway.redo.run").
	BaseDomain string

	// RedisAddr is the Redis server address (e.g., "localhost:6379").
	RedisAddr string

	// PortRangeStart is the beginning of the public port range for port-based access.
	PortRangeStart int

	// PortRangeEnd is the end of the public port range for port-based access.
	PortRangeEnd int

	// ACMEEmail is the email used for ACME certificate registration.
	ACMEEmail string

	// ACMEDirectory is the ACME directory URL (defaults to Let's Encrypt production).
	ACMEDirectory string

	// TSStateDir is the directory for Tailscale state persistence.
	TSStateDir string

	// RegistrationAPIPort is the port for the Tailscale-side registration API.
	RegistrationAPIPort int

	// HeartbeatTTL is the TTL in seconds for registration keys in Redis.
	HeartbeatTTL int

	// TSHostname is the Tailscale hostname for this instance (must be unique per instance).
	TSHostname string

	// ServiceName is the Tailscale Service name used for service discovery (e.g., "svc:spillway").
	ServiceName string
}

// LoadServerConfig reads configuration from environment variables with sensible defaults.
func LoadServerConfig() (*ServerConfig, error) {
	cfg := &ServerConfig{
		BaseDomain:          envOrDefault("SPILLWAY_BASE_DOMAIN", "spillway.redo.run"),
		RedisAddr:           envOrDefault("SPILLWAY_REDIS_ADDR", "localhost:6379"),
		ACMEEmail:           os.Getenv("SPILLWAY_ACME_EMAIL"),
		ACMEDirectory:       envOrDefault("SPILLWAY_ACME_DIRECTORY", "https://acme-v02.api.letsencrypt.org/directory"),
		TSStateDir:          envOrDefault("SPILLWAY_TS_STATE_DIR", "tsnet-spillway"),
		RegistrationAPIPort: envIntOrDefault("SPILLWAY_API_PORT", 9090),
		HeartbeatTTL:        envIntOrDefault("SPILLWAY_HEARTBEAT_TTL", 90),
		TSHostname:          envOrDefault("SPILLWAY_TS_HOSTNAME", "spillway"),
		ServiceName:         envOrDefault("SPILLWAY_SERVICE_NAME", "svc:spillway"),
	}

	portRange := envOrDefault("SPILLWAY_PORT_RANGE", "8000-9000")
	start, end, err := parsePortRange(portRange)
	if err != nil {
		return nil, fmt.Errorf("invalid SPILLWAY_PORT_RANGE %q: %w", portRange, err)
	}
	cfg.PortRangeStart = start
	cfg.PortRangeEnd = end

	return cfg, nil
}

// ClientConfig holds CLI client configuration.
type ClientConfig struct {
	// ServerAddr is the Tailscale address of the spillway server.
	ServerAddr string
}

// LoadClientConfig reads client configuration from environment variables.
func LoadClientConfig() *ClientConfig {
	return &ClientConfig{
		ServerAddr: envOrDefault("SPILLWAY_SERVER", "spillway:9090"),
	}
}

func envOrDefault(key, defaultVal string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return defaultVal
}

func envIntOrDefault(key string, defaultVal int) int {
	if v := os.Getenv(key); v != "" {
		n, err := strconv.Atoi(v)
		if err == nil {
			return n
		}
	}
	return defaultVal
}

func parsePortRange(s string) (start, end int, err error) {
	parts := strings.SplitN(s, "-", 2)
	if len(parts) != 2 {
		return 0, 0, fmt.Errorf("expected format start-end")
	}
	start, err = strconv.Atoi(parts[0])
	if err != nil {
		return 0, 0, fmt.Errorf("invalid start port: %w", err)
	}
	end, err = strconv.Atoi(parts[1])
	if err != nil {
		return 0, 0, fmt.Errorf("invalid end port: %w", err)
	}
	if start > end {
		return 0, 0, fmt.Errorf("start port %d > end port %d", start, end)
	}
	return start, end, nil
}
