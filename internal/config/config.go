package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
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

	// TSAuthKey is a Tailscale auth key for automatic authentication.
	TSAuthKey string

	// TSClientID is the OAuth client ID for Tailscale OAuth or Workload Identity Federation.
	TSClientID string

	// TSClientSecret is the OAuth client secret for Tailscale OAuth authentication.
	TSClientSecret string

	// TSIDToken is the OIDC ID token for Tailscale Workload Identity Federation.
	TSIDToken string

	// TSAudience is the OIDC audience for Tailscale Workload Identity Federation.
	TSAudience string

	// TSEphemeral marks the Tailscale node as ephemeral (removed on disconnect).
	TSEphemeral bool

	// UsernameFormat controls how login names are sanitized for DNS.
	// "short" (default): strips domain — "alice@github" -> "alice"
	// "full": replaces special chars — "alice@github" -> "alice-github"
	// Any other value is treated as a primary domain: users matching that
	// domain are shortened, others get the full format.
	// e.g. "github": "alice@github" -> "alice", "alice@google" -> "alice-google"
	UsernameFormat string
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
		TSAuthKey:           envOrFile("SPILLWAY_TS_AUTH_KEY", "SPILLWAY_TS_AUTH_KEY_FILE"),
		TSClientID:          envOrFile("SPILLWAY_TS_CLIENT_ID", "SPILLWAY_TS_CLIENT_ID_FILE"),
		TSClientSecret:      envOrFile("SPILLWAY_TS_CLIENT_SECRET", "SPILLWAY_TS_CLIENT_SECRET_FILE"),
		TSIDToken:           envOrFile("SPILLWAY_TS_ID_TOKEN", "SPILLWAY_TS_ID_TOKEN_FILE"),
		TSAudience:          envOrFile("SPILLWAY_TS_AUDIENCE", "SPILLWAY_TS_AUDIENCE_FILE"),
		TSEphemeral:         os.Getenv("SPILLWAY_TS_EPHEMERAL") == "true",
		UsernameFormat:      envOrDefault("SPILLWAY_USERNAME_FORMAT", "short"),
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

	// Aliases maps port numbers to friendly alias names.
	Aliases map[int]string
}

// LoadClientConfig reads client configuration from environment variables
// and loads aliases from the config file.
func LoadClientConfig() *ClientConfig {
	cfg := &ClientConfig{
		ServerAddr: envOrDefault("SPILLWAY_SERVER", "spillway:9090"),
	}
	cfg.Aliases = loadAliasConfig()
	return cfg
}

// aliasFileConfig represents the YAML structure for alias configuration.
type aliasFileConfig struct {
	Aliases map[int]string `yaml:"aliases"`
}

// loadAliasConfig reads alias configuration from YAML files in standard locations.
// Search order: ./spillway.yaml -> $XDG_CONFIG_HOME/spillway/config.yaml -> ~/.config/spillway/config.yaml
func loadAliasConfig() map[int]string {
	paths := aliasConfigPaths()
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		var cfg aliasFileConfig
		if err := yaml.Unmarshal(data, &cfg); err != nil {
			continue
		}
		if len(cfg.Aliases) > 0 {
			return cfg.Aliases
		}
	}
	return nil
}

// aliasConfigPaths returns the ordered list of config file paths to search.
func aliasConfigPaths() []string {
	var paths []string

	// 1. Current directory
	paths = append(paths, "spillway.yaml")

	// 2. XDG_CONFIG_HOME
	if xdg := os.Getenv("XDG_CONFIG_HOME"); xdg != "" {
		paths = append(paths, filepath.Join(xdg, "spillway", "config.yaml"))
	}

	// 3. ~/.config/spillway/config.yaml
	if home, err := os.UserHomeDir(); err == nil {
		paths = append(paths, filepath.Join(home, ".config", "spillway", "config.yaml"))
	}

	return paths
}

// ValidateAlias checks that an alias is a valid DNS label that does not start
// with a digit. This is re-exported from the router package for convenience
// but is defined here to avoid circular imports in the client binary.
// The actual validation logic lives in router.ValidateAlias.
// This function provides a basic check suitable for client-side pre-validation.
func ValidateAlias(alias string) error {
	if alias == "" {
		return fmt.Errorf("alias must not be empty")
	}
	if len(alias) > 63 {
		return fmt.Errorf("alias must be at most 63 characters")
	}
	if alias[0] >= '0' && alias[0] <= '9' {
		return fmt.Errorf("alias must not start with a digit")
	}
	for _, c := range alias {
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
			return fmt.Errorf("alias must contain only lowercase alphanumeric characters and hyphens")
		}
	}
	if strings.HasPrefix(alias, "-") || strings.HasSuffix(alias, "-") {
		return fmt.Errorf("alias must not start or end with a hyphen")
	}
	return nil
}

// envOrFile returns the value of the env var named key if set and non-empty.
// Otherwise, if the env var named fileKey is set, it reads the file at that path
// and returns its contents with surrounding whitespace trimmed.
// Returns "" if neither is set.
func envOrFile(key, fileKey string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	if path := os.Getenv(fileKey); path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			return ""
		}
		return strings.TrimSpace(string(data))
	}
	return ""
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
