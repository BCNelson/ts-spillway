package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadServerConfig_Defaults(t *testing.T) {
	// Clear all relevant env vars by unsetting them via t.Setenv
	for _, e := range []string{
		"SPILLWAY_BASE_DOMAIN", "SPILLWAY_REDIS_ADDR", "SPILLWAY_PORT_RANGE",
		"SPILLWAY_ACME_EMAIL", "SPILLWAY_ACME_DIRECTORY", "SPILLWAY_TS_STATE_DIR",
		"SPILLWAY_API_PORT", "SPILLWAY_HEARTBEAT_TTL",
		"SPILLWAY_TS_HOSTNAME", "SPILLWAY_SERVICE_NAME",
		"SPILLWAY_TS_AUTH_KEY", "SPILLWAY_TS_AUTH_KEY_FILE",
		"SPILLWAY_TS_CLIENT_ID", "SPILLWAY_TS_CLIENT_ID_FILE",
		"SPILLWAY_TS_CLIENT_SECRET", "SPILLWAY_TS_CLIENT_SECRET_FILE",
		"SPILLWAY_TS_ID_TOKEN", "SPILLWAY_TS_ID_TOKEN_FILE",
		"SPILLWAY_TS_AUDIENCE", "SPILLWAY_TS_AUDIENCE_FILE",
		"SPILLWAY_TS_EPHEMERAL",
		"SPILLWAY_USERNAME_FORMAT",
	} {
		t.Setenv(e, "")
	}

	cfg, err := LoadServerConfig()
	require.NoError(t, err)

	assert.Equal(t, "spillway.redo.run", cfg.BaseDomain)
	assert.Equal(t, "localhost:6379", cfg.RedisAddr)
	assert.Equal(t, 8000, cfg.PortRangeStart)
	assert.Equal(t, 9000, cfg.PortRangeEnd)
	assert.Equal(t, "", cfg.ACMEEmail)
	assert.Equal(t, "https://acme-v02.api.letsencrypt.org/directory", cfg.ACMEDirectory)
	assert.Equal(t, "tsnet-spillway", cfg.TSStateDir)
	assert.Equal(t, 9090, cfg.RegistrationAPIPort)
	assert.Equal(t, 90, cfg.HeartbeatTTL)
	assert.Equal(t, "spillway", cfg.TSHostname)
	assert.Equal(t, "svc:spillway", cfg.ServiceName)
	assert.Equal(t, "", cfg.TSAuthKey)
	assert.Equal(t, "", cfg.TSClientID)
	assert.Equal(t, "", cfg.TSClientSecret)
	assert.Equal(t, "", cfg.TSIDToken)
	assert.Equal(t, "", cfg.TSAudience)
	assert.False(t, cfg.TSEphemeral)
	assert.Equal(t, "short", cfg.UsernameFormat)
}

func TestLoadServerConfig_EnvOverrides(t *testing.T) {
	t.Setenv("SPILLWAY_BASE_DOMAIN", "my.domain.com")
	t.Setenv("SPILLWAY_REDIS_ADDR", "redis:6380")
	t.Setenv("SPILLWAY_PORT_RANGE", "5000-6000")
	t.Setenv("SPILLWAY_ACME_EMAIL", "admin@example.com")
	t.Setenv("SPILLWAY_API_PORT", "8080")
	t.Setenv("SPILLWAY_HEARTBEAT_TTL", "120")
	t.Setenv("SPILLWAY_TS_HOSTNAME", "spillway-2")
	t.Setenv("SPILLWAY_SERVICE_NAME", "svc:my-spillway")
	t.Setenv("SPILLWAY_TS_AUTH_KEY", "tskey-auth-test123")
	t.Setenv("SPILLWAY_TS_CLIENT_ID", "oidc-client-id")
	t.Setenv("SPILLWAY_TS_CLIENT_SECRET", "oidc-client-secret")
	t.Setenv("SPILLWAY_TS_ID_TOKEN", "eyJhbGciOiJSUzI1NiJ9.test")
	t.Setenv("SPILLWAY_TS_AUDIENCE", "https://login.tailscale.com")
	t.Setenv("SPILLWAY_TS_EPHEMERAL", "true")
	t.Setenv("SPILLWAY_USERNAME_FORMAT", "full")

	cfg, err := LoadServerConfig()
	require.NoError(t, err)

	assert.Equal(t, "my.domain.com", cfg.BaseDomain)
	assert.Equal(t, "redis:6380", cfg.RedisAddr)
	assert.Equal(t, 5000, cfg.PortRangeStart)
	assert.Equal(t, 6000, cfg.PortRangeEnd)
	assert.Equal(t, "admin@example.com", cfg.ACMEEmail)
	assert.Equal(t, 8080, cfg.RegistrationAPIPort)
	assert.Equal(t, 120, cfg.HeartbeatTTL)
	assert.Equal(t, "spillway-2", cfg.TSHostname)
	assert.Equal(t, "svc:my-spillway", cfg.ServiceName)
	assert.Equal(t, "tskey-auth-test123", cfg.TSAuthKey)
	assert.Equal(t, "oidc-client-id", cfg.TSClientID)
	assert.Equal(t, "oidc-client-secret", cfg.TSClientSecret)
	assert.Equal(t, "eyJhbGciOiJSUzI1NiJ9.test", cfg.TSIDToken)
	assert.Equal(t, "https://login.tailscale.com", cfg.TSAudience)
	assert.True(t, cfg.TSEphemeral)
	assert.Equal(t, "full", cfg.UsernameFormat)
}

func TestLoadServerConfig_InvalidPortRange(t *testing.T) {
	t.Setenv("SPILLWAY_PORT_RANGE", "invalid")
	_, err := LoadServerConfig()
	require.Error(t, err)
}

func TestLoadClientConfig_Defaults(t *testing.T) {
	t.Setenv("SPILLWAY_SERVER", "")

	cfg := LoadClientConfig()
	assert.Equal(t, "spillway:9090", cfg.ServerAddr)
	assert.Nil(t, cfg.Aliases)
}

func TestLoadClientConfig_EnvOverride(t *testing.T) {
	t.Setenv("SPILLWAY_SERVER", "myserver:1234")
	cfg := LoadClientConfig()
	assert.Equal(t, "myserver:1234", cfg.ServerAddr)
}

func TestLoadServerConfig_FileBased(t *testing.T) {
	// Clear direct env vars so only _FILE variants are active.
	for _, e := range []string{
		"SPILLWAY_TS_AUTH_KEY", "SPILLWAY_TS_CLIENT_ID",
		"SPILLWAY_TS_CLIENT_SECRET", "SPILLWAY_TS_ID_TOKEN",
		"SPILLWAY_TS_AUDIENCE", "SPILLWAY_TS_EPHEMERAL",
		"SPILLWAY_USERNAME_FORMAT",
	} {
		t.Setenv(e, "")
	}

	// Write a credential to a temp file (with extra whitespace to verify trimming).
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "auth-key")
	require.NoError(t, os.WriteFile(keyFile, []byte("  tskey-auth-from-file\n"), 0o600))

	t.Setenv("SPILLWAY_TS_AUTH_KEY_FILE", keyFile)
	// Clear other _FILE vars to isolate.
	for _, e := range []string{
		"SPILLWAY_TS_CLIENT_ID_FILE", "SPILLWAY_TS_CLIENT_SECRET_FILE",
		"SPILLWAY_TS_ID_TOKEN_FILE", "SPILLWAY_TS_AUDIENCE_FILE",
	} {
		t.Setenv(e, "")
	}

	cfg, err := LoadServerConfig()
	require.NoError(t, err)

	assert.Equal(t, "tskey-auth-from-file", cfg.TSAuthKey)
}

func TestLoadServerConfig_EnvTakesPriorityOverFile(t *testing.T) {
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "auth-key")
	require.NoError(t, os.WriteFile(keyFile, []byte("from-file"), 0o600))

	// Set both the direct env var and the _FILE var.
	t.Setenv("SPILLWAY_TS_AUTH_KEY", "from-env")
	t.Setenv("SPILLWAY_TS_AUTH_KEY_FILE", keyFile)

	cfg, err := LoadServerConfig()
	require.NoError(t, err)

	// Direct env var should win.
	assert.Equal(t, "from-env", cfg.TSAuthKey)
}

func TestParsePortRange(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantStart int
		wantEnd   int
		wantErr   bool
	}{
		{"valid range", "8000-9000", 8000, 9000, false},
		{"single port range", "8080-8080", 8080, 8080, false},
		{"missing dash", "8000", 0, 0, true},
		{"start > end", "9000-8000", 0, 0, true},
		{"non-numeric start", "abc-9000", 0, 0, true},
		{"non-numeric end", "8000-xyz", 0, 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			start, end, err := parsePortRange(tt.input)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.wantStart, start)
			assert.Equal(t, tt.wantEnd, end)
		})
	}
}

func TestLoadAliasConfig_FromFile(t *testing.T) {
	dir := t.TempDir()
	cfgFile := filepath.Join(dir, "spillway.yaml")
	require.NoError(t, os.WriteFile(cfgFile, []byte("aliases:\n  8080: myapp\n  3000: dashboard\n"), 0o644))

	// Change to the temp dir so loadAliasConfig finds ./spillway.yaml
	origDir, err := os.Getwd()
	require.NoError(t, err)
	require.NoError(t, os.Chdir(dir))
	defer func() { _ = os.Chdir(origDir) }()

	aliases := loadAliasConfig()
	assert.Equal(t, "myapp", aliases[8080])
	assert.Equal(t, "dashboard", aliases[3000])
}

func TestLoadAliasConfig_XDGPath(t *testing.T) {
	dir := t.TempDir()
	xdgDir := filepath.Join(dir, "spillway")
	require.NoError(t, os.MkdirAll(xdgDir, 0o755))
	cfgFile := filepath.Join(xdgDir, "config.yaml")
	require.NoError(t, os.WriteFile(cfgFile, []byte("aliases:\n  9090: api\n"), 0o644))

	t.Setenv("XDG_CONFIG_HOME", dir)

	// Change to a dir without spillway.yaml so XDG path is used
	emptyDir := t.TempDir()
	origDir, err := os.Getwd()
	require.NoError(t, err)
	require.NoError(t, os.Chdir(emptyDir))
	defer func() { _ = os.Chdir(origDir) }()

	aliases := loadAliasConfig()
	assert.Equal(t, "api", aliases[9090])
}

func TestLoadAliasConfig_NoFile(t *testing.T) {
	dir := t.TempDir()
	origDir, err := os.Getwd()
	require.NoError(t, err)
	require.NoError(t, os.Chdir(dir))
	defer func() { _ = os.Chdir(origDir) }()

	t.Setenv("XDG_CONFIG_HOME", filepath.Join(dir, "nonexistent"))

	aliases := loadAliasConfig()
	assert.Nil(t, aliases)
}

func TestValidateAlias(t *testing.T) {
	tests := []struct {
		name    string
		alias   string
		wantErr bool
	}{
		{"valid simple", "myapp", false},
		{"valid with hyphens", "my-cool-app", false},
		{"valid with numbers", "app2", false},
		{"valid single char", "a", false},
		{"empty", "", true},
		{"starts with digit", "1app", true},
		{"starts with hyphen", "-app", true},
		{"ends with hyphen", "app-", true},
		{"uppercase", "MyApp", true},
		{"has underscore", "my_app", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateAlias(tt.alias)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
