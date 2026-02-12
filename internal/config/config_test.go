package config

import (
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
}

func TestLoadClientConfig_EnvOverride(t *testing.T) {
	t.Setenv("SPILLWAY_SERVER", "myserver:1234")
	cfg := LoadClientConfig()
	assert.Equal(t, "myserver:1234", cfg.ServerAddr)
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
