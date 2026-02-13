package router

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewRouter(t *testing.T) {
	r := NewRouter("spillway.redo.run")
	assert.Equal(t, "spillway.redo.run", r.baseDomain)
	assert.Equal(t, 3, r.baseLabels)
}

func TestNewRouter_CaseFolding(t *testing.T) {
	r := NewRouter("Spillway.Redo.Run")
	assert.Equal(t, "spillway.redo.run", r.baseDomain)
}

func TestParseHost_SubdomainFormat(t *testing.T) {
	r := NewRouter("spillway.redo.run")

	tests := []struct {
		name    string
		host    string
		want    *Route
		wantErr bool
	}{
		{
			name: "standard subdomain",
			host: "8000.mymachine.alice.spillway.redo.run",
			want: &Route{User: "alice", Machine: "mymachine", Port: 8000},
		},
		{
			name: "subdomain with explicit port 443",
			host: "8000.mymachine.alice.spillway.redo.run:443",
			want: &Route{User: "alice", Machine: "mymachine", Port: 8000},
		},
		{
			name: "case insensitive",
			host: "8000.MyMachine.Alice.Spillway.Redo.Run",
			want: &Route{User: "alice", Machine: "mymachine", Port: 8000},
		},
		{
			name: "alias subdomain",
			host: "myapp.mymachine.alice.spillway.redo.run",
			want: &Route{User: "alice", Machine: "mymachine", Alias: "myapp"},
		},
		{
			name: "alias with hyphens",
			host: "my-cool-app.mymachine.alice.spillway.redo.run",
			want: &Route{User: "alice", Machine: "mymachine", Alias: "my-cool-app"},
		},
		{
			name:    "invalid alias starting with hyphen",
			host:    "-badname.mymachine.alice.spillway.redo.run",
			wantErr: true,
		},
		{
			name:    "invalid alias ending with hyphen",
			host:    "badname-.mymachine.alice.spillway.redo.run",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := r.ParseHost(tt.host)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestParseHost_PortBasedFormat(t *testing.T) {
	r := NewRouter("spillway.redo.run")

	tests := []struct {
		name    string
		host    string
		want    *Route
		wantErr bool
	}{
		{
			name: "port in host header",
			host: "mymachine.alice.spillway.redo.run:8000",
			want: &Route{User: "alice", Machine: "mymachine", Port: 8000},
		},
		{
			name:    "missing port",
			host:    "mymachine.alice.spillway.redo.run",
			wantErr: true,
		},
		{
			name:    "non-numeric port",
			host:    "mymachine.alice.spillway.redo.run:abc",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := r.ParseHost(tt.host)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestParseHost_Errors(t *testing.T) {
	r := NewRouter("spillway.redo.run")

	tests := []struct {
		name string
		host string
	}{
		{"wrong base domain", "8000.mymachine.alice.example.com"},
		{"too few labels", "alice.spillway.redo.run"},
		{"too many labels", "extra.8000.mymachine.alice.spillway.redo.run"},
		{"empty host", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := r.ParseHost(tt.host)
			require.Error(t, err)
		})
	}
}

func TestParseRequest(t *testing.T) {
	r := NewRouter("spillway.redo.run")

	req, err := http.NewRequest("GET", "https://8000.mymachine.alice.spillway.redo.run/path", nil)
	require.NoError(t, err)
	req.Host = "8000.mymachine.alice.spillway.redo.run"

	route, err := r.ParseRequest(req)
	require.NoError(t, err)
	assert.Equal(t, &Route{User: "alice", Machine: "mymachine", Port: 8000}, route)
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
		{"has dot", "my.app", true},
		{"too long", "a" + string(make([]byte, 63)), true},
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
