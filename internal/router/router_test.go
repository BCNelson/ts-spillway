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
			name:    "non-numeric port label",
			host:    "abc.mymachine.alice.spillway.redo.run",
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
