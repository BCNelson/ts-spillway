package auth

import (
	"context"
	"fmt"
	"net/http"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/tailcfg"
)

// mockWhoIser is a test double for the WhoIser interface.
type mockWhoIser struct {
	fn func(ctx context.Context, remoteAddr string) (*apitype.WhoIsResponse, error)
}

func (m *mockWhoIser) WhoIs(ctx context.Context, remoteAddr string) (*apitype.WhoIsResponse, error) {
	return m.fn(ctx, remoteAddr)
}

func TestIdentify_Success(t *testing.T) {
	mock := &mockWhoIser{
		fn: func(_ context.Context, remoteAddr string) (*apitype.WhoIsResponse, error) {
			assert.Equal(t, "100.64.0.5:12345", remoteAddr)
			return &apitype.WhoIsResponse{
				Node: &tailcfg.Node{
					ComputedName: "MyLaptop",
					Addresses: []netip.Prefix{
						netip.MustParsePrefix("100.64.0.5/32"),
						netip.MustParsePrefix("fd7a:115c:a1e0::5/128"),
					},
				},
				UserProfile: &tailcfg.UserProfile{
					ID:          12345,
					LoginName:   "alice@github",
					DisplayName: "Alice Smith",
				},
			}, nil
		},
	}

	a := NewAuthenticatorFromWhoIser(mock)

	req, _ := http.NewRequest("GET", "http://example.com", nil)
	req.RemoteAddr = "100.64.0.5:12345"

	id, err := a.Identify(req)
	require.NoError(t, err)

	assert.Equal(t, "12345", id.UserID)
	assert.Equal(t, "alice", id.LoginName)
	assert.Equal(t, "Alice Smith", id.DisplayName)
	assert.Equal(t, "mylaptop", id.MachineName)
	assert.Equal(t, "100.64.0.5", id.TailscaleIP)
}

func TestIdentify_LoginNameWithoutDomain(t *testing.T) {
	mock := &mockWhoIser{
		fn: func(_ context.Context, _ string) (*apitype.WhoIsResponse, error) {
			return &apitype.WhoIsResponse{
				Node: &tailcfg.Node{
					ComputedName: "desktop",
					Addresses:    []netip.Prefix{netip.MustParsePrefix("100.64.0.1/32")},
				},
				UserProfile: &tailcfg.UserProfile{
					ID:          1,
					LoginName:   "bob",
					DisplayName: "Bob",
				},
			}, nil
		},
	}

	a := NewAuthenticatorFromWhoIser(mock)
	req, _ := http.NewRequest("GET", "http://example.com", nil)
	req.RemoteAddr = "100.64.0.1:1234"

	id, err := a.Identify(req)
	require.NoError(t, err)
	assert.Equal(t, "bob", id.LoginName)
}

func TestIdentify_WhoIsError(t *testing.T) {
	mock := &mockWhoIser{
		fn: func(_ context.Context, _ string) (*apitype.WhoIsResponse, error) {
			return nil, fmt.Errorf("connection refused")
		},
	}

	a := NewAuthenticatorFromWhoIser(mock)
	req, _ := http.NewRequest("GET", "http://example.com", nil)
	req.RemoteAddr = "100.64.0.1:1234"

	_, err := a.Identify(req)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "WhoIs failed")
}

func TestIdentify_NoUserProfile(t *testing.T) {
	mock := &mockWhoIser{
		fn: func(_ context.Context, _ string) (*apitype.WhoIsResponse, error) {
			return &apitype.WhoIsResponse{
				Node:        &tailcfg.Node{},
				UserProfile: nil,
			}, nil
		},
	}

	a := NewAuthenticatorFromWhoIser(mock)
	req, _ := http.NewRequest("GET", "http://example.com", nil)
	req.RemoteAddr = "100.64.0.1:1234"

	_, err := a.Identify(req)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no user profile")
}

func TestIdentify_NoTailscaleIP(t *testing.T) {
	mock := &mockWhoIser{
		fn: func(_ context.Context, _ string) (*apitype.WhoIsResponse, error) {
			return &apitype.WhoIsResponse{
				Node: &tailcfg.Node{
					ComputedName: "mynode",
					Addresses:    nil,
				},
				UserProfile: &tailcfg.UserProfile{
					ID:          1,
					LoginName:   "alice@github",
					DisplayName: "Alice",
				},
			}, nil
		},
	}

	a := NewAuthenticatorFromWhoIser(mock)
	req, _ := http.NewRequest("GET", "http://example.com", nil)
	req.RemoteAddr = "100.64.0.1:1234"

	_, err := a.Identify(req)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no Tailscale IP")
}

func TestTailscaleIPFromAddrs(t *testing.T) {
	tests := []struct {
		name  string
		addrs []netip.Prefix
		want  string
	}{
		{
			name: "prefer 100.x IPv4",
			addrs: []netip.Prefix{
				netip.MustParsePrefix("fd7a:115c:a1e0::1/128"),
				netip.MustParsePrefix("100.64.0.1/32"),
			},
			want: "100.64.0.1",
		},
		{
			name: "fallback to first address",
			addrs: []netip.Prefix{
				netip.MustParsePrefix("fd7a:115c:a1e0::1/128"),
			},
			want: "fd7a:115c:a1e0::1",
		},
		{
			name:  "empty addrs",
			addrs: nil,
			want:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tailscaleIPFromAddrs(tt.addrs)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestContextRoundTrip(t *testing.T) {
	id := &Identity{
		UserID:      "42",
		LoginName:   "alice",
		DisplayName: "Alice",
		MachineName: "laptop",
		TailscaleIP: "100.64.0.1",
	}

	ctx := WithIdentity(context.Background(), id)
	got, ok := GetIdentity(ctx)
	require.True(t, ok)
	assert.Equal(t, id, got)
}

func TestGetIdentity_Missing(t *testing.T) {
	_, ok := GetIdentity(context.Background())
	assert.False(t, ok)
}
