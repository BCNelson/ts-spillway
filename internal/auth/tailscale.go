package auth

import (
	"context"
	"fmt"
	"net/http"
	"net/netip"
	"strings"

	"tailscale.com/client/local"
)

// Identity represents an authenticated Tailscale user and their machine.
type Identity struct {
	UserID      string
	LoginName   string // e.g., "alice@github"
	DisplayName string
	MachineName string // e.g., "mymachine"
	TailscaleIP string // e.g., "100.64.0.1"
}

// Authenticator authenticates requests using the Tailscale WhoIs API.
type Authenticator struct {
	lc *local.Client
}

// NewAuthenticator creates an Authenticator backed by the given LocalClient.
func NewAuthenticator(lc *local.Client) *Authenticator {
	return &Authenticator{lc: lc}
}

// Identify extracts the caller's Tailscale identity from the request.
// This only works for requests arriving on a tsnet listener.
func (a *Authenticator) Identify(r *http.Request) (*Identity, error) {
	who, err := a.lc.WhoIs(r.Context(), r.RemoteAddr)
	if err != nil {
		return nil, fmt.Errorf("WhoIs failed: %w", err)
	}

	if who.UserProfile == nil {
		return nil, fmt.Errorf("no user profile for %s", r.RemoteAddr)
	}

	ip := tailscaleIPFromAddrs(who.Node.Addresses)
	if ip == "" {
		return nil, fmt.Errorf("no Tailscale IP for node %s", who.Node.ComputedName)
	}

	// Sanitize login name: "alice@github" -> "alice"
	loginName := who.UserProfile.LoginName
	shortName := loginName
	if idx := strings.Index(loginName, "@"); idx > 0 {
		shortName = loginName[:idx]
	}

	return &Identity{
		UserID:      fmt.Sprintf("%d", who.UserProfile.ID),
		LoginName:   shortName,
		DisplayName: who.UserProfile.DisplayName,
		MachineName: strings.ToLower(who.Node.ComputedName),
		TailscaleIP: ip,
	}, nil
}

// IdentifyContext is a convenience that extracts identity from context (for middleware use).
type contextKey string

const identityKey contextKey = "spillway-identity"

// WithIdentity stores an Identity in the request context.
func WithIdentity(ctx context.Context, id *Identity) context.Context {
	return context.WithValue(ctx, identityKey, id)
}

// GetIdentity retrieves an Identity from the request context.
func GetIdentity(ctx context.Context) (*Identity, bool) {
	id, ok := ctx.Value(identityKey).(*Identity)
	return id, ok
}

func tailscaleIPFromAddrs(addrs []netip.Prefix) string {
	for _, prefix := range addrs {
		ip := prefix.Addr()
		// Prefer IPv4 Tailscale addresses (100.x.x.x)
		if ip.Is4() && strings.HasPrefix(ip.String(), "100.") {
			return ip.String()
		}
	}
	// Fallback to first address if no 100.x found
	if len(addrs) > 0 {
		return addrs[0].Addr().String()
	}
	return ""
}
