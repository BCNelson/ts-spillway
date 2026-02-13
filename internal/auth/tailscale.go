package auth

import (
	"context"
	"fmt"
	"net/http"
	"net/netip"
	"regexp"
	"strings"

	"tailscale.com/client/local"
	"tailscale.com/client/tailscale/apitype"
)

// WhoIser abstracts the Tailscale WhoIs API so that Authenticator can be tested
// without a real Tailscale connection. *local.Client satisfies this interface.
type WhoIser interface {
	WhoIs(ctx context.Context, remoteAddr string) (*apitype.WhoIsResponse, error)
}

// Identity represents an authenticated Tailscale user and their machine.
type Identity struct {
	UserID      string
	LoginName   string // e.g., "alice" (short) or "alice-github" (full)
	DisplayName string
	MachineName string // e.g., "mymachine"
	TailscaleIP string // e.g., "100.64.0.1"
}

// UsernameFormat controls how login names are sanitized for DNS.
type UsernameFormat string

const (
	// UsernameFormatShort strips the domain: "alice@github" -> "alice"
	UsernameFormatShort UsernameFormat = "short"
	// UsernameFormatFull replaces special characters: "alice@github" -> "alice-github"
	UsernameFormatFull UsernameFormat = "full"
	// Any other value is treated as a primary domain: users matching that
	// domain are shortened, others get the full format.
	// e.g. "github" means "alice@github" -> "alice", "alice@google" -> "alice-google"
)

// Authenticator authenticates requests using the Tailscale WhoIs API.
type Authenticator struct {
	lc             WhoIser
	usernameFormat UsernameFormat
}

// NewAuthenticator creates an Authenticator backed by the given LocalClient.
// Uses short username format by default (backward compatible).
func NewAuthenticator(lc *local.Client) *Authenticator {
	return &Authenticator{lc: lc, usernameFormat: UsernameFormatShort}
}

// NewAuthenticatorFromWhoIser creates an Authenticator backed by any WhoIser implementation.
func NewAuthenticatorFromWhoIser(w WhoIser) *Authenticator {
	return &Authenticator{lc: w, usernameFormat: UsernameFormatShort}
}

// WithUsernameFormat sets the username sanitization format.
func (a *Authenticator) WithUsernameFormat(format UsernameFormat) *Authenticator {
	a.usernameFormat = format
	return a
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

	loginName := SanitizeLoginName(who.UserProfile.LoginName, a.usernameFormat)

	return &Identity{
		UserID:      fmt.Sprintf("%d", who.UserProfile.ID),
		LoginName:   loginName,
		DisplayName: who.UserProfile.DisplayName,
		MachineName: strings.ToLower(who.Node.ComputedName),
		TailscaleIP: ip,
	}, nil
}

// dnsUnsafe matches characters that are not valid in DNS labels.
var dnsUnsafe = regexp.MustCompile(`[^a-z0-9-]`)

// SanitizeLoginName converts a Tailscale login name to a DNS-safe string.
func SanitizeLoginName(loginName string, format UsernameFormat) string {
	loginName = strings.ToLower(loginName)

	switch format {
	case UsernameFormatFull:
		return sanitizeFull(loginName)
	case UsernameFormatShort:
		return sanitizeShort(loginName)
	default:
		// Treat format value as a primary domain — users from that domain
		// get shortened names, everyone else gets the full format.
		primaryDomain := strings.ToLower(string(format))
		if idx := strings.Index(loginName, "@"); idx > 0 {
			domain := loginName[idx+1:]
			if domain == primaryDomain {
				return loginName[:idx]
			}
			return sanitizeFull(loginName)
		}
		return loginName
	}
}

func sanitizeShort(loginName string) string {
	if idx := strings.Index(loginName, "@"); idx > 0 {
		return loginName[:idx]
	}
	return loginName
}

func sanitizeFull(loginName string) string {
	s := strings.ReplaceAll(loginName, "@", "-")
	s = strings.ReplaceAll(s, ".", "-")
	s = dnsUnsafe.ReplaceAllString(s, "")
	for strings.Contains(s, "--") {
		s = strings.ReplaceAll(s, "--", "-")
	}
	s = strings.Trim(s, "-")
	return s
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
