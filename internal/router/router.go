package router

import (
	"fmt"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
)

// Route represents a parsed request route identifying the target.
type Route struct {
	User    string
	Machine string
	Port    int
	Alias   string // Non-empty when the request used an alias instead of a port number
}

// Router parses incoming requests to determine the target user, machine, and port.
type Router struct {
	baseDomain string
	// Number of labels in the base domain (e.g., "spillway.redo.run" = 3)
	baseLabels int
}

// NewRouter creates a Router for the given base domain.
func NewRouter(baseDomain string) *Router {
	return &Router{
		baseDomain: strings.ToLower(baseDomain),
		baseLabels: len(strings.Split(baseDomain, ".")),
	}
}

// ParseRequest extracts routing information from the HTTP request.
// Supports two patterns:
//   - Subdomain: 8000.machine.user.spillway.redo.run (port in first label)
//   - Alias subdomain: myapp.machine.user.spillway.redo.run (alias in first label)
//   - Port-based: machine.user.spillway.redo.run:8000 (port from Host header port or listener port)
func (r *Router) ParseRequest(req *http.Request) (*Route, error) {
	return r.ParseHost(req.Host)
}

// ParseHost extracts routing information from a Host header value.
func (r *Router) ParseHost(host string) (*Route, error) {
	// Split host and port from Host header
	hostname, portStr, err := net.SplitHostPort(host)
	if err != nil {
		// No port in Host header
		hostname = host
		portStr = ""
	}
	hostname = strings.ToLower(hostname)

	// Strip the base domain suffix to get the prefix labels
	if !strings.HasSuffix(hostname, "."+r.baseDomain) {
		return nil, fmt.Errorf("host %q does not match base domain %q", hostname, r.baseDomain)
	}

	prefix := strings.TrimSuffix(hostname, "."+r.baseDomain)
	labels := strings.Split(prefix, ".")

	switch len(labels) {
	case 3:
		// Subdomain format: port.machine.user OR alias.machine.user
		port, err := strconv.Atoi(labels[0])
		if err != nil {
			// Not a number — treat as alias if it's a valid alias label
			alias := labels[0]
			if err := ValidateAlias(alias); err != nil {
				return nil, fmt.Errorf("invalid alias label %q: %w", alias, err)
			}
			return &Route{
				User:    labels[2],
				Machine: labels[1],
				Alias:   alias,
			}, nil
		}
		return &Route{
			User:    labels[2],
			Machine: labels[1],
			Port:    port,
		}, nil

	case 2:
		// Port-based format: machine.user (port from Host header port)
		if portStr == "" {
			return nil, fmt.Errorf("port-based format requires port in Host header for %q", host)
		}
		port, err := strconv.Atoi(portStr)
		if err != nil {
			return nil, fmt.Errorf("invalid port %q: %w", portStr, err)
		}
		return &Route{
			User:    labels[1],
			Machine: labels[0],
			Port:    port,
		}, nil

	default:
		return nil, fmt.Errorf("unexpected number of labels (%d) in host %q", len(labels), hostname)
	}
}

// aliasRegexp matches a valid DNS label that does NOT start with a digit:
// lowercase alphanumeric + hyphens, 1-63 chars, must not start or end with hyphen.
var aliasRegexp = regexp.MustCompile(`^[a-z][a-z0-9-]{0,62}$`)

// ValidateAlias checks that an alias is a valid DNS label that does not start
// with a digit (to disambiguate from port numbers). It must be lowercase
// alphanumeric + hyphens, 1-63 chars, and must not end with a hyphen.
func ValidateAlias(alias string) error {
	if alias == "" {
		return fmt.Errorf("alias must not be empty")
	}
	if len(alias) > 63 {
		return fmt.Errorf("alias must be at most 63 characters")
	}
	if !aliasRegexp.MatchString(alias) {
		return fmt.Errorf("alias must start with a letter and contain only lowercase alphanumeric characters and hyphens")
	}
	if strings.HasSuffix(alias, "-") {
		return fmt.Errorf("alias must not end with a hyphen")
	}
	return nil
}
