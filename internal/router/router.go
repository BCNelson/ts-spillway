package router

import (
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
)

// Route represents a parsed request route identifying the target.
type Route struct {
	User    string
	Machine string
	Port    int
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
		// Subdomain format: port.machine.user
		port, err := strconv.Atoi(labels[0])
		if err != nil {
			return nil, fmt.Errorf("invalid port label %q: %w", labels[0], err)
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
