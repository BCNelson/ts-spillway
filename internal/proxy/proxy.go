package proxy

import (
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"

	"github.com/bcnelson/ts-spillway/internal/registry"
	"github.com/bcnelson/ts-spillway/internal/router"
)

// Proxy reverse-proxies public requests to the appropriate Tailscale client.
type Proxy struct {
	store     registry.Store
	router    *router.Router
	logger    *slog.Logger
	transport http.RoundTripper
}

// NewProxy creates a new Proxy.
func NewProxy(store registry.Store, router *router.Router, logger *slog.Logger) *Proxy {
	return &Proxy{
		store:  store,
		router: router,
		logger: logger,
	}
}

// SetTransport sets the HTTP transport used for proxying requests to backends.
// This should be configured with a DialContext that routes through the Tailscale
// network (e.g., tsnet.Server.Dial) so the proxy can reach Tailscale IPs.
func (p *Proxy) SetTransport(rt http.RoundTripper) {
	p.transport = rt
}

// ServeHTTP handles incoming public requests by routing and proxying them.
func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	route, err := p.router.ParseRequest(r)
	if err != nil {
		p.logger.Warn("failed to parse route", "host", r.Host, "error", err)
		http.Error(w, "Invalid host", http.StatusBadRequest)
		return
	}

	tailscaleIP, err := p.store.Lookup(r.Context(), route.User, route.Machine, route.Port)
	if err != nil {
		p.logger.Error("registry lookup failed", "user", route.User, "machine", route.Machine, "port", route.Port, "error", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	if tailscaleIP == "" {
		http.Error(w, "Not found: no active registration", http.StatusNotFound)
		return
	}

	target := &url.URL{
		Scheme: "http",
		Host:   fmt.Sprintf("%s:%d", tailscaleIP, route.Port),
	}

	proxy := &httputil.ReverseProxy{
		Transport: p.transport,
		Director: func(req *http.Request) {
			req.URL.Scheme = target.Scheme
			req.URL.Host = target.Host
			req.Header.Set("X-Forwarded-For", r.RemoteAddr)
			req.Header.Set("X-Forwarded-Host", r.Host)
			req.Header.Set("X-Forwarded-Proto", "https")
		},
		ErrorHandler: func(w http.ResponseWriter, req *http.Request, err error) {
			p.logger.Error("proxy error",
				"user", route.User,
				"machine", route.Machine,
				"port", route.Port,
				"target", target.String(),
				"error", err,
			)
			http.Error(w, "Bad gateway", http.StatusBadGateway)
		},
	}

	p.logger.Info("proxying request",
		"user", route.User,
		"machine", route.Machine,
		"port", route.Port,
		"target", target.String(),
		"path", r.URL.Path,
	)

	proxy.ServeHTTP(w, r)
}
