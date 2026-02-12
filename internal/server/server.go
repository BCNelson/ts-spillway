package server

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/bcnelson/ts-spillway/internal/auth"
	"github.com/bcnelson/ts-spillway/internal/certmanager"
	"github.com/bcnelson/ts-spillway/internal/config"
	"github.com/bcnelson/ts-spillway/internal/proxy"
	"github.com/bcnelson/ts-spillway/internal/registry"
	"github.com/bcnelson/ts-spillway/internal/router"

	"tailscale.com/ipn"
	"tailscale.com/tsnet"
)

// Identifier abstracts authentication so that handlers can be tested
// without a real Tailscale connection. *auth.Authenticator satisfies this interface.
type Identifier interface {
	Identify(r *http.Request) (*auth.Identity, error)
}

// TSOverrides allows overriding tsnet.Server fields for testing.
// When nil (production), the default tsnet behavior is used.
type TSOverrides struct {
	ControlURL string
	Store      ipn.StateStore
	Ephemeral  bool
}

// Server is the main spillway server.
type Server struct {
	cfg          *config.ServerConfig
	store        registry.Store
	certMgr      *certmanager.Manager
	tsServer     *tsnet.Server
	tsOverrides  *TSOverrides
	authn        Identifier
	proxyHandler *proxy.Proxy
	listeners    *ListenerManager
	logger       *slog.Logger
}

// New creates a new Server with all dependencies wired together.
func New(
	cfg *config.ServerConfig,
	store registry.Store,
	certMgr *certmanager.Manager,
	logger *slog.Logger,
) *Server {
	rtr := router.NewRouter(cfg.BaseDomain)
	proxyHandler := proxy.NewProxy(store, rtr, logger)

	return &Server{
		cfg:          cfg,
		store:        store,
		certMgr:      certMgr,
		proxyHandler: proxyHandler,
		logger:       logger,
	}
}

// WithTSOverrides sets tsnet overrides for testing.
func (s *Server) WithTSOverrides(overrides *TSOverrides) {
	s.tsOverrides = overrides
}

// Start initializes tsnet, starts listeners, and runs the server.
func (s *Server) Start(ctx context.Context) error {
	// Initialize tsnet
	s.tsServer = &tsnet.Server{
		Hostname: s.cfg.TSHostname,
		Dir:      s.cfg.TSStateDir,
	}
	if s.tsOverrides != nil {
		s.tsServer.ControlURL = s.tsOverrides.ControlURL
		if s.tsOverrides.Store != nil {
			s.tsServer.Store = s.tsOverrides.Store
		}
		s.tsServer.Ephemeral = s.tsOverrides.Ephemeral
	}

	status, err := s.tsServer.Up(ctx)
	if err != nil {
		return fmt.Errorf("tsnet startup failed: %w", err)
	}
	s.logger.Info("tsnet connected", "tailscale_ips", status.TailscaleIPs)

	// Configure proxy to dial backends through the Tailscale network
	s.proxyHandler.SetTransport(&http.Transport{
		DialContext: s.tsServer.Dial,
	})

	lc, err := s.tsServer.LocalClient()
	if err != nil {
		return fmt.Errorf("getting tsnet local client: %w", err)
	}
	s.authn = auth.NewAuthenticator(lc)

	// Start registration API listener.
	// Try ListenService first for Tailscale Services (multi-instance load balancing).
	// Fall back to plain Listen if the node is untagged (single-instance / dev mode).
	var apiLn net.Listener
	if s.cfg.ServiceName != "" {
		svcLn, svcErr := s.tsServer.ListenService(s.cfg.ServiceName, tsnet.ServiceModeHTTP{
			Port: uint16(s.cfg.RegistrationAPIPort),
		})
		if svcErr != nil {
			if errors.Is(svcErr, tsnet.ErrUntaggedServiceHost) {
				s.logger.Warn("node is untagged, falling back to plain listener (single-instance mode)",
					"service", s.cfg.ServiceName)
			} else {
				return fmt.Errorf("ListenService %q: %w", s.cfg.ServiceName, svcErr)
			}
		} else {
			apiLn = svcLn
			s.logger.Info("registration API advertised as Tailscale Service",
				"service", s.cfg.ServiceName, "fqdn", svcLn.FQDN, "port", s.cfg.RegistrationAPIPort)
		}
	}
	if apiLn == nil {
		ln, listenErr := s.tsServer.Listen("tcp", fmt.Sprintf(":%d", s.cfg.RegistrationAPIPort))
		if listenErr != nil {
			return fmt.Errorf("listening on tsnet port %d: %w", s.cfg.RegistrationAPIPort, listenErr)
		}
		apiLn = ln
		s.logger.Info("registration API listening", "port", s.cfg.RegistrationAPIPort)
	}

	apiMux := http.NewServeMux()
	apiMux.HandleFunc("/api/v1/register", s.handleRegister)
	apiMux.HandleFunc("/api/v1/heartbeat", s.handleHeartbeat)
	apiMux.HandleFunc("/api/v1/deregister", s.handleDeregister)
	apiMux.HandleFunc("/api/v1/status", s.handleStatus)

	go func() {
		if err := http.Serve(apiLn, apiMux); err != nil {
			s.logger.Error("registration API server error", "error", err)
		}
	}()

	// Set up public TLS listeners
	tlsConfig := &tls.Config{
		GetCertificate: s.certMgr.GetCertificate,
		MinVersion:     tls.VersionTLS12,
	}

	s.listeners = NewListenerManager(s.proxyHandler, tlsConfig, s.logger)

	if err := s.listeners.Listen443(); err != nil {
		s.logger.Warn("could not listen on 443", "error", err)
	}

	if err := s.listeners.ListenPortRange(s.cfg.PortRangeStart, s.cfg.PortRangeEnd); err != nil {
		return fmt.Errorf("starting port range listeners: %w", err)
	}

	// Start cert renewal loop
	s.certMgr.StartRenewalLoop(ctx)

	// Start daily cert TTL refresh loop
	s.startCertTTLRefreshLoop(ctx)

	s.logger.Info("spillway server started",
		"base_domain", s.cfg.BaseDomain,
		"port_range", fmt.Sprintf("%d-%d", s.cfg.PortRangeStart, s.cfg.PortRangeEnd),
	)

	return nil
}

// startCertTTLRefreshLoop runs a daily goroutine that refreshes TTLs
// for certs belonging to currently registered machines.
func (s *Server) startCertTTLRefreshLoop(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(24 * time.Hour)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				s.refreshCertTTLs(ctx)
			}
		}
	}()
}

// refreshCertTTLs resets the 14-day TTL on certs for all active machines.
func (s *Server) refreshCertTTLs(ctx context.Context) {
	machines, err := s.store.ListActiveMachines(ctx)
	if err != nil {
		s.logger.Error("failed to list active machines for cert TTL refresh", "error", err)
		return
	}
	for _, m := range machines {
		domain := certmanager.MachineWildcard(m.User, m.Machine, s.cfg.BaseDomain)
		s.certMgr.RefreshCertTTL(ctx, domain)
	}
}

// Close shuts down the server.
func (s *Server) Close() {
	if s.listeners != nil {
		s.listeners.Close()
	}
	if s.tsServer != nil {
		_ = s.tsServer.Close()
	}
}

// API request/response types

type registerRequest struct {
	Ports []int `json:"ports"`
}

type registerResponse struct {
	URLs []string `json:"urls"`
}

type heartbeatRequest struct {
	Ports []int `json:"ports"`
}

type deregisterRequest struct {
	Ports []int `json:"ports"`
}

type statusResponse struct {
	Registrations []registrationInfo `json:"registrations"`
}

type registrationInfo struct {
	Port      int       `json:"port"`
	URLs      []string  `json:"urls"`
	ExpiresAt time.Time `json:"expires_at"`
}

// API Handlers

func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	id, err := s.authn.Identify(r)
	if err != nil {
		s.logger.Error("auth failed", "error", err)
		http.Error(w, "Authentication failed", http.StatusUnauthorized)
		return
	}

	var req registerRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Save user and machine info
	if err := s.store.SaveUser(r.Context(), id.UserID, id.LoginName, id.DisplayName); err != nil {
		s.logger.Error("failed to save user", "error", err)
	}
	if err := s.store.SaveMachine(r.Context(), id.LoginName, id.MachineName, id.TailscaleIP); err != nil {
		s.logger.Error("failed to save machine", "error", err)
	}

	// Ensure certs exist for this user/machine
	wildcards := certmanager.WildcardsForRegistration(id.LoginName, id.MachineName, s.cfg.BaseDomain)
	for _, wc := range wildcards {
		if err := s.certMgr.EnsureCert(r.Context(), wc); err != nil {
			s.logger.Error("failed to ensure cert", "domain", wc, "error", err)
			// Non-fatal: continue with registration, certs can be retried
		}
	}

	var urls []string
	for _, port := range req.Ports {
		if err := s.store.Register(r.Context(), id.LoginName, id.MachineName, port, id.TailscaleIP); err != nil {
			s.logger.Error("registration failed", "port", port, "error", err)
			http.Error(w, "Registration failed", http.StatusInternalServerError)
			return
		}
		urls = append(urls,
			fmt.Sprintf("https://%d.%s.%s.%s", port, id.MachineName, id.LoginName, s.cfg.BaseDomain),
			fmt.Sprintf("https://%s.%s.%s:%d", id.MachineName, id.LoginName, s.cfg.BaseDomain, port),
		)
	}

	s.logger.Info("registered ports",
		"user", id.LoginName,
		"machine", id.MachineName,
		"ports", req.Ports,
	)

	writeJSON(w, http.StatusOK, registerResponse{URLs: urls})
}

func (s *Server) handleHeartbeat(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	id, err := s.authn.Identify(r)
	if err != nil {
		http.Error(w, "Authentication failed", http.StatusUnauthorized)
		return
	}

	var req heartbeatRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if err := s.store.RefreshHeartbeat(r.Context(), id.LoginName, id.MachineName, req.Ports); err != nil {
		s.logger.Error("heartbeat failed", "error", err)
		http.Error(w, "Heartbeat failed", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleDeregister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	id, err := s.authn.Identify(r)
	if err != nil {
		http.Error(w, "Authentication failed", http.StatusUnauthorized)
		return
	}

	var req deregisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	for _, port := range req.Ports {
		if err := s.store.Deregister(r.Context(), id.LoginName, id.MachineName, port); err != nil {
			s.logger.Error("deregistration failed", "port", port, "error", err)
		}
	}

	s.logger.Info("deregistered ports",
		"user", id.LoginName,
		"machine", id.MachineName,
		"ports", req.Ports,
	)

	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	id, err := s.authn.Identify(r)
	if err != nil {
		http.Error(w, "Authentication failed", http.StatusUnauthorized)
		return
	}

	regs, err := s.store.ListByMachine(r.Context(), id.LoginName, id.MachineName)
	if err != nil {
		s.logger.Error("status lookup failed", "error", err)
		http.Error(w, "Status lookup failed", http.StatusInternalServerError)
		return
	}

	var infos []registrationInfo
	for _, reg := range regs {
		infos = append(infos, registrationInfo{
			Port:      reg.Port,
			ExpiresAt: reg.ExpiresAt,
			URLs: []string{
				fmt.Sprintf("https://%d.%s.%s.%s", reg.Port, reg.Machine, reg.User, s.cfg.BaseDomain),
				fmt.Sprintf("https://%s.%s.%s:%d", reg.Machine, reg.User, s.cfg.BaseDomain, reg.Port),
			},
		})
	}

	writeJSON(w, http.StatusOK, statusResponse{Registrations: infos})
}

// ProxyHandler returns the proxy HTTP handler. Useful for testing proxy forwarding.
func (s *Server) ProxyHandler() http.Handler {
	return s.proxyHandler
}

// TSListener returns a net.Listener from the tsnet server. Useful for testing.
func (s *Server) TSListener(network, addr string) (net.Listener, error) {
	return s.tsServer.Listen(network, addr)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
