package server

import (
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"sync"
)

// ListenerManager manages multiple TLS listeners for port-based access.
type ListenerManager struct {
	handler   http.Handler
	tlsConfig *tls.Config
	logger    *slog.Logger
	listeners []net.Listener
	servers   []*http.Server
	mu        sync.Mutex
}

// NewListenerManager creates a new ListenerManager.
func NewListenerManager(handler http.Handler, tlsConfig *tls.Config, logger *slog.Logger) *ListenerManager {
	return &ListenerManager{
		handler:   handler,
		tlsConfig: tlsConfig,
		logger:    logger,
	}
}

// ListenPortRange starts TLS listeners on each port in the given range.
func (lm *ListenerManager) ListenPortRange(start, end int) error {
	lm.mu.Lock()
	defer lm.mu.Unlock()

	for port := start; port <= end; port++ {
		addr := fmt.Sprintf(":%d", port)
		ln, err := tls.Listen("tcp", addr, lm.tlsConfig)
		if err != nil {
			lm.logger.Warn("failed to listen on port", "port", port, "error", err)
			continue
		}

		srv := &http.Server{
			Handler: lm.handler,
		}

		lm.listeners = append(lm.listeners, ln)
		lm.servers = append(lm.servers, srv)

		go func(p int, s *http.Server, l net.Listener) {
			lm.logger.Info("listening on port", "port", p)
			if err := s.Serve(l); err != nil && err != http.ErrServerClosed {
				lm.logger.Error("listener error", "port", p, "error", err)
			}
		}(port, srv, ln)
	}

	return nil
}

// Listen443 starts the main HTTPS listener on port 443.
func (lm *ListenerManager) Listen443() error {
	lm.mu.Lock()
	defer lm.mu.Unlock()

	ln, err := tls.Listen("tcp", ":443", lm.tlsConfig)
	if err != nil {
		return fmt.Errorf("listening on :443: %w", err)
	}

	srv := &http.Server{
		Handler: lm.handler,
	}

	lm.listeners = append(lm.listeners, ln)
	lm.servers = append(lm.servers, srv)

	go func() {
		lm.logger.Info("listening on port 443")
		if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
			lm.logger.Error("port 443 listener error", "error", err)
		}
	}()

	return nil
}

// Close gracefully shuts down all listeners.
func (lm *ListenerManager) Close() {
	lm.mu.Lock()
	defer lm.mu.Unlock()

	for _, srv := range lm.servers {
		_ = srv.Close()
	}
	lm.servers = nil
	lm.listeners = nil
}
