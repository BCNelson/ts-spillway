package certmanager

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"
)

// CertStore persists TLS certificates.
type CertStore interface {
	GetCert(ctx context.Context, domain string) (*StoredCert, error)
	SaveCert(ctx context.Context, domain string, certPEM, keyPEM []byte, notAfter time.Time) error
	ListExpiring(ctx context.Context, before time.Time) ([]string, error)
	RefreshCertTTL(ctx context.Context, domain string, ttl time.Duration) error
}

// StoredCert is a certificate retrieved from the store.
type StoredCert struct {
	CertPEM  []byte
	KeyPEM   []byte
	NotAfter time.Time
}

// CertIssuer issues new TLS certificates via ACME.
type CertIssuer interface {
	Issue(ctx context.Context, domain string) (certPEM, keyPEM []byte, notAfter time.Time, err error)
}

// Manager orchestrates TLS certificate lifecycle.
type Manager struct {
	store  CertStore
	issuer CertIssuer
	logger *slog.Logger

	// In-memory cache of parsed certificates keyed by wildcard domain.
	mu    sync.RWMutex
	cache map[string]*tls.Certificate
}

// NewManager creates a new certificate Manager.
func NewManager(store CertStore, issuer CertIssuer, logger *slog.Logger) *Manager {
	return &Manager{
		store:  store,
		issuer: issuer,
		logger: logger,
		cache:  make(map[string]*tls.Certificate),
	}
}

// GetCertificate implements tls.Config.GetCertificate.
// It selects the appropriate wildcard certificate based on SNI.
func (m *Manager) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	serverName := strings.ToLower(hello.ServerName)

	// Try each wildcard level: for "8000.machine.user.spillway.redo.run",
	// try "*.machine.user.spillway.redo.run", then "*.user.spillway.redo.run", etc.
	labels := strings.Split(serverName, ".")
	for i := 1; i < len(labels); i++ {
		wildcard := "*." + strings.Join(labels[i:], ".")
		cert, err := m.getCertForDomain(wildcard)
		if err != nil {
			return nil, err
		}
		if cert != nil {
			return cert, nil
		}
	}

	return nil, fmt.Errorf("no certificate found for %s", serverName)
}

func (m *Manager) getCertForDomain(domain string) (*tls.Certificate, error) {
	// Check in-memory cache
	m.mu.RLock()
	cert, ok := m.cache[domain]
	m.mu.RUnlock()
	if ok {
		return cert, nil
	}

	// Check store
	ctx := context.Background()
	stored, err := m.store.GetCert(ctx, domain)
	if err != nil {
		return nil, err
	}
	if stored != nil {
		tlsCert, err := tls.X509KeyPair(stored.CertPEM, stored.KeyPEM)
		if err != nil {
			return nil, fmt.Errorf("parsing stored cert for %s: %w", domain, err)
		}
		m.mu.Lock()
		m.cache[domain] = &tlsCert
		m.mu.Unlock()
		return &tlsCert, nil
	}

	return nil, nil
}

// EnsureCert obtains a certificate for the given domain, issuing one if needed.
func (m *Manager) EnsureCert(ctx context.Context, domain string) error {
	stored, err := m.store.GetCert(ctx, domain)
	if err != nil {
		return err
	}

	// If cert exists and isn't expiring within 30 days, we're good
	if stored != nil && time.Until(stored.NotAfter) > 30*24*time.Hour {
		return nil
	}

	m.logger.Info("issuing certificate", "domain", domain)
	certPEM, keyPEM, notAfter, err := m.issuer.Issue(ctx, domain)
	if err != nil {
		return fmt.Errorf("issuing cert for %s: %w", domain, err)
	}

	if err := m.store.SaveCert(ctx, domain, certPEM, keyPEM, notAfter); err != nil {
		return fmt.Errorf("saving cert for %s: %w", domain, err)
	}

	// Update in-memory cache
	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return fmt.Errorf("parsing new cert for %s: %w", domain, err)
	}
	m.mu.Lock()
	m.cache[domain] = &tlsCert
	m.mu.Unlock()

	m.logger.Info("certificate issued", "domain", domain, "expires", notAfter)
	return nil
}

// StartRenewalLoop runs a background goroutine that renews certificates
// expiring within 30 days. It checks once per day.
func (m *Manager) StartRenewalLoop(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(24 * time.Hour)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				m.renewExpiring(ctx)
			}
		}
	}()
}

func (m *Manager) renewExpiring(ctx context.Context) {
	threshold := time.Now().Add(30 * 24 * time.Hour)
	domains, err := m.store.ListExpiring(ctx, threshold)
	if err != nil {
		m.logger.Error("failed to list expiring certs", "error", err)
		return
	}

	for _, domain := range domains {
		if err := m.EnsureCert(ctx, domain); err != nil {
			m.logger.Error("failed to renew cert", "domain", domain, "error", err)
		}
	}
}

// certTTL is the TTL applied to cert keys in Redis.
const certTTL = 14 * 24 * time.Hour

// RefreshCertTTL resets the TTL for a cert key without rewriting the value.
func (m *Manager) RefreshCertTTL(ctx context.Context, domain string) {
	if err := m.store.RefreshCertTTL(ctx, domain, certTTL); err != nil {
		m.logger.Error("failed to refresh cert TTL", "domain", domain, "error", err)
	}
}

// MachineWildcard returns the machine-specific wildcard domain.
func MachineWildcard(user, machine, baseDomain string) string {
	return fmt.Sprintf("*.%s.%s.%s", machine, user, baseDomain)
}

// WildcardsForRegistration returns the wildcard domains needed for a user/machine registration.
func WildcardsForRegistration(user, machine, baseDomain string) []string {
	return []string{
		fmt.Sprintf("*.%s.%s.%s", machine, user, baseDomain), // subdomain-style
		fmt.Sprintf("*.%s.%s", user, baseDomain),             // port-based style
	}
}
