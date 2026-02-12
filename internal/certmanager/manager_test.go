package certmanager

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"testing"
	"time"

	"github.com/bcnelson/ts-spillway/internal/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- local mocks (no external project imports needed) ---

type mockCertStore struct {
	getCertFn        func(ctx context.Context, domain string) (*StoredCert, error)
	saveCertFn       func(ctx context.Context, domain string, certPEM, keyPEM []byte, notAfter time.Time) error
	listExpiringFn   func(ctx context.Context, before time.Time) ([]string, error)
	refreshCertTTLFn func(ctx context.Context, domain string, ttl time.Duration) error
}

func (m *mockCertStore) GetCert(ctx context.Context, domain string) (*StoredCert, error) {
	if m.getCertFn != nil {
		return m.getCertFn(ctx, domain)
	}
	return nil, nil
}
func (m *mockCertStore) SaveCert(ctx context.Context, domain string, certPEM, keyPEM []byte, notAfter time.Time) error {
	if m.saveCertFn != nil {
		return m.saveCertFn(ctx, domain, certPEM, keyPEM, notAfter)
	}
	return nil
}
func (m *mockCertStore) ListExpiring(ctx context.Context, before time.Time) ([]string, error) {
	if m.listExpiringFn != nil {
		return m.listExpiringFn(ctx, before)
	}
	return nil, nil
}
func (m *mockCertStore) RefreshCertTTL(ctx context.Context, domain string, ttl time.Duration) error {
	if m.refreshCertTTLFn != nil {
		return m.refreshCertTTLFn(ctx, domain, ttl)
	}
	return nil
}

type mockCertIssuer struct {
	issueFn func(ctx context.Context, domain string) ([]byte, []byte, time.Time, error)
}

func (m *mockCertIssuer) Issue(ctx context.Context, domain string) ([]byte, []byte, time.Time, error) {
	if m.issueFn != nil {
		return m.issueFn(ctx, domain)
	}
	return nil, nil, time.Time{}, nil
}

// --- pure-logic tests ---

func TestWildcardsForRegistration(t *testing.T) {
	wildcards := WildcardsForRegistration("alice", "mymachine", "spillway.redo.run")
	assert.Equal(t, []string{
		"*.mymachine.alice.spillway.redo.run",
		"*.alice.spillway.redo.run",
	}, wildcards)
}

func TestWildcardsForRegistration_DifferentDomain(t *testing.T) {
	wildcards := WildcardsForRegistration("bob", "laptop", "example.com")
	assert.Equal(t, []string{
		"*.laptop.bob.example.com",
		"*.bob.example.com",
	}, wildcards)
}

// --- mocked unit tests ---

func TestGetCertificate_FromStore(t *testing.T) {
	certPEM, keyPEM, err := testutil.GenerateSelfSignedCert("*.test.example.com", time.Now().Add(90*24*time.Hour))
	require.NoError(t, err)

	store := &mockCertStore{
		getCertFn: func(_ context.Context, domain string) (*StoredCert, error) {
			if domain == "*.test.example.com" {
				return &StoredCert{CertPEM: certPEM, KeyPEM: keyPEM, NotAfter: time.Now().Add(90 * 24 * time.Hour)}, nil
			}
			return nil, nil
		},
	}

	mgr := NewManager(store, &mockCertIssuer{}, slog.Default())

	hello := &tls.ClientHelloInfo{ServerName: "8000.test.example.com"}
	cert, err := mgr.GetCertificate(hello)
	require.NoError(t, err)
	require.NotNil(t, cert)
}

func TestGetCertificate_CacheHit(t *testing.T) {
	certPEM, keyPEM, err := testutil.GenerateSelfSignedCert("*.test.example.com", time.Now().Add(90*24*time.Hour))
	require.NoError(t, err)

	calls := 0
	store := &mockCertStore{
		getCertFn: func(_ context.Context, domain string) (*StoredCert, error) {
			calls++
			if domain == "*.test.example.com" {
				return &StoredCert{CertPEM: certPEM, KeyPEM: keyPEM, NotAfter: time.Now().Add(90 * 24 * time.Hour)}, nil
			}
			return nil, nil
		},
	}

	mgr := NewManager(store, &mockCertIssuer{}, slog.Default())

	hello := &tls.ClientHelloInfo{ServerName: "8000.test.example.com"}
	_, _ = mgr.GetCertificate(hello) // populates cache
	_, err = mgr.GetCertificate(hello)
	require.NoError(t, err)

	// Store should only have been queried once for *.test.example.com;
	// the second call hits the in-memory cache.
	assert.Equal(t, 1, calls)
}

func TestGetCertificate_NotFound(t *testing.T) {
	store := &mockCertStore{}
	mgr := NewManager(store, &mockCertIssuer{}, slog.Default())

	hello := &tls.ClientHelloInfo{ServerName: "8000.test.example.com"}
	_, err := mgr.GetCertificate(hello)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no certificate found")
}

func TestGetCertificate_WildcardLevels(t *testing.T) {
	// Cert is for *.user.spillway.redo.run (second wildcard level).
	certPEM, keyPEM, err := testutil.GenerateSelfSignedCert("*.user.spillway.redo.run", time.Now().Add(90*24*time.Hour))
	require.NoError(t, err)

	store := &mockCertStore{
		getCertFn: func(_ context.Context, domain string) (*StoredCert, error) {
			if domain == "*.user.spillway.redo.run" {
				return &StoredCert{CertPEM: certPEM, KeyPEM: keyPEM, NotAfter: time.Now().Add(90 * 24 * time.Hour)}, nil
			}
			return nil, nil
		},
	}

	mgr := NewManager(store, &mockCertIssuer{}, slog.Default())

	// SNI = machine.user.spillway.redo.run — first wildcard tried is
	// *.user.spillway.redo.run (after *.machine.user... misses).
	hello := &tls.ClientHelloInfo{ServerName: "machine.user.spillway.redo.run"}
	cert, err := mgr.GetCertificate(hello)
	require.NoError(t, err)
	require.NotNil(t, cert)
}

func TestEnsureCert_FreshCert(t *testing.T) {
	store := &mockCertStore{
		getCertFn: func(_ context.Context, _ string) (*StoredCert, error) {
			return &StoredCert{NotAfter: time.Now().Add(60 * 24 * time.Hour)}, nil
		},
	}
	issuer := &mockCertIssuer{
		issueFn: func(_ context.Context, _ string) ([]byte, []byte, time.Time, error) {
			t.Fatal("issuer should not be called for a fresh cert")
			return nil, nil, time.Time{}, nil
		},
	}

	mgr := NewManager(store, issuer, slog.Default())
	require.NoError(t, mgr.EnsureCert(context.Background(), "*.test.example.com"))
}

func TestEnsureCert_ExpiringCert(t *testing.T) {
	certPEM, keyPEM, err := testutil.GenerateSelfSignedCert("*.test.example.com", time.Now().Add(90*24*time.Hour))
	require.NoError(t, err)

	var savedDomain string
	store := &mockCertStore{
		getCertFn: func(_ context.Context, _ string) (*StoredCert, error) {
			return &StoredCert{NotAfter: time.Now().Add(10 * 24 * time.Hour)}, nil // within 30-day window
		},
		saveCertFn: func(_ context.Context, domain string, _ []byte, _ []byte, _ time.Time) error {
			savedDomain = domain
			return nil
		},
	}
	issuer := &mockCertIssuer{
		issueFn: func(_ context.Context, _ string) ([]byte, []byte, time.Time, error) {
			return certPEM, keyPEM, time.Now().Add(90 * 24 * time.Hour), nil
		},
	}

	mgr := NewManager(store, issuer, slog.Default())
	require.NoError(t, mgr.EnsureCert(context.Background(), "*.test.example.com"))
	assert.Equal(t, "*.test.example.com", savedDomain)
}

func TestEnsureCert_NoCert(t *testing.T) {
	certPEM, keyPEM, err := testutil.GenerateSelfSignedCert("*.test.example.com", time.Now().Add(90*24*time.Hour))
	require.NoError(t, err)

	saved := false
	store := &mockCertStore{
		saveCertFn: func(_ context.Context, _ string, _ []byte, _ []byte, _ time.Time) error {
			saved = true
			return nil
		},
	}
	issuer := &mockCertIssuer{
		issueFn: func(_ context.Context, _ string) ([]byte, []byte, time.Time, error) {
			return certPEM, keyPEM, time.Now().Add(90 * 24 * time.Hour), nil
		},
	}

	mgr := NewManager(store, issuer, slog.Default())
	require.NoError(t, mgr.EnsureCert(context.Background(), "*.new.example.com"))
	assert.True(t, saved)
}

func TestEnsureCert_IssueError(t *testing.T) {
	store := &mockCertStore{} // GetCert returns nil → needs issuance
	issuer := &mockCertIssuer{
		issueFn: func(_ context.Context, _ string) ([]byte, []byte, time.Time, error) {
			return nil, nil, time.Time{}, fmt.Errorf("ACME rate limit")
		},
	}

	mgr := NewManager(store, issuer, slog.Default())
	err := mgr.EnsureCert(context.Background(), "*.test.example.com")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "issuing cert")
}

func TestMachineWildcard(t *testing.T) {
	assert.Equal(t, "*.mymachine.alice.spillway.redo.run", MachineWildcard("alice", "mymachine", "spillway.redo.run"))
	assert.Equal(t, "*.laptop.bob.example.com", MachineWildcard("bob", "laptop", "example.com"))
}

func TestRefreshCertTTL(t *testing.T) {
	var refreshedDomain string
	var refreshedTTL time.Duration
	store := &mockCertStore{
		refreshCertTTLFn: func(_ context.Context, domain string, ttl time.Duration) error {
			refreshedDomain = domain
			refreshedTTL = ttl
			return nil
		},
	}

	mgr := NewManager(store, &mockCertIssuer{}, slog.Default())
	mgr.RefreshCertTTL(context.Background(), "*.test.example.com")

	assert.Equal(t, "*.test.example.com", refreshedDomain)
	assert.Equal(t, 14*24*time.Hour, refreshedTTL)
}

func TestRenewExpiring(t *testing.T) {
	certPEM, keyPEM, err := testutil.GenerateSelfSignedCert("*.test.example.com", time.Now().Add(90*24*time.Hour))
	require.NoError(t, err)

	var renewed []string
	store := &mockCertStore{
		listExpiringFn: func(_ context.Context, _ time.Time) ([]string, error) {
			return []string{"*.test.example.com"}, nil
		},
		getCertFn: func(_ context.Context, _ string) (*StoredCert, error) {
			return &StoredCert{NotAfter: time.Now().Add(5 * 24 * time.Hour)}, nil
		},
		saveCertFn: func(_ context.Context, domain string, _ []byte, _ []byte, _ time.Time) error {
			renewed = append(renewed, domain)
			return nil
		},
	}
	issuer := &mockCertIssuer{
		issueFn: func(_ context.Context, _ string) ([]byte, []byte, time.Time, error) {
			return certPEM, keyPEM, time.Now().Add(90 * 24 * time.Hour), nil
		},
	}

	mgr := NewManager(store, issuer, slog.Default())
	mgr.renewExpiring(context.Background())

	assert.Equal(t, []string{"*.test.example.com"}, renewed)
}

// --- mock locker ---

type mockLocker struct {
	acquireFn func(ctx context.Context, key string) (func(ctx context.Context), error)
}

func (m *mockLocker) Acquire(ctx context.Context, key string) (func(ctx context.Context), error) {
	if m.acquireFn != nil {
		return m.acquireFn(ctx, key)
	}
	return func(ctx context.Context) {}, nil
}

// --- EnsureCert with Locker tests ---

func TestEnsureCert_WithLocker_AcquiredAndIssues(t *testing.T) {
	certPEM, keyPEM, err := testutil.GenerateSelfSignedCert("*.test.example.com", time.Now().Add(90*24*time.Hour))
	require.NoError(t, err)

	issued := false
	released := false
	store := &mockCertStore{
		saveCertFn: func(_ context.Context, _ string, _ []byte, _ []byte, _ time.Time) error {
			return nil
		},
	}
	issuer := &mockCertIssuer{
		issueFn: func(_ context.Context, _ string) ([]byte, []byte, time.Time, error) {
			issued = true
			return certPEM, keyPEM, time.Now().Add(90 * 24 * time.Hour), nil
		},
	}
	locker := &mockLocker{
		acquireFn: func(_ context.Context, _ string) (func(ctx context.Context), error) {
			return func(_ context.Context) { released = true }, nil
		},
	}

	mgr := NewManager(store, issuer, slog.Default())
	mgr.WithLocker(locker)

	require.NoError(t, mgr.EnsureCert(context.Background(), "*.test.example.com"))
	assert.True(t, issued, "issuer should have been called")
	assert.True(t, released, "lock should have been released")
}

func TestEnsureCert_WithLocker_NotAcquired_Skips(t *testing.T) {
	issuer := &mockCertIssuer{
		issueFn: func(_ context.Context, _ string) ([]byte, []byte, time.Time, error) {
			t.Fatal("issuer should not be called when lock is not acquired")
			return nil, nil, time.Time{}, nil
		},
	}
	locker := &mockLocker{
		acquireFn: func(_ context.Context, _ string) (func(ctx context.Context), error) {
			return nil, ErrLockNotAcquired
		},
	}

	mgr := NewManager(&mockCertStore{}, issuer, slog.Default())
	mgr.WithLocker(locker)

	// Should not error — just skips issuance
	require.NoError(t, mgr.EnsureCert(context.Background(), "*.test.example.com"))
}

func TestEnsureCert_WithLocker_DoubleCheck_SkipsIfFresh(t *testing.T) {
	getCertCalls := 0
	store := &mockCertStore{
		getCertFn: func(_ context.Context, _ string) (*StoredCert, error) {
			getCertCalls++
			if getCertCalls == 1 {
				// First check: no cert
				return nil, nil
			}
			// Second check (after lock): cert now exists (another instance issued it)
			return &StoredCert{NotAfter: time.Now().Add(60 * 24 * time.Hour)}, nil
		},
	}
	issuer := &mockCertIssuer{
		issueFn: func(_ context.Context, _ string) ([]byte, []byte, time.Time, error) {
			t.Fatal("issuer should not be called after double-check finds fresh cert")
			return nil, nil, time.Time{}, nil
		},
	}
	locker := &mockLocker{
		acquireFn: func(_ context.Context, _ string) (func(ctx context.Context), error) {
			return func(_ context.Context) {}, nil
		},
	}

	mgr := NewManager(store, issuer, slog.Default())
	mgr.WithLocker(locker)

	require.NoError(t, mgr.EnsureCert(context.Background(), "*.test.example.com"))
	assert.Equal(t, 2, getCertCalls, "store should have been checked twice (before and after lock)")
}

func TestEnsureCert_NilLocker_StillWorks(t *testing.T) {
	certPEM, keyPEM, err := testutil.GenerateSelfSignedCert("*.test.example.com", time.Now().Add(90*24*time.Hour))
	require.NoError(t, err)

	issued := false
	store := &mockCertStore{
		saveCertFn: func(_ context.Context, _ string, _ []byte, _ []byte, _ time.Time) error {
			return nil
		},
	}
	issuer := &mockCertIssuer{
		issueFn: func(_ context.Context, _ string) ([]byte, []byte, time.Time, error) {
			issued = true
			return certPEM, keyPEM, time.Now().Add(90 * 24 * time.Hour), nil
		},
	}

	mgr := NewManager(store, issuer, slog.Default())
	// No WithLocker call — locker is nil

	require.NoError(t, mgr.EnsureCert(context.Background(), "*.test.example.com"))
	assert.True(t, issued, "issuer should still be called with nil locker")
}
