package certmanager

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/bcnelson/ts-spillway/internal/testutil"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestCertStore(t *testing.T) (*RedisCertStore, *miniredis.Miniredis) {
	t.Helper()
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	return NewRedisCertStore(client), mr
}

func TestRedisCertStore_SaveAndGet(t *testing.T) {
	store, _ := newTestCertStore(t)
	ctx := context.Background()

	certPEM, keyPEM, err := testutil.GenerateSelfSignedCert("*.test.example.com", time.Now().Add(90*24*time.Hour))
	require.NoError(t, err)

	notAfter := time.Now().Add(90 * 24 * time.Hour).Truncate(time.Second)
	require.NoError(t, store.SaveCert(ctx, "*.test.example.com", certPEM, keyPEM, notAfter))

	got, err := store.GetCert(ctx, "*.test.example.com")
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, certPEM, got.CertPEM)
	assert.Equal(t, keyPEM, got.KeyPEM)
	assert.Equal(t, notAfter.UTC(), got.NotAfter.UTC())
}

func TestRedisCertStore_GetNotFound(t *testing.T) {
	store, _ := newTestCertStore(t)
	ctx := context.Background()

	got, err := store.GetCert(ctx, "*.nonexistent.example.com")
	require.NoError(t, err)
	assert.Nil(t, got)
}

func TestRedisCertStore_Overwrite(t *testing.T) {
	store, _ := newTestCertStore(t)
	ctx := context.Background()

	cert1, key1, err := testutil.GenerateSelfSignedCert("*.test.example.com", time.Now().Add(30*24*time.Hour))
	require.NoError(t, err)
	require.NoError(t, store.SaveCert(ctx, "*.test.example.com", cert1, key1, time.Now().Add(30*24*time.Hour)))

	cert2, key2, err := testutil.GenerateSelfSignedCert("*.test.example.com", time.Now().Add(90*24*time.Hour))
	require.NoError(t, err)
	require.NoError(t, store.SaveCert(ctx, "*.test.example.com", cert2, key2, time.Now().Add(90*24*time.Hour)))

	got, err := store.GetCert(ctx, "*.test.example.com")
	require.NoError(t, err)
	assert.Equal(t, cert2, got.CertPEM)
}

func TestRedisCertStore_ListExpiring(t *testing.T) {
	store, _ := newTestCertStore(t)
	ctx := context.Background()

	cert1, key1, err := testutil.GenerateSelfSignedCert("*.expiring.example.com", time.Now().Add(10*24*time.Hour))
	require.NoError(t, err)
	require.NoError(t, store.SaveCert(ctx, "*.expiring.example.com", cert1, key1, time.Now().Add(10*24*time.Hour)))

	cert2, key2, err := testutil.GenerateSelfSignedCert("*.fresh.example.com", time.Now().Add(90*24*time.Hour))
	require.NoError(t, err)
	require.NoError(t, store.SaveCert(ctx, "*.fresh.example.com", cert2, key2, time.Now().Add(90*24*time.Hour)))

	// List certs expiring within 30 days
	expiring, err := store.ListExpiring(ctx, time.Now().Add(30*24*time.Hour))
	require.NoError(t, err)

	assert.Contains(t, expiring, "*.expiring.example.com")
	assert.NotContains(t, expiring, "*.fresh.example.com")
}

func TestRedisCertStore_ListExpiring_Empty(t *testing.T) {
	store, _ := newTestCertStore(t)
	ctx := context.Background()

	expiring, err := store.ListExpiring(ctx, time.Now().Add(30*24*time.Hour))
	require.NoError(t, err)
	assert.Empty(t, expiring)
}

func TestRedisCertStore_SaveCert_Sets14DayTTL(t *testing.T) {
	store, mr := newTestCertStore(t)
	ctx := context.Background()

	certPEM, keyPEM, err := testutil.GenerateSelfSignedCert("*.test.example.com", time.Now().Add(90*24*time.Hour))
	require.NoError(t, err)
	require.NoError(t, store.SaveCert(ctx, "*.test.example.com", certPEM, keyPEM, time.Now().Add(90*24*time.Hour)))

	ttl := mr.TTL("cert:*.test.example.com")
	assert.InDelta(t, (14 * 24 * time.Hour).Seconds(), ttl.Seconds(), 5)
}

func TestRedisCertStore_RefreshCertTTL(t *testing.T) {
	store, mr := newTestCertStore(t)
	ctx := context.Background()

	certPEM, keyPEM, err := testutil.GenerateSelfSignedCert("*.test.example.com", time.Now().Add(90*24*time.Hour))
	require.NoError(t, err)
	require.NoError(t, store.SaveCert(ctx, "*.test.example.com", certPEM, keyPEM, time.Now().Add(90*24*time.Hour)))

	// Advance time by 7 days
	mr.FastForward(7 * 24 * time.Hour)

	// TTL should be ~7 days now
	ttlBefore := mr.TTL("cert:*.test.example.com")
	assert.InDelta(t, (7 * 24 * time.Hour).Seconds(), ttlBefore.Seconds(), 5)

	// Refresh TTL back to 14 days
	require.NoError(t, store.RefreshCertTTL(ctx, "*.test.example.com", 14*24*time.Hour))

	ttlAfter := mr.TTL("cert:*.test.example.com")
	assert.InDelta(t, (14 * 24 * time.Hour).Seconds(), ttlAfter.Seconds(), 5)
}

func TestRedisCertStore_RefreshCertTTL_NonexistentKey(t *testing.T) {
	store, _ := newTestCertStore(t)
	ctx := context.Background()

	// Should not error — EXPIRE on nonexistent key returns false, not an error
	err := store.RefreshCertTTL(ctx, "*.nonexistent.example.com", 14*24*time.Hour)
	require.NoError(t, err)
}
