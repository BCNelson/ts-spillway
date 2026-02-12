package certmanager

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestRedis(t *testing.T) (*miniredis.Miniredis, redis.Cmdable) {
	t.Helper()
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })
	return mr, rdb
}

func TestAcquireLock_Success(t *testing.T) {
	_, rdb := newTestRedis(t)
	locker := NewRedisLocker(rdb, 5*time.Minute)

	release, err := locker.Acquire(context.Background(), "*.test.example.com")
	require.NoError(t, err)
	require.NotNil(t, release)

	// Clean up
	release(context.Background())
}

func TestAcquireLock_AlreadyHeld(t *testing.T) {
	_, rdb := newTestRedis(t)
	locker := NewRedisLocker(rdb, 5*time.Minute)

	release, err := locker.Acquire(context.Background(), "*.test.example.com")
	require.NoError(t, err)
	defer release(context.Background())

	// Second acquire should fail
	_, err = locker.Acquire(context.Background(), "*.test.example.com")
	assert.ErrorIs(t, err, ErrLockNotAcquired)
}

func TestReleaseLock_OwnerOnly(t *testing.T) {
	mr, rdb := newTestRedis(t)
	locker := NewRedisLocker(rdb, 5*time.Minute)

	release, err := locker.Acquire(context.Background(), "*.test.example.com")
	require.NoError(t, err)

	// Simulate another owner by overwriting the lock value directly
	require.NoError(t, mr.Set("spillway:lock:*.test.example.com", "other-owner"))

	// Release should be a no-op since the owner doesn't match
	release(context.Background())

	// Lock should still exist (not deleted by the wrong owner)
	val, err := rdb.Get(context.Background(), "spillway:lock:*.test.example.com").Result()
	require.NoError(t, err)
	assert.Equal(t, "other-owner", val)
}

func TestLockExpires(t *testing.T) {
	mr, rdb := newTestRedis(t)
	locker := NewRedisLocker(rdb, 5*time.Minute)

	_, err := locker.Acquire(context.Background(), "*.test.example.com")
	require.NoError(t, err)

	// Fast-forward past the TTL
	mr.FastForward(6 * time.Minute)

	// Lock should have expired; a new acquire should succeed
	release2, err := locker.Acquire(context.Background(), "*.test.example.com")
	require.NoError(t, err)
	release2(context.Background())
}

func TestAcquireLock_DifferentKeys(t *testing.T) {
	_, rdb := newTestRedis(t)
	locker := NewRedisLocker(rdb, 5*time.Minute)

	release1, err := locker.Acquire(context.Background(), "*.a.example.com")
	require.NoError(t, err)
	defer release1(context.Background())

	// Different key should succeed
	release2, err := locker.Acquire(context.Background(), "*.b.example.com")
	require.NoError(t, err)
	defer release2(context.Background())
}

func TestReleaseLock_AllowsReacquire(t *testing.T) {
	_, rdb := newTestRedis(t)
	locker := NewRedisLocker(rdb, 5*time.Minute)

	release, err := locker.Acquire(context.Background(), "*.test.example.com")
	require.NoError(t, err)

	release(context.Background())

	// Should be able to acquire again after release
	release2, err := locker.Acquire(context.Background(), "*.test.example.com")
	require.NoError(t, err)
	release2(context.Background())
}
