package certmanager

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"time"

	"github.com/redis/go-redis/v9"
)

// ErrLockNotAcquired is returned when a lock is already held by another owner.
var ErrLockNotAcquired = errors.New("lock not acquired")

// Locker provides distributed locking for certificate issuance.
type Locker interface {
	// Acquire attempts to acquire a lock for the given key.
	// Returns a release function on success, or ErrLockNotAcquired if already held.
	Acquire(ctx context.Context, key string) (release func(ctx context.Context), err error)
}

// RedisLocker implements Locker using Redis SET NX with TTL and Lua-script release.
type RedisLocker struct {
	client redis.Cmdable
	ttl    time.Duration
	prefix string
}

// NewRedisLocker creates a new RedisLocker.
// ttl controls how long a lock is held before auto-expiring (safety net).
func NewRedisLocker(client redis.Cmdable, ttl time.Duration) *RedisLocker {
	return &RedisLocker{
		client: client,
		ttl:    ttl,
		prefix: "spillway:lock:",
	}
}

func (l *RedisLocker) Acquire(ctx context.Context, key string) (func(ctx context.Context), error) {
	owner, err := randomOwner()
	if err != nil {
		return nil, err
	}

	lockKey := l.prefix + key

	ok, err := l.client.SetNX(ctx, lockKey, owner, l.ttl).Result()
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, ErrLockNotAcquired
	}

	release := func(ctx context.Context) {
		// Lua script: only delete if the value matches our owner token.
		const luaRelease = `if redis.call("GET", KEYS[1]) == ARGV[1] then return redis.call("DEL", KEYS[1]) else return 0 end`
		_ = l.client.Eval(ctx, luaRelease, []string{lockKey}, owner).Err()
	}

	return release, nil
}

func randomOwner() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
