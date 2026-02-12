package registry

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestStore(t *testing.T) (*RedisStore, *miniredis.Miniredis) {
	t.Helper()
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	store := NewRedisStore(client, 90*time.Second)
	return store, mr
}

func TestRegisterAndLookup(t *testing.T) {
	store, _ := newTestStore(t)
	ctx := context.Background()

	require.NoError(t, store.Register(ctx, "alice", "laptop", 8080, "100.64.0.1"))

	ip, err := store.Lookup(ctx, "alice", "laptop", 8080)
	require.NoError(t, err)
	assert.Equal(t, "100.64.0.1", ip)
}

func TestLookup_NotFound(t *testing.T) {
	store, _ := newTestStore(t)
	ctx := context.Background()

	ip, err := store.Lookup(ctx, "alice", "laptop", 9999)
	require.NoError(t, err)
	assert.Equal(t, "", ip)
}

func TestDeregister(t *testing.T) {
	store, _ := newTestStore(t)
	ctx := context.Background()

	require.NoError(t, store.Register(ctx, "alice", "laptop", 8080, "100.64.0.1"))
	require.NoError(t, store.Deregister(ctx, "alice", "laptop", 8080))

	ip, err := store.Lookup(ctx, "alice", "laptop", 8080)
	require.NoError(t, err)
	assert.Equal(t, "", ip)
}

func TestRefreshHeartbeat(t *testing.T) {
	store, mr := newTestStore(t)
	ctx := context.Background()

	require.NoError(t, store.Register(ctx, "alice", "laptop", 8080, "100.64.0.1"))

	// Fast-forward time close to expiry
	mr.FastForward(80 * time.Second)

	// Refresh should reset the TTL
	require.NoError(t, store.RefreshHeartbeat(ctx, "alice", "laptop", []int{8080}))

	// Fast-forward another 80 seconds — without refresh this would have expired
	mr.FastForward(80 * time.Second)

	ip, err := store.Lookup(ctx, "alice", "laptop", 8080)
	require.NoError(t, err)
	assert.Equal(t, "100.64.0.1", ip)
}

func TestRefreshHeartbeat_Expired(t *testing.T) {
	store, mr := newTestStore(t)
	ctx := context.Background()

	require.NoError(t, store.Register(ctx, "alice", "laptop", 8080, "100.64.0.1"))

	// Let key expire
	mr.FastForward(91 * time.Second)

	ip, err := store.Lookup(ctx, "alice", "laptop", 8080)
	require.NoError(t, err)
	assert.Equal(t, "", ip)
}

func TestListByMachine(t *testing.T) {
	store, _ := newTestStore(t)
	ctx := context.Background()

	require.NoError(t, store.Register(ctx, "alice", "laptop", 8080, "100.64.0.1"))
	require.NoError(t, store.Register(ctx, "alice", "laptop", 8081, "100.64.0.1"))

	regs, err := store.ListByMachine(ctx, "alice", "laptop")
	require.NoError(t, err)
	assert.Len(t, regs, 2)

	ports := map[int]bool{}
	for _, r := range regs {
		ports[r.Port] = true
		assert.Equal(t, "alice", r.User)
		assert.Equal(t, "laptop", r.Machine)
		assert.Equal(t, "100.64.0.1", r.TailscaleIP)
	}
	assert.True(t, ports[8080])
	assert.True(t, ports[8081])
}

func TestListByMachine_CleansExpired(t *testing.T) {
	store, mr := newTestStore(t)
	ctx := context.Background()

	require.NoError(t, store.Register(ctx, "alice", "laptop", 8080, "100.64.0.1"))
	require.NoError(t, store.Register(ctx, "alice", "laptop", 8081, "100.64.0.1"))

	// Expire all keys
	mr.FastForward(91 * time.Second)

	regs, err := store.ListByMachine(ctx, "alice", "laptop")
	require.NoError(t, err)
	assert.Empty(t, regs)
}

func TestSaveUser(t *testing.T) {
	store, mr := newTestStore(t)
	ctx := context.Background()

	require.NoError(t, store.SaveUser(ctx, "12345", "alice", "Alice Smith"))

	val, err := mr.Get("user:12345")
	require.NoError(t, err)
	assert.Contains(t, val, "alice")
	assert.Contains(t, val, "Alice Smith")
}

func TestSaveMachine(t *testing.T) {
	store, mr := newTestStore(t)
	ctx := context.Background()

	require.NoError(t, store.SaveMachine(ctx, "alice", "laptop", "100.64.0.1"))

	val, err := mr.Get("machine:alice:laptop")
	require.NoError(t, err)
	assert.Equal(t, "100.64.0.1", val)
}

func TestListActiveMachines(t *testing.T) {
	store, _ := newTestStore(t)
	ctx := context.Background()

	// Register ports for two machines
	require.NoError(t, store.Register(ctx, "alice", "laptop", 8080, "100.64.0.1"))
	require.NoError(t, store.Register(ctx, "bob", "desktop", 9090, "100.64.0.2"))

	machines, err := store.ListActiveMachines(ctx)
	require.NoError(t, err)
	assert.Len(t, machines, 2)

	refs := map[string]bool{}
	for _, m := range machines {
		refs[m.User+":"+m.Machine] = true
	}
	assert.True(t, refs["alice:laptop"])
	assert.True(t, refs["bob:desktop"])
}

func TestListActiveMachines_ExcludesEmptySets(t *testing.T) {
	store, _ := newTestStore(t)
	ctx := context.Background()

	// Register then deregister — set should become empty
	require.NoError(t, store.Register(ctx, "alice", "laptop", 8080, "100.64.0.1"))
	require.NoError(t, store.Deregister(ctx, "alice", "laptop", 8080))

	// Register another machine that stays active
	require.NoError(t, store.Register(ctx, "bob", "desktop", 9090, "100.64.0.2"))

	machines, err := store.ListActiveMachines(ctx)
	require.NoError(t, err)
	assert.Len(t, machines, 1)
	assert.Equal(t, "bob", machines[0].User)
	assert.Equal(t, "desktop", machines[0].Machine)
}

func TestListActiveMachines_Empty(t *testing.T) {
	store, _ := newTestStore(t)
	ctx := context.Background()

	machines, err := store.ListActiveMachines(ctx)
	require.NoError(t, err)
	assert.Empty(t, machines)
}

func TestKeyFormat(t *testing.T) {
	store, mr := newTestStore(t)
	ctx := context.Background()

	require.NoError(t, store.Register(ctx, "alice", "laptop", 8080, "100.64.0.1"))

	// Verify key format
	val, err := mr.Get("reg:alice:laptop:8080")
	require.NoError(t, err)
	assert.Equal(t, "100.64.0.1", val)

	// Verify set membership
	members, err := mr.Members("machine_regs:alice:laptop")
	require.NoError(t, err)
	assert.Contains(t, members, "8080")
}
