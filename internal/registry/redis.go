package registry

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

// RedisStore implements Store using Redis.
type RedisStore struct {
	client *redis.Client
	ttl    time.Duration
}

// NewRedisStore creates a new RedisStore.
func NewRedisStore(client *redis.Client, heartbeatTTL time.Duration) *RedisStore {
	return &RedisStore{
		client: client,
		ttl:    heartbeatTTL,
	}
}

func regKey(user, machine string, port int) string {
	return fmt.Sprintf("reg:%s:%s:%d", user, machine, port)
}

func machineRegsKey(user, machine string) string {
	return fmt.Sprintf("machine_regs:%s:%s", user, machine)
}

func userKey(tailscaleID string) string {
	return fmt.Sprintf("user:%s", tailscaleID)
}

func machineKey(user, machineName string) string {
	return fmt.Sprintf("machine:%s:%s", user, machineName)
}

func aliasKey(user, machine, alias string) string {
	return fmt.Sprintf("alias:%s:%s:%s", user, machine, alias)
}

func machineAliasesKey(user, machine string) string {
	return fmt.Sprintf("machine_aliases:%s:%s", user, machine)
}

func (s *RedisStore) Register(ctx context.Context, user, machine string, port int, tailscaleIP string) error {
	pipe := s.client.Pipeline()

	// Set registration key with TTL
	pipe.Set(ctx, regKey(user, machine, port), tailscaleIP, s.ttl)

	// Add port to machine's registration set
	pipe.SAdd(ctx, machineRegsKey(user, machine), strconv.Itoa(port))

	_, err := pipe.Exec(ctx)
	return err
}

func (s *RedisStore) Deregister(ctx context.Context, user, machine string, port int) error {
	pipe := s.client.Pipeline()

	pipe.Del(ctx, regKey(user, machine, port))
	pipe.SRem(ctx, machineRegsKey(user, machine), strconv.Itoa(port))

	_, err := pipe.Exec(ctx)
	return err
}

func (s *RedisStore) RefreshHeartbeat(ctx context.Context, user, machine string, ports []int) error {
	pipe := s.client.Pipeline()

	for _, port := range ports {
		pipe.Expire(ctx, regKey(user, machine, port), s.ttl)
	}

	_, err := pipe.Exec(ctx)
	return err
}

func (s *RedisStore) Lookup(ctx context.Context, user, machine string, port int) (string, error) {
	ip, err := s.client.Get(ctx, regKey(user, machine, port)).Result()
	if err == redis.Nil {
		return "", nil
	}
	return ip, err
}

func (s *RedisStore) ListByMachine(ctx context.Context, user, machine string) ([]Registration, error) {
	ports, err := s.client.SMembers(ctx, machineRegsKey(user, machine)).Result()
	if err != nil {
		return nil, err
	}

	// Build a reverse map of port -> alias from the alias set
	aliasMembers, err := s.client.SMembers(ctx, machineAliasesKey(user, machine)).Result()
	if err != nil {
		return nil, err
	}
	portAlias := make(map[int]string)
	for _, member := range aliasMembers {
		parts := strings.SplitN(member, ":", 2)
		if len(parts) != 2 {
			continue
		}
		alias := parts[0]
		port, err := strconv.Atoi(parts[1])
		if err != nil {
			continue
		}
		portAlias[port] = alias
	}

	var regs []Registration
	for _, portStr := range ports {
		port, err := strconv.Atoi(portStr)
		if err != nil {
			continue
		}

		key := regKey(user, machine, port)
		ip, err := s.client.Get(ctx, key).Result()
		if err == redis.Nil {
			// Registration expired, clean up the set entry
			s.client.SRem(ctx, machineRegsKey(user, machine), portStr)
			continue
		}
		if err != nil {
			return nil, err
		}

		ttl, err := s.client.TTL(ctx, key).Result()
		if err != nil {
			return nil, err
		}

		regs = append(regs, Registration{
			User:        user,
			Machine:     machine,
			Port:        port,
			TailscaleIP: ip,
			ExpiresAt:   time.Now().Add(ttl),
			Alias:       portAlias[port],
		})
	}

	return regs, nil
}

type userInfo struct {
	LoginName   string `json:"login_name"`
	DisplayName string `json:"display_name"`
}

func (s *RedisStore) SaveUser(ctx context.Context, tailscaleID, loginName, displayName string) error {
	data, err := json.Marshal(userInfo{LoginName: loginName, DisplayName: displayName})
	if err != nil {
		return err
	}
	return s.client.Set(ctx, userKey(tailscaleID), data, 0).Err()
}

func (s *RedisStore) ListActiveMachines(ctx context.Context) ([]MachineRef, error) {
	var machines []MachineRef

	iter := s.client.Scan(ctx, 0, "machine_regs:*", 100).Iterator()
	for iter.Next(ctx) {
		key := iter.Val()
		// Key format: machine_regs:{user}:{machine}
		parts := strings.SplitN(key, ":", 3)
		if len(parts) != 3 {
			continue
		}
		user := parts[1]
		machine := parts[2]

		// Only include machines with active registrations
		count, err := s.client.SCard(ctx, key).Result()
		if err != nil {
			continue
		}
		if count > 0 {
			machines = append(machines, MachineRef{User: user, Machine: machine})
		}
	}
	if err := iter.Err(); err != nil {
		return nil, err
	}

	return machines, nil
}

func (s *RedisStore) SaveMachine(ctx context.Context, user, machineName, tailscaleIP string) error {
	return s.client.Set(ctx, machineKey(user, machineName), tailscaleIP, 0).Err()
}

// RegisterAlias maps an alias to a port for a user's machine.
func (s *RedisStore) RegisterAlias(ctx context.Context, user, machine, alias string, port int) error {
	pipe := s.client.Pipeline()

	// Store alias -> port mapping with TTL
	pipe.Set(ctx, aliasKey(user, machine, alias), strconv.Itoa(port), s.ttl)

	// Track alias in the machine's alias set (alias:port pairs)
	pipe.SAdd(ctx, machineAliasesKey(user, machine), fmt.Sprintf("%s:%d", alias, port))

	_, err := pipe.Exec(ctx)
	return err
}

// DeregisterAlias removes an alias mapping.
func (s *RedisStore) DeregisterAlias(ctx context.Context, user, machine, alias string) error {
	// Look up the port for this alias first so we can clean the set
	portStr, err := s.client.Get(ctx, aliasKey(user, machine, alias)).Result()
	if err == redis.Nil {
		return nil // Already gone
	}
	if err != nil {
		return err
	}

	pipe := s.client.Pipeline()
	pipe.Del(ctx, aliasKey(user, machine, alias))
	pipe.SRem(ctx, machineAliasesKey(user, machine), fmt.Sprintf("%s:%s", alias, portStr))
	_, err = pipe.Exec(ctx)
	return err
}

// LookupAlias returns the port for a given alias, or 0 if not found.
func (s *RedisStore) LookupAlias(ctx context.Context, user, machine, alias string) (int, error) {
	portStr, err := s.client.Get(ctx, aliasKey(user, machine, alias)).Result()
	if err == redis.Nil {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return 0, fmt.Errorf("invalid port value for alias %q: %w", alias, err)
	}
	return port, nil
}

// RefreshAliasHeartbeat extends the TTL on aliases for the given machine.
func (s *RedisStore) RefreshAliasHeartbeat(ctx context.Context, user, machine string, aliases []string) error {
	pipe := s.client.Pipeline()

	for _, alias := range aliases {
		pipe.Expire(ctx, aliasKey(user, machine, alias), s.ttl)
	}

	_, err := pipe.Exec(ctx)
	return err
}
