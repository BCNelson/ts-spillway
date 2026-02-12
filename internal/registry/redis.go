package registry

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
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

func (s *RedisStore) SaveMachine(ctx context.Context, user, machineName, tailscaleIP string) error {
	return s.client.Set(ctx, machineKey(user, machineName), tailscaleIP, 0).Err()
}
