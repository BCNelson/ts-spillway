package certmanager

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// RedisCertStore implements CertStore using Redis.
type RedisCertStore struct {
	client *redis.Client
}

// NewRedisCertStore creates a new RedisCertStore.
func NewRedisCertStore(client *redis.Client) *RedisCertStore {
	return &RedisCertStore{client: client}
}

type storedCertJSON struct {
	CertPEM  []byte    `json:"cert_pem"`
	KeyPEM   []byte    `json:"key_pem"`
	NotAfter time.Time `json:"not_after"`
}

func certKey(domain string) string {
	return fmt.Sprintf("cert:%s", domain)
}

func (s *RedisCertStore) GetCert(ctx context.Context, domain string) (*StoredCert, error) {
	data, err := s.client.Get(ctx, certKey(domain)).Bytes()
	if err == redis.Nil {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	var stored storedCertJSON
	if err := json.Unmarshal(data, &stored); err != nil {
		return nil, fmt.Errorf("unmarshaling cert data for %s: %w", domain, err)
	}

	return &StoredCert{
		CertPEM:  stored.CertPEM,
		KeyPEM:   stored.KeyPEM,
		NotAfter: stored.NotAfter,
	}, nil
}

func (s *RedisCertStore) SaveCert(ctx context.Context, domain string, certPEM, keyPEM []byte, notAfter time.Time) error {
	data, err := json.Marshal(storedCertJSON{
		CertPEM:  certPEM,
		KeyPEM:   keyPEM,
		NotAfter: notAfter,
	})
	if err != nil {
		return err
	}

	// 14-day TTL — daily refresh job resets TTL for active machines' certs.
	// Certs for deregistered machines naturally expire.
	return s.client.Set(ctx, certKey(domain), data, 14*24*time.Hour).Err()
}

func (s *RedisCertStore) RefreshCertTTL(ctx context.Context, domain string, ttl time.Duration) error {
	return s.client.Expire(ctx, certKey(domain), ttl).Err()
}

func (s *RedisCertStore) ListExpiring(ctx context.Context, before time.Time) ([]string, error) {
	var expiring []string

	iter := s.client.Scan(ctx, 0, "cert:*", 100).Iterator()
	for iter.Next(ctx) {
		key := iter.Val()
		data, err := s.client.Get(ctx, key).Bytes()
		if err != nil {
			continue
		}

		var stored storedCertJSON
		if err := json.Unmarshal(data, &stored); err != nil {
			continue
		}

		if stored.NotAfter.Before(before) {
			// Extract domain from key "cert:<domain>"
			domain := key[len("cert:"):]
			expiring = append(expiring, domain)
		}
	}
	if err := iter.Err(); err != nil {
		return nil, err
	}

	return expiring, nil
}
