//go:build e2e

package e2e

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/go-acme/lego/v4/challenge/dns01"
)

// challtestProvider implements challenge.Provider by calling pebble-challtestsrv's
// HTTP management API to set/clear DNS TXT records for ACME DNS-01 challenges.
type challtestProvider struct {
	apiURL string // e.g. "http://localhost:8055"
}

func newChalltestProvider(apiURL string) *challtestProvider {
	return &challtestProvider{apiURL: apiURL}
}

func (p *challtestProvider) Present(domain, token, keyAuth string) error {
	info := dns01.GetChallengeInfo(domain, keyAuth)

	body, err := json.Marshal(map[string]string{
		"host":  info.FQDN,
		"value": info.Value,
	})
	if err != nil {
		return fmt.Errorf("marshaling set-txt request: %w", err)
	}

	resp, err := http.Post(p.apiURL+"/set-txt", "application/json", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("calling challtestsrv set-txt: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("challtestsrv set-txt returned %d", resp.StatusCode)
	}

	return nil
}

func (p *challtestProvider) CleanUp(domain, token, keyAuth string) error {
	info := dns01.GetChallengeInfo(domain, keyAuth)

	body, err := json.Marshal(map[string]string{
		"host": info.FQDN,
	})
	if err != nil {
		return fmt.Errorf("marshaling clear-txt request: %w", err)
	}

	resp, err := http.Post(p.apiURL+"/clear-txt", "application/json", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("calling challtestsrv clear-txt: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("challtestsrv clear-txt returned %d", resp.StatusCode)
	}

	return nil
}
