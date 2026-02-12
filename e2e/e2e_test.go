//go:build e2e

package e2e

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestE2E_FullLifecycle exercises the complete register → status → deregister → status flow
// over real Tailscale networking (via testcontrol).
func TestE2E_FullLifecycle(t *testing.T) {
	env := setupE2E(t)

	serverAddr := fmt.Sprintf("spillway:%d", env.apiPort)
	client := newE2EClient(t, env.controlURL, "testclient", serverAddr)

	// Register ports
	reg := client.register(t, []int{8080, 8443})
	if len(reg.URLs) == 0 {
		t.Fatal("register returned no URLs")
	}
	t.Logf("registered URLs: %v", reg.URLs)

	// Status should show registrations
	st := client.status(t)
	if len(st.Registrations) != 2 {
		t.Fatalf("expected 2 registrations, got %d", len(st.Registrations))
	}

	ports := map[int]bool{}
	for _, r := range st.Registrations {
		ports[r.Port] = true
	}
	if !ports[8080] || !ports[8443] {
		t.Fatalf("expected ports 8080 and 8443, got %v", ports)
	}

	// Deregister
	client.deregister(t, []int{8080, 8443})

	// Status should be empty
	st = client.status(t)
	if len(st.Registrations) != 0 {
		t.Fatalf("expected 0 registrations after deregister, got %d", len(st.Registrations))
	}
}

// TestE2E_CertificateIssuance verifies that registration triggers ACME certificate
// issuance via Pebble, with DNS-01 validation through challtestsrv.
func TestE2E_CertificateIssuance(t *testing.T) {
	env := setupE2E(t)

	serverAddr := fmt.Sprintf("spillway:%d", env.apiPort)
	client := newE2EClient(t, env.controlURL, "certclient", serverAddr)

	// Register a port — this triggers EnsureCert
	client.register(t, []int{9000})

	// Check that cert keys were written to Redis
	ctx := t.Context()
	var keys []string
	iter := env.rdb.Scan(ctx, 0, "cert:*", 100).Iterator()
	for iter.Next(ctx) {
		keys = append(keys, iter.Val())
	}
	if err := iter.Err(); err != nil {
		t.Fatalf("scanning for cert keys: %v", err)
	}

	if len(keys) == 0 {
		t.Fatal("no cert:* keys found in Redis after registration")
	}

	t.Logf("found %d cert keys: %v", len(keys), keys)
}

// TestE2E_MultiNode verifies that two different tsnet clients get isolated registrations.
func TestE2E_MultiNode(t *testing.T) {
	env := setupE2E(t)

	serverAddr := fmt.Sprintf("spillway:%d", env.apiPort)

	client1 := newE2EClient(t, env.controlURL, "node-alpha", serverAddr)
	client2 := newE2EClient(t, env.controlURL, "node-beta", serverAddr)

	// Both register
	reg1 := client1.register(t, []int{3000})
	reg2 := client2.register(t, []int{4000})

	t.Logf("client1 URLs: %v", reg1.URLs)
	t.Logf("client2 URLs: %v", reg2.URLs)

	// Each should see only their own registrations
	st1 := client1.status(t)
	st2 := client2.status(t)

	if len(st1.Registrations) != 1 {
		t.Fatalf("client1: expected 1 registration, got %d", len(st1.Registrations))
	}
	if st1.Registrations[0].Port != 3000 {
		t.Fatalf("client1: expected port 3000, got %d", st1.Registrations[0].Port)
	}

	if len(st2.Registrations) != 1 {
		t.Fatalf("client2: expected 1 registration, got %d", len(st2.Registrations))
	}
	if st2.Registrations[0].Port != 4000 {
		t.Fatalf("client2: expected port 4000, got %d", st2.Registrations[0].Port)
	}

	// URLs should contain different machine names
	hasAlpha := false
	for _, u := range reg1.URLs {
		if strings.Contains(u, "node-alpha") {
			hasAlpha = true
			break
		}
	}
	hasBeta := false
	for _, u := range reg2.URLs {
		if strings.Contains(u, "node-beta") {
			hasBeta = true
			break
		}
	}
	if !hasAlpha {
		t.Error("client1 URLs don't contain 'node-alpha'")
	}
	if !hasBeta {
		t.Error("client2 URLs don't contain 'node-beta'")
	}
}

// TestE2E_TTLExpiration verifies that registrations expire after TTL.
func TestE2E_TTLExpiration(t *testing.T) {
	env := setupE2E(t)

	serverAddr := fmt.Sprintf("spillway:%d", env.apiPort)
	client := newE2EClient(t, env.controlURL, "ttlclient", serverAddr)

	// Register
	client.register(t, []int{5000})

	// Verify the registration is alive immediately
	st := client.status(t)
	if len(st.Registrations) != 1 {
		t.Fatalf("expected 1 registration, got %d", len(st.Registrations))
	}

	// Still alive just before TTL expires (89s of 90s TTL)
	env.mini.FastForward(89 * time.Second)
	st = client.status(t)
	if len(st.Registrations) != 1 {
		t.Fatalf("expected 1 registration at 89s (before 90s TTL), got %d", len(st.Registrations))
	}

	// Fast-forward past the TTL (2 more seconds → 91s total)
	env.mini.FastForward(2 * time.Second)

	// Status should be empty
	st = client.status(t)
	if len(st.Registrations) != 0 {
		t.Fatalf("expected 0 registrations after TTL expiry, got %d", len(st.Registrations))
	}
}

// TestE2E_HeartbeatKeepsAlive verifies that heartbeats extend TTL.
func TestE2E_HeartbeatKeepsAlive(t *testing.T) {
	env := setupE2E(t)

	serverAddr := fmt.Sprintf("spillway:%d", env.apiPort)
	client := newE2EClient(t, env.controlURL, "hbclient", serverAddr)

	// Register
	client.register(t, []int{6000})

	// Fast-forward 80s (under the 90s TTL)
	env.mini.FastForward(80 * time.Second)

	// Heartbeat to refresh
	client.heartbeat(t, []int{6000})

	// Fast-forward another 80s (160s total, but heartbeat reset the TTL)
	env.mini.FastForward(80 * time.Second)

	// Should still be alive
	st := client.status(t)
	if len(st.Registrations) != 1 {
		t.Fatalf("expected 1 registration after heartbeat, got %d", len(st.Registrations))
	}
	if st.Registrations[0].Port != 6000 {
		t.Fatalf("expected port 6000, got %d", st.Registrations[0].Port)
	}
}

// TestE2E_ProxyForwarding verifies that the proxy forwards HTTP requests from the
// public-facing side through to a backend service on a tsnet client node.
func TestE2E_ProxyForwarding(t *testing.T) {
	env := setupE2E(t)

	serverAddr := fmt.Sprintf("spillway:%d", env.apiPort)
	client := newE2EClient(t, env.controlURL, "proxyclient", serverAddr)

	// Start a backend HTTP server on the tsnet client node.
	// We record every request the backend receives so we can verify the proxy
	// actually forwarded the call (not just returned canned data).
	backendPort := 7777
	ln, err := client.node.Listen("tcp", fmt.Sprintf(":%d", backendPort))
	if err != nil {
		t.Fatalf("backend listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	type backendHit struct {
		Method          string
		Path            string
		Host            string
		XForwardedFor   string
		XForwardedHost  string
		XForwardedProto string
	}
	var (
		mu   sync.Mutex
		hits []backendHit
	)

	go http.Serve(ln, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		hits = append(hits, backendHit{
			Method:          r.Method,
			Path:            r.URL.Path,
			Host:            r.Host,
			XForwardedFor:   r.Header.Get("X-Forwarded-For"),
			XForwardedHost:  r.Header.Get("X-Forwarded-Host"),
			XForwardedProto: r.Header.Get("X-Forwarded-Proto"),
		})
		mu.Unlock()

		w.Header().Set("X-Backend", "proxyclient")
		w.Header().Set("X-Request-Path", r.URL.Path)
		w.Header().Set("X-Request-Method", r.Method)
		fmt.Fprintf(w, "method=%s path=%s", r.Method, r.URL.Path)
	}))

	// Register the backend port with spillway
	reg := client.register(t, []int{backendPort})
	t.Logf("registered URLs: %v", reg.URLs)

	// Find the subdomain-style URL (e.g., https://7777.proxyclient.user-X.spillway.test)
	// to determine the correct Host header for the proxy
	var subdomainHost string
	for _, u := range reg.URLs {
		parsed, err := url.Parse(u)
		if err != nil {
			continue
		}
		labels := strings.Split(parsed.Hostname(), ".")
		if len(labels) > 0 {
			if _, err := strconv.Atoi(labels[0]); err == nil {
				subdomainHost = parsed.Hostname()
				break
			}
		}
	}
	if subdomainHost == "" {
		t.Fatal("could not find subdomain-style URL in registration response")
	}
	t.Logf("proxy host: %s", subdomainHost)

	// Start a real TLS listener using the cert manager's GetCertificate.
	// This exercises the full TLS termination path: SNI → cert lookup in Redis → TLS handshake.
	tlsCfg := &tls.Config{
		GetCertificate: env.certMgr.GetCertificate,
	}
	tlsLn, err := tls.Listen("tcp", "127.0.0.1:0", tlsCfg)
	if err != nil {
		t.Fatalf("starting TLS listener: %v", err)
	}
	t.Cleanup(func() { tlsLn.Close() })

	go http.Serve(tlsLn, env.srv.ProxyHandler())

	// Build a CA trust pool from the Pebble-issued cert chain stored in Redis.
	// The stored PEM includes the leaf + intermediate CA. Adding the intermediate
	// to the root pool makes it a trust anchor for TLS verification.
	ctx := t.Context()
	wildcardDomain := "*." + strings.Join(strings.Split(subdomainHost, ".")[1:], ".")
	stored, err := env.certStore.GetCert(ctx, wildcardDomain)
	if err != nil {
		t.Fatalf("getting cert from store: %v", err)
	}
	if stored == nil {
		t.Fatalf("no cert found in store for %s after registration", wildcardDomain)
	}
	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(stored.CertPEM) {
		t.Fatal("failed to parse cert chain PEM into CA pool")
	}

	// Create an HTTPS client that:
	// 1. Trusts the Pebble-issued cert chain (via caPool)
	// 2. Routes all connections to our local TLS listener (via DialContext)
	// SNI is set automatically from the request URL hostname.
	tlsListenerAddr := tlsLn.Addr().String()
	proxyClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs: caPool,
			},
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "tcp", tlsListenerAddr)
			},
		},
		Timeout: 30 * time.Second,
	}

	// Send multiple requests with different methods and paths over real TLS
	// to verify the proxy consistently forwards them.
	requests := []struct {
		method   string
		path     string
		wantBody string
	}{
		{"GET", "/hello", "method=GET path=/hello"},
		{"GET", "/api/data", "method=GET path=/api/data"},
		{"POST", "/submit", "method=POST path=/submit"},
		{"PUT", "/update/123", "method=PUT path=/update/123"},
	}

	for _, tc := range requests {
		reqURL := fmt.Sprintf("https://%s%s", subdomainHost, tc.path)
		req, err := http.NewRequest(tc.method, reqURL, nil)
		if err != nil {
			t.Fatalf("%s %s: creating request: %v", tc.method, tc.path, err)
		}

		resp, err := proxyClient.Do(req)
		if err != nil {
			t.Fatalf("%s %s: proxy request: %v", tc.method, tc.path, err)
		}

		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			t.Fatalf("%s %s: reading response: %v", tc.method, tc.path, err)
		}

		if resp.StatusCode != http.StatusOK {
			t.Fatalf("%s %s: proxy returned %d: %s", tc.method, tc.path, resp.StatusCode, body)
		}

		if string(body) != tc.wantBody {
			t.Fatalf("%s %s: expected body %q, got %q", tc.method, tc.path, tc.wantBody, string(body))
		}

		// Verify the TLS handshake used a real Pebble-issued certificate
		if resp.TLS == nil {
			t.Fatalf("%s %s: response has no TLS connection state", tc.method, tc.path)
		}
		if len(resp.TLS.PeerCertificates) == 0 {
			t.Fatalf("%s %s: no peer certificates in TLS handshake", tc.method, tc.path)
		}

		// Verify response headers set by the backend came through the proxy
		if got := resp.Header.Get("X-Backend"); got != "proxyclient" {
			t.Errorf("%s %s: X-Backend header = %q, want %q", tc.method, tc.path, got, "proxyclient")
		}
		if got := resp.Header.Get("X-Request-Method"); got != tc.method {
			t.Errorf("%s %s: X-Request-Method header = %q, want %q", tc.method, tc.path, got, tc.method)
		}
		if got := resp.Header.Get("X-Request-Path"); got != tc.path {
			t.Errorf("%s %s: X-Request-Path header = %q, want %q", tc.method, tc.path, got, tc.path)
		}
	}

	// Verify the backend received all requests (not just proxy returning canned data)
	mu.Lock()
	defer mu.Unlock()

	if len(hits) != len(requests) {
		t.Fatalf("expected backend to receive %d requests, got %d", len(requests), len(hits))
	}

	for i, tc := range requests {
		hit := hits[i]
		if hit.Method != tc.method {
			t.Errorf("request %d: backend saw method %q, want %q", i, hit.Method, tc.method)
		}
		if hit.Path != tc.path {
			t.Errorf("request %d: backend saw path %q, want %q", i, hit.Path, tc.path)
		}
		if hit.XForwardedFor == "" {
			t.Errorf("request %d: backend saw empty X-Forwarded-For", i)
		}
		if hit.XForwardedHost != subdomainHost {
			t.Errorf("request %d: backend saw X-Forwarded-Host %q, want %q", i, hit.XForwardedHost, subdomainHost)
		}
		if hit.XForwardedProto != "https" {
			t.Errorf("request %d: backend saw X-Forwarded-Proto %q, want %q", i, hit.XForwardedProto, "https")
		}
	}

	t.Logf("proxy forwarding with TLS verified: backend received all %d requests through real TLS termination", len(hits))
}
