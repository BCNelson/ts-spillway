package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/bcnelson/ts-spillway/internal/auth"
	"github.com/bcnelson/ts-spillway/internal/certmanager"
	"github.com/bcnelson/ts-spillway/internal/config"
	"github.com/bcnelson/ts-spillway/internal/proxy"
	"github.com/bcnelson/ts-spillway/internal/registry"
	"github.com/bcnelson/ts-spillway/internal/router"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const baseDomain = "test.spillway.io"

// integrationEnv bundles all the real components wired together.
type integrationEnv struct {
	mr       *miniredis.Miniredis
	store    *registry.RedisStore
	srv      *Server
	apiTS    *httptest.Server // serves the API mux
	proxyTS  *httptest.Server // serves the proxy handler
	mockAuth *mockIdentifier
}

func setupIntegration(t *testing.T) *integrationEnv {
	t.Helper()

	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	store := registry.NewRedisStore(client, 90*time.Second)

	cfg := &config.ServerConfig{
		BaseDomain: baseDomain,
	}
	logger := slog.Default()
	certMgr := certmanager.NewManager(&noopCertStore{}, &noopCertIssuer{}, logger)
	rtr := router.NewRouter(baseDomain)
	proxyHandler := proxy.NewProxy(store, rtr, logger)

	mockAuth := &mockIdentifier{
		identifyFn: func(_ *http.Request) (*auth.Identity, error) {
			return nil, fmt.Errorf("no identity configured")
		},
	}

	srv := &Server{
		cfg:          cfg,
		store:        store,
		certMgr:      certMgr,
		authn:        mockAuth,
		proxyHandler: proxyHandler,
		logger:       logger,
	}

	apiMux := http.NewServeMux()
	apiMux.HandleFunc("/api/v1/register", srv.handleRegister)
	apiMux.HandleFunc("/api/v1/heartbeat", srv.handleHeartbeat)
	apiMux.HandleFunc("/api/v1/deregister", srv.handleDeregister)
	apiMux.HandleFunc("/api/v1/status", srv.handleStatus)

	apiTS := httptest.NewServer(apiMux)
	t.Cleanup(apiTS.Close)

	proxyTS := httptest.NewServer(proxyHandler)
	t.Cleanup(proxyTS.Close)

	return &integrationEnv{
		mr:       mr,
		store:    store,
		srv:      srv,
		apiTS:    apiTS,
		proxyTS:  proxyTS,
		mockAuth: mockAuth,
	}
}

// setIdentity configures the mock authenticator to return the given identity.
func (e *integrationEnv) setIdentity(id *auth.Identity) {
	e.mockAuth.identifyFn = func(_ *http.Request) (*auth.Identity, error) {
		return id, nil
	}
}

// setAuthError configures the mock authenticator to return an error.
func (e *integrationEnv) setAuthError() {
	e.mockAuth.identifyFn = func(_ *http.Request) (*auth.Identity, error) {
		return nil, fmt.Errorf("unauthenticated")
	}
}

// apiPost sends a POST with JSON body to the API server.
func (e *integrationEnv) apiPost(t *testing.T, path string, body any) *http.Response {
	t.Helper()
	data, err := json.Marshal(body)
	require.NoError(t, err)
	resp, err := http.Post(e.apiTS.URL+path, "application/json", bytes.NewReader(data))
	require.NoError(t, err)
	return resp
}

// apiGet sends a GET to the API server.
func (e *integrationEnv) apiGet(t *testing.T, path string) *http.Response {
	t.Helper()
	resp, err := http.Get(e.apiTS.URL + path)
	require.NoError(t, err)
	return resp
}

// proxyGet sends a GET to the proxy server with the given Host header.
func (e *integrationEnv) proxyGet(t *testing.T, host, path string) *http.Response {
	t.Helper()
	u, err := url.Parse(e.proxyTS.URL + path)
	require.NoError(t, err)
	req, err := http.NewRequest(http.MethodGet, u.String(), nil)
	require.NoError(t, err)
	req.Host = host
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	return resp
}

// decodeJSON reads and decodes the response body into v.
func decodeJSON(t *testing.T, resp *http.Response, v any) {
	t.Helper()
	defer func() { _ = resp.Body.Close() }()
	require.NoError(t, json.NewDecoder(resp.Body).Decode(v))
}

// --- Registration lifecycle ---

func TestIntegration_FullLifecycle(t *testing.T) {
	env := setupIntegration(t)
	id := testIdentity()
	env.setIdentity(id)

	// Register
	resp := env.apiPost(t, "/api/v1/register", registerRequest{Ports: []int{8080}})
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var regResp registerResponse
	decodeJSON(t, resp, &regResp)
	assert.Len(t, regResp.URLs, 2)

	// Status should show the registration
	resp = env.apiGet(t, "/api/v1/status")
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var statusResp statusResponse
	decodeJSON(t, resp, &statusResp)
	require.Len(t, statusResp.Registrations, 1)
	assert.Equal(t, 8080, statusResp.Registrations[0].Port)

	// Heartbeat should succeed
	resp = env.apiPost(t, "/api/v1/heartbeat", heartbeatRequest{Ports: []int{8080}})
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	_ = resp.Body.Close()

	// Deregister
	resp = env.apiPost(t, "/api/v1/deregister", deregisterRequest{Ports: []int{8080}})
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	_ = resp.Body.Close()

	// Status should now be empty
	resp = env.apiGet(t, "/api/v1/status")
	require.Equal(t, http.StatusOK, resp.StatusCode)
	decodeJSON(t, resp, &statusResp)
	assert.Empty(t, statusResp.Registrations)
}

func TestIntegration_DuplicateRegisterIsIdempotent(t *testing.T) {
	env := setupIntegration(t)
	env.setIdentity(testIdentity())

	// Register the same port twice
	resp := env.apiPost(t, "/api/v1/register", registerRequest{Ports: []int{8080}})
	require.Equal(t, http.StatusOK, resp.StatusCode)
	_ = resp.Body.Close()

	resp = env.apiPost(t, "/api/v1/register", registerRequest{Ports: []int{8080}})
	require.Equal(t, http.StatusOK, resp.StatusCode)
	_ = resp.Body.Close()

	// Status should show exactly one registration (not two)
	resp = env.apiGet(t, "/api/v1/status")
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var statusResp statusResponse
	decodeJSON(t, resp, &statusResp)
	assert.Len(t, statusResp.Registrations, 1)
}

// --- TTL expiration ---

func TestIntegration_TTLExpiration(t *testing.T) {
	env := setupIntegration(t)
	env.setIdentity(testIdentity())

	resp := env.apiPost(t, "/api/v1/register", registerRequest{Ports: []int{8080}})
	require.Equal(t, http.StatusOK, resp.StatusCode)
	_ = resp.Body.Close()

	// Fast-forward past the 90s TTL
	env.mr.FastForward(91 * time.Second)

	// Status should be empty because the registration expired
	resp = env.apiGet(t, "/api/v1/status")
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var statusResp statusResponse
	decodeJSON(t, resp, &statusResp)
	assert.Empty(t, statusResp.Registrations)
}

func TestIntegration_HeartbeatExtendsTTL(t *testing.T) {
	env := setupIntegration(t)
	env.setIdentity(testIdentity())

	resp := env.apiPost(t, "/api/v1/register", registerRequest{Ports: []int{8080}})
	require.Equal(t, http.StatusOK, resp.StatusCode)
	_ = resp.Body.Close()

	// Advance to 80s (within the 90s TTL)
	env.mr.FastForward(80 * time.Second)

	// Heartbeat resets TTL to 90s from now
	resp = env.apiPost(t, "/api/v1/heartbeat", heartbeatRequest{Ports: []int{8080}})
	require.Equal(t, http.StatusOK, resp.StatusCode)
	_ = resp.Body.Close()

	// Advance another 80s — 160s total, which would expire without heartbeat
	env.mr.FastForward(80 * time.Second)

	// Should still be alive because heartbeat reset the TTL
	resp = env.apiGet(t, "/api/v1/status")
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var statusResp statusResponse
	decodeJSON(t, resp, &statusResp)
	require.Len(t, statusResp.Registrations, 1)
	assert.Equal(t, 8080, statusResp.Registrations[0].Port)
}

// --- Proxy end-to-end ---

func TestIntegration_ProxyToBackend(t *testing.T) {
	env := setupIntegration(t)

	// Start a real backend that the proxy will forward to
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Backend", "reached")
		_, _ = fmt.Fprint(w, "hello from backend")
	}))
	t.Cleanup(backend.Close)

	// Parse the backend's ephemeral port
	backendURL, err := url.Parse(backend.URL)
	require.NoError(t, err)
	var backendPort int
	_, err = fmt.Sscanf(backendURL.Port(), "%d", &backendPort)
	require.NoError(t, err)

	// Set identity with TailscaleIP=127.0.0.1 so proxy connects to localhost
	id := &auth.Identity{
		UserID:      "42",
		LoginName:   "alice",
		DisplayName: "Alice Smith",
		MachineName: "laptop",
		TailscaleIP: "127.0.0.1",
	}
	env.setIdentity(id)

	// Register the backend's port via the API
	resp := env.apiPost(t, "/api/v1/register", registerRequest{Ports: []int{backendPort}})
	require.Equal(t, http.StatusOK, resp.StatusCode)
	_ = resp.Body.Close()

	// Proxy request using subdomain format: <port>.laptop.alice.test.spillway.io
	host := fmt.Sprintf("%d.laptop.alice.%s", backendPort, baseDomain)
	resp = env.proxyGet(t, host, "/some/path")
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "reached", resp.Header.Get("X-Backend"))

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, "hello from backend", string(body))
}

func TestIntegration_ProxyForwardsHeaders(t *testing.T) {
	env := setupIntegration(t)

	var receivedHeaders http.Header
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedHeaders = r.Header.Clone()
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(backend.Close)

	backendURL, err := url.Parse(backend.URL)
	require.NoError(t, err)
	var backendPort int
	_, err = fmt.Sscanf(backendURL.Port(), "%d", &backendPort)
	require.NoError(t, err)

	id := &auth.Identity{
		UserID:      "42",
		LoginName:   "alice",
		DisplayName: "Alice Smith",
		MachineName: "laptop",
		TailscaleIP: "127.0.0.1",
	}
	env.setIdentity(id)

	resp := env.apiPost(t, "/api/v1/register", registerRequest{Ports: []int{backendPort}})
	require.Equal(t, http.StatusOK, resp.StatusCode)
	_ = resp.Body.Close()

	host := fmt.Sprintf("%d.laptop.alice.%s", backendPort, baseDomain)
	resp = env.proxyGet(t, host, "/")
	_ = resp.Body.Close()

	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.NotEmpty(t, receivedHeaders.Get("X-Forwarded-For"))
	assert.Equal(t, host, receivedHeaders.Get("X-Forwarded-Host"))
	assert.Equal(t, "https", receivedHeaders.Get("X-Forwarded-Proto"))
}

func TestIntegration_ProxyReturns404AfterDeregister(t *testing.T) {
	env := setupIntegration(t)

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprint(w, "should not reach here")
	}))
	t.Cleanup(backend.Close)

	backendURL, err := url.Parse(backend.URL)
	require.NoError(t, err)
	var backendPort int
	_, err = fmt.Sscanf(backendURL.Port(), "%d", &backendPort)
	require.NoError(t, err)

	id := &auth.Identity{
		UserID:      "42",
		LoginName:   "alice",
		DisplayName: "Alice Smith",
		MachineName: "laptop",
		TailscaleIP: "127.0.0.1",
	}
	env.setIdentity(id)

	// Register and then deregister
	resp := env.apiPost(t, "/api/v1/register", registerRequest{Ports: []int{backendPort}})
	require.Equal(t, http.StatusOK, resp.StatusCode)
	_ = resp.Body.Close()

	resp = env.apiPost(t, "/api/v1/deregister", deregisterRequest{Ports: []int{backendPort}})
	require.Equal(t, http.StatusOK, resp.StatusCode)
	_ = resp.Body.Close()

	// Proxy should 404
	host := fmt.Sprintf("%d.laptop.alice.%s", backendPort, baseDomain)
	resp = env.proxyGet(t, host, "/")
	_ = resp.Body.Close()
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

func TestIntegration_ProxyReturns404AfterTTLExpiry(t *testing.T) {
	env := setupIntegration(t)

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprint(w, "should not reach here")
	}))
	t.Cleanup(backend.Close)

	backendURL, err := url.Parse(backend.URL)
	require.NoError(t, err)
	var backendPort int
	_, err = fmt.Sscanf(backendURL.Port(), "%d", &backendPort)
	require.NoError(t, err)

	id := &auth.Identity{
		UserID:      "42",
		LoginName:   "alice",
		DisplayName: "Alice Smith",
		MachineName: "laptop",
		TailscaleIP: "127.0.0.1",
	}
	env.setIdentity(id)

	resp := env.apiPost(t, "/api/v1/register", registerRequest{Ports: []int{backendPort}})
	require.Equal(t, http.StatusOK, resp.StatusCode)
	_ = resp.Body.Close()

	// Fast-forward past TTL
	env.mr.FastForward(91 * time.Second)

	// Proxy should 404
	host := fmt.Sprintf("%d.laptop.alice.%s", backendPort, baseDomain)
	resp = env.proxyGet(t, host, "/")
	_ = resp.Body.Close()
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

// --- Multi-user isolation ---

func TestIntegration_MultiUserIsolation(t *testing.T) {
	env := setupIntegration(t)

	alice := &auth.Identity{
		UserID:      "1",
		LoginName:   "alice",
		DisplayName: "Alice",
		MachineName: "laptop",
		TailscaleIP: "100.64.0.1",
	}
	bob := &auth.Identity{
		UserID:      "2",
		LoginName:   "bob",
		DisplayName: "Bob",
		MachineName: "laptop",
		TailscaleIP: "100.64.0.2",
	}

	// Alice registers port 8080
	env.setIdentity(alice)
	resp := env.apiPost(t, "/api/v1/register", registerRequest{Ports: []int{8080}})
	require.Equal(t, http.StatusOK, resp.StatusCode)
	_ = resp.Body.Close()

	// Bob registers port 8080 (same port, different user)
	env.setIdentity(bob)
	resp = env.apiPost(t, "/api/v1/register", registerRequest{Ports: []int{8080}})
	require.Equal(t, http.StatusOK, resp.StatusCode)
	_ = resp.Body.Close()

	// Alice's status should show only her registration
	env.setIdentity(alice)
	resp = env.apiGet(t, "/api/v1/status")
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var aliceStatus statusResponse
	decodeJSON(t, resp, &aliceStatus)
	require.Len(t, aliceStatus.Registrations, 1)
	assert.Equal(t, 8080, aliceStatus.Registrations[0].Port)

	// Bob's status should show only his registration
	env.setIdentity(bob)
	resp = env.apiGet(t, "/api/v1/status")
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var bobStatus statusResponse
	decodeJSON(t, resp, &bobStatus)
	require.Len(t, bobStatus.Registrations, 1)
	assert.Equal(t, 8080, bobStatus.Registrations[0].Port)

	// Deregistering Alice's port should not affect Bob's
	env.setIdentity(alice)
	resp = env.apiPost(t, "/api/v1/deregister", deregisterRequest{Ports: []int{8080}})
	require.Equal(t, http.StatusOK, resp.StatusCode)
	_ = resp.Body.Close()

	env.setIdentity(alice)
	resp = env.apiGet(t, "/api/v1/status")
	require.Equal(t, http.StatusOK, resp.StatusCode)
	decodeJSON(t, resp, &aliceStatus)
	assert.Empty(t, aliceStatus.Registrations)

	env.setIdentity(bob)
	resp = env.apiGet(t, "/api/v1/status")
	require.Equal(t, http.StatusOK, resp.StatusCode)
	decodeJSON(t, resp, &bobStatus)
	require.Len(t, bobStatus.Registrations, 1)
}

func TestIntegration_MultiUserProxyRouting(t *testing.T) {
	env := setupIntegration(t)

	// Backend for Alice
	aliceBackend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprint(w, "alice-backend")
	}))
	t.Cleanup(aliceBackend.Close)

	aliceURL, err := url.Parse(aliceBackend.URL)
	require.NoError(t, err)
	var alicePort int
	_, err = fmt.Sscanf(aliceURL.Port(), "%d", &alicePort)
	require.NoError(t, err)

	// Backend for Bob
	bobBackend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprint(w, "bob-backend")
	}))
	t.Cleanup(bobBackend.Close)

	bobURL, err := url.Parse(bobBackend.URL)
	require.NoError(t, err)
	var bobPort int
	_, err = fmt.Sscanf(bobURL.Port(), "%d", &bobPort)
	require.NoError(t, err)

	alice := &auth.Identity{
		UserID:      "1",
		LoginName:   "alice",
		DisplayName: "Alice",
		MachineName: "laptop",
		TailscaleIP: "127.0.0.1",
	}
	bob := &auth.Identity{
		UserID:      "2",
		LoginName:   "bob",
		DisplayName: "Bob",
		MachineName: "desktop",
		TailscaleIP: "127.0.0.1",
	}

	// Register Alice
	env.setIdentity(alice)
	resp := env.apiPost(t, "/api/v1/register", registerRequest{Ports: []int{alicePort}})
	require.Equal(t, http.StatusOK, resp.StatusCode)
	_ = resp.Body.Close()

	// Register Bob
	env.setIdentity(bob)
	resp = env.apiPost(t, "/api/v1/register", registerRequest{Ports: []int{bobPort}})
	require.Equal(t, http.StatusOK, resp.StatusCode)
	_ = resp.Body.Close()

	// Proxy to Alice's backend
	aliceHost := fmt.Sprintf("%d.laptop.alice.%s", alicePort, baseDomain)
	resp = env.proxyGet(t, aliceHost, "/")
	body, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	require.NoError(t, err)
	assert.Equal(t, "alice-backend", string(body))

	// Proxy to Bob's backend
	bobHost := fmt.Sprintf("%d.desktop.bob.%s", bobPort, baseDomain)
	resp = env.proxyGet(t, bobHost, "/")
	body, err = io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	require.NoError(t, err)
	assert.Equal(t, "bob-backend", string(body))
}

// --- Error flows ---

func TestIntegration_UnauthenticatedRegister(t *testing.T) {
	env := setupIntegration(t)
	env.setAuthError()

	resp := env.apiPost(t, "/api/v1/register", registerRequest{Ports: []int{8080}})
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestIntegration_UnauthenticatedHeartbeat(t *testing.T) {
	env := setupIntegration(t)
	env.setAuthError()

	resp := env.apiPost(t, "/api/v1/heartbeat", heartbeatRequest{Ports: []int{8080}})
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestIntegration_UnauthenticatedDeregister(t *testing.T) {
	env := setupIntegration(t)
	env.setAuthError()

	resp := env.apiPost(t, "/api/v1/deregister", deregisterRequest{Ports: []int{8080}})
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestIntegration_UnauthenticatedStatus(t *testing.T) {
	env := setupIntegration(t)
	env.setAuthError()

	resp := env.apiGet(t, "/api/v1/status")
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestIntegration_ProxyToUnregisteredHost(t *testing.T) {
	env := setupIntegration(t)

	// No registrations exist — proxy should return 404
	host := fmt.Sprintf("9999.laptop.alice.%s", baseDomain)
	resp := env.proxyGet(t, host, "/")
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

// --- Multi-port registration ---

func TestIntegration_MultiplePortsRegistration(t *testing.T) {
	env := setupIntegration(t)
	env.setIdentity(testIdentity())

	// Register multiple ports at once
	resp := env.apiPost(t, "/api/v1/register", registerRequest{Ports: []int{8080, 8081, 8082}})
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var regResp registerResponse
	decodeJSON(t, resp, &regResp)
	assert.Len(t, regResp.URLs, 6) // 3 ports × 2 URL formats

	// Status should show all three
	resp = env.apiGet(t, "/api/v1/status")
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var statusResp statusResponse
	decodeJSON(t, resp, &statusResp)
	assert.Len(t, statusResp.Registrations, 3)

	ports := map[int]bool{}
	for _, reg := range statusResp.Registrations {
		ports[reg.Port] = true
	}
	assert.True(t, ports[8080])
	assert.True(t, ports[8081])
	assert.True(t, ports[8082])
}
