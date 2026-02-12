package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/bcnelson/ts-spillway/internal/auth"
	"github.com/bcnelson/ts-spillway/internal/certmanager"
	"github.com/bcnelson/ts-spillway/internal/config"
	"github.com/bcnelson/ts-spillway/internal/registry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- local mocks ---

type mockIdentifier struct {
	identifyFn func(r *http.Request) (*auth.Identity, error)
}

func (m *mockIdentifier) Identify(r *http.Request) (*auth.Identity, error) {
	return m.identifyFn(r)
}

type mockStore struct {
	registerFn         func(ctx context.Context, user, machine string, port int, tailscaleIP string) error
	deregisterFn       func(ctx context.Context, user, machine string, port int) error
	refreshHeartbeatFn func(ctx context.Context, user, machine string, ports []int) error
	lookupFn           func(ctx context.Context, user, machine string, port int) (string, error)
	listByMachineFn    func(ctx context.Context, user, machine string) ([]registry.Registration, error)
	saveUserFn         func(ctx context.Context, tailscaleID, loginName, displayName string) error
	saveMachineFn      func(ctx context.Context, user, machineName, tailscaleIP string) error
}

func (m *mockStore) Register(ctx context.Context, user, machine string, port int, ip string) error {
	if m.registerFn != nil {
		return m.registerFn(ctx, user, machine, port, ip)
	}
	return nil
}
func (m *mockStore) Deregister(ctx context.Context, user, machine string, port int) error {
	if m.deregisterFn != nil {
		return m.deregisterFn(ctx, user, machine, port)
	}
	return nil
}
func (m *mockStore) RefreshHeartbeat(ctx context.Context, user, machine string, ports []int) error {
	if m.refreshHeartbeatFn != nil {
		return m.refreshHeartbeatFn(ctx, user, machine, ports)
	}
	return nil
}
func (m *mockStore) Lookup(ctx context.Context, user, machine string, port int) (string, error) {
	if m.lookupFn != nil {
		return m.lookupFn(ctx, user, machine, port)
	}
	return "", nil
}
func (m *mockStore) ListByMachine(ctx context.Context, user, machine string) ([]registry.Registration, error) {
	if m.listByMachineFn != nil {
		return m.listByMachineFn(ctx, user, machine)
	}
	return nil, nil
}
func (m *mockStore) SaveUser(ctx context.Context, id, login, display string) error {
	if m.saveUserFn != nil {
		return m.saveUserFn(ctx, id, login, display)
	}
	return nil
}
func (m *mockStore) SaveMachine(ctx context.Context, user, machine, ip string) error {
	if m.saveMachineFn != nil {
		return m.saveMachineFn(ctx, user, machine, ip)
	}
	return nil
}

var _ registry.Store = (*mockStore)(nil)
var _ Identifier = (*mockIdentifier)(nil)

// --- helpers ---

func testIdentity() *auth.Identity {
	return &auth.Identity{
		UserID:      "42",
		LoginName:   "alice",
		DisplayName: "Alice Smith",
		MachineName: "laptop",
		TailscaleIP: "100.64.0.1",
	}
}

func newTestServer(authn Identifier, store registry.Store) *Server {
	return &Server{
		cfg: &config.ServerConfig{
			BaseDomain: "spillway.redo.run",
		},
		store:   store,
		certMgr: certmanager.NewManager(&noopCertStore{}, &noopCertIssuer{}, slog.Default()),
		authn:   authn,
		logger:  slog.Default(),
	}
}

// noopCertStore satisfies certmanager.CertStore for handler tests.
type noopCertStore struct{}

func (n *noopCertStore) GetCert(context.Context, string) (*certmanager.StoredCert, error) {
	return nil, nil
}
func (n *noopCertStore) SaveCert(context.Context, string, []byte, []byte, time.Time) error {
	return nil
}
func (n *noopCertStore) ListExpiring(context.Context, time.Time) ([]string, error) {
	return nil, nil
}

// noopCertIssuer satisfies certmanager.CertIssuer for handler tests.
type noopCertIssuer struct{}

func (n *noopCertIssuer) Issue(context.Context, string) ([]byte, []byte, time.Time, error) {
	return nil, nil, time.Time{}, nil
}

// --- register handler tests ---

func TestHandleRegister_Success(t *testing.T) {
	var registered []int
	store := &mockStore{
		registerFn: func(_ context.Context, _, _ string, port int, _ string) error {
			registered = append(registered, port)
			return nil
		},
	}
	authn := &mockIdentifier{identifyFn: func(_ *http.Request) (*auth.Identity, error) {
		return testIdentity(), nil
	}}

	srv := newTestServer(authn, store)
	body, _ := json.Marshal(registerRequest{Ports: []int{8080, 8081}})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/register", bytes.NewReader(body))
	rr := httptest.NewRecorder()

	srv.handleRegister(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, []int{8080, 8081}, registered)

	var resp registerResponse
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&resp))
	assert.Len(t, resp.URLs, 4) // 2 ports × 2 URL formats
}

func TestHandleRegister_MethodNotAllowed(t *testing.T) {
	srv := newTestServer(&mockIdentifier{}, &mockStore{})
	req := httptest.NewRequest(http.MethodGet, "/api/v1/register", nil)
	rr := httptest.NewRecorder()

	srv.handleRegister(rr, req)

	assert.Equal(t, http.StatusMethodNotAllowed, rr.Code)
}

func TestHandleRegister_AuthFailure(t *testing.T) {
	authn := &mockIdentifier{identifyFn: func(_ *http.Request) (*auth.Identity, error) {
		return nil, fmt.Errorf("not on tailnet")
	}}

	srv := newTestServer(authn, &mockStore{})
	body, _ := json.Marshal(registerRequest{Ports: []int{8080}})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/register", bytes.NewReader(body))
	rr := httptest.NewRecorder()

	srv.handleRegister(rr, req)

	assert.Equal(t, http.StatusUnauthorized, rr.Code)
}

func TestHandleRegister_InvalidBody(t *testing.T) {
	authn := &mockIdentifier{identifyFn: func(_ *http.Request) (*auth.Identity, error) {
		return testIdentity(), nil
	}}

	srv := newTestServer(authn, &mockStore{})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/register", bytes.NewReader([]byte("not json")))
	rr := httptest.NewRecorder()

	srv.handleRegister(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestHandleRegister_StoreError(t *testing.T) {
	store := &mockStore{
		registerFn: func(context.Context, string, string, int, string) error {
			return fmt.Errorf("redis down")
		},
	}
	authn := &mockIdentifier{identifyFn: func(_ *http.Request) (*auth.Identity, error) {
		return testIdentity(), nil
	}}

	srv := newTestServer(authn, store)
	body, _ := json.Marshal(registerRequest{Ports: []int{8080}})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/register", bytes.NewReader(body))
	rr := httptest.NewRecorder()

	srv.handleRegister(rr, req)

	assert.Equal(t, http.StatusInternalServerError, rr.Code)
}

// --- heartbeat handler tests ---

func TestHandleHeartbeat_Success(t *testing.T) {
	var refreshedPorts []int
	store := &mockStore{
		refreshHeartbeatFn: func(_ context.Context, _, _ string, ports []int) error {
			refreshedPorts = ports
			return nil
		},
	}
	authn := &mockIdentifier{identifyFn: func(_ *http.Request) (*auth.Identity, error) {
		return testIdentity(), nil
	}}

	srv := newTestServer(authn, store)
	body, _ := json.Marshal(heartbeatRequest{Ports: []int{8080, 8081}})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/heartbeat", bytes.NewReader(body))
	rr := httptest.NewRecorder()

	srv.handleHeartbeat(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, []int{8080, 8081}, refreshedPorts)
}

func TestHandleHeartbeat_MethodNotAllowed(t *testing.T) {
	srv := newTestServer(&mockIdentifier{}, &mockStore{})
	req := httptest.NewRequest(http.MethodGet, "/api/v1/heartbeat", nil)
	rr := httptest.NewRecorder()

	srv.handleHeartbeat(rr, req)

	assert.Equal(t, http.StatusMethodNotAllowed, rr.Code)
}

func TestHandleHeartbeat_AuthFailure(t *testing.T) {
	authn := &mockIdentifier{identifyFn: func(_ *http.Request) (*auth.Identity, error) {
		return nil, fmt.Errorf("denied")
	}}

	srv := newTestServer(authn, &mockStore{})
	body, _ := json.Marshal(heartbeatRequest{Ports: []int{8080}})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/heartbeat", bytes.NewReader(body))
	rr := httptest.NewRecorder()

	srv.handleHeartbeat(rr, req)

	assert.Equal(t, http.StatusUnauthorized, rr.Code)
}

func TestHandleHeartbeat_StoreError(t *testing.T) {
	store := &mockStore{
		refreshHeartbeatFn: func(context.Context, string, string, []int) error {
			return fmt.Errorf("redis down")
		},
	}
	authn := &mockIdentifier{identifyFn: func(_ *http.Request) (*auth.Identity, error) {
		return testIdentity(), nil
	}}

	srv := newTestServer(authn, store)
	body, _ := json.Marshal(heartbeatRequest{Ports: []int{8080}})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/heartbeat", bytes.NewReader(body))
	rr := httptest.NewRecorder()

	srv.handleHeartbeat(rr, req)

	assert.Equal(t, http.StatusInternalServerError, rr.Code)
}

// --- deregister handler tests ---

func TestHandleDeregister_Success(t *testing.T) {
	var deregistered []int
	store := &mockStore{
		deregisterFn: func(_ context.Context, _, _ string, port int) error {
			deregistered = append(deregistered, port)
			return nil
		},
	}
	authn := &mockIdentifier{identifyFn: func(_ *http.Request) (*auth.Identity, error) {
		return testIdentity(), nil
	}}

	srv := newTestServer(authn, store)
	body, _ := json.Marshal(deregisterRequest{Ports: []int{8080}})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/deregister", bytes.NewReader(body))
	rr := httptest.NewRecorder()

	srv.handleDeregister(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, []int{8080}, deregistered)
}

func TestHandleDeregister_MethodNotAllowed(t *testing.T) {
	srv := newTestServer(&mockIdentifier{}, &mockStore{})
	req := httptest.NewRequest(http.MethodGet, "/api/v1/deregister", nil)
	rr := httptest.NewRecorder()

	srv.handleDeregister(rr, req)

	assert.Equal(t, http.StatusMethodNotAllowed, rr.Code)
}

func TestHandleDeregister_AuthFailure(t *testing.T) {
	authn := &mockIdentifier{identifyFn: func(_ *http.Request) (*auth.Identity, error) {
		return nil, fmt.Errorf("denied")
	}}

	srv := newTestServer(authn, &mockStore{})
	body, _ := json.Marshal(deregisterRequest{Ports: []int{8080}})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/deregister", bytes.NewReader(body))
	rr := httptest.NewRecorder()

	srv.handleDeregister(rr, req)

	assert.Equal(t, http.StatusUnauthorized, rr.Code)
}

// --- status handler tests ---

func TestHandleStatus_Success(t *testing.T) {
	store := &mockStore{
		listByMachineFn: func(_ context.Context, _, _ string) ([]registry.Registration, error) {
			return []registry.Registration{
				{User: "alice", Machine: "laptop", Port: 8080, TailscaleIP: "100.64.0.1", ExpiresAt: time.Now().Add(60 * time.Second)},
			}, nil
		},
	}
	authn := &mockIdentifier{identifyFn: func(_ *http.Request) (*auth.Identity, error) {
		return testIdentity(), nil
	}}

	srv := newTestServer(authn, store)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/status", nil)
	rr := httptest.NewRecorder()

	srv.handleStatus(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	var resp statusResponse
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&resp))
	require.Len(t, resp.Registrations, 1)
	assert.Equal(t, 8080, resp.Registrations[0].Port)
	assert.Len(t, resp.Registrations[0].URLs, 2)
}

func TestHandleStatus_MethodNotAllowed(t *testing.T) {
	srv := newTestServer(&mockIdentifier{}, &mockStore{})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/status", nil)
	rr := httptest.NewRecorder()

	srv.handleStatus(rr, req)

	assert.Equal(t, http.StatusMethodNotAllowed, rr.Code)
}

func TestHandleStatus_AuthFailure(t *testing.T) {
	authn := &mockIdentifier{identifyFn: func(_ *http.Request) (*auth.Identity, error) {
		return nil, fmt.Errorf("denied")
	}}

	srv := newTestServer(authn, &mockStore{})
	req := httptest.NewRequest(http.MethodGet, "/api/v1/status", nil)
	rr := httptest.NewRecorder()

	srv.handleStatus(rr, req)

	assert.Equal(t, http.StatusUnauthorized, rr.Code)
}

func TestHandleStatus_StoreError(t *testing.T) {
	store := &mockStore{
		listByMachineFn: func(context.Context, string, string) ([]registry.Registration, error) {
			return nil, fmt.Errorf("redis down")
		},
	}
	authn := &mockIdentifier{identifyFn: func(_ *http.Request) (*auth.Identity, error) {
		return testIdentity(), nil
	}}

	srv := newTestServer(authn, store)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/status", nil)
	rr := httptest.NewRecorder()

	srv.handleStatus(rr, req)

	assert.Equal(t, http.StatusInternalServerError, rr.Code)
}
