package proxy

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/bcnelson/ts-spillway/internal/registry"
	"github.com/bcnelson/ts-spillway/internal/router"
	"github.com/stretchr/testify/assert"
)

// mockStore implements registry.Store for proxy tests.
type mockStore struct {
	lookupFn func(ctx context.Context, user, machine string, port int) (string, error)
}

func (m *mockStore) Register(context.Context, string, string, int, string) error { return nil }
func (m *mockStore) Deregister(context.Context, string, string, int) error       { return nil }
func (m *mockStore) RefreshHeartbeat(context.Context, string, string, []int) error {
	return nil
}
func (m *mockStore) Lookup(ctx context.Context, user, machine string, port int) (string, error) {
	if m.lookupFn != nil {
		return m.lookupFn(ctx, user, machine, port)
	}
	return "", nil
}
func (m *mockStore) ListByMachine(context.Context, string, string) ([]registry.Registration, error) {
	return nil, nil
}
func (m *mockStore) SaveUser(context.Context, string, string, string) error    { return nil }
func (m *mockStore) SaveMachine(context.Context, string, string, string) error { return nil }

var _ registry.Store = (*mockStore)(nil)

func TestServeHTTP_Success(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprint(w, "hello from backend")
	}))
	defer backend.Close()

	_, port, _ := splitHostPort(backend.Listener.Addr().String())

	store := &mockStore{
		lookupFn: func(_ context.Context, _, _ string, _ int) (string, error) {
			return "127.0.0.1", nil
		},
	}

	p := NewProxy(store, router.NewRouter("spillway.redo.run"), slog.Default())

	req := httptest.NewRequest("GET", "/path", nil)
	req.Host = fmt.Sprintf("mymachine.alice.spillway.redo.run:%s", port)

	rr := httptest.NewRecorder()
	p.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, "hello from backend", rr.Body.String())
}

func TestServeHTTP_NotFound(t *testing.T) {
	store := &mockStore{
		lookupFn: func(_ context.Context, _, _ string, _ int) (string, error) {
			return "", nil
		},
	}

	p := NewProxy(store, router.NewRouter("spillway.redo.run"), slog.Default())

	req := httptest.NewRequest("GET", "/", nil)
	req.Host = "8000.mymachine.alice.spillway.redo.run"

	rr := httptest.NewRecorder()
	p.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusNotFound, rr.Code)
}

func TestServeHTTP_LookupError(t *testing.T) {
	store := &mockStore{
		lookupFn: func(_ context.Context, _, _ string, _ int) (string, error) {
			return "", fmt.Errorf("redis connection refused")
		},
	}

	p := NewProxy(store, router.NewRouter("spillway.redo.run"), slog.Default())

	req := httptest.NewRequest("GET", "/", nil)
	req.Host = "8000.mymachine.alice.spillway.redo.run"

	rr := httptest.NewRecorder()
	p.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusInternalServerError, rr.Code)
}

func TestServeHTTP_InvalidHost(t *testing.T) {
	p := NewProxy(&mockStore{}, router.NewRouter("spillway.redo.run"), slog.Default())

	req := httptest.NewRequest("GET", "/", nil)
	req.Host = "invalid.example.com"

	rr := httptest.NewRecorder()
	p.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestServeHTTP_ForwardedHeaders(t *testing.T) {
	var gotHeaders http.Header
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHeaders = r.Header.Clone()
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	_, port, _ := splitHostPort(backend.Listener.Addr().String())

	store := &mockStore{
		lookupFn: func(_ context.Context, _, _ string, _ int) (string, error) {
			return "127.0.0.1", nil
		},
	}

	p := NewProxy(store, router.NewRouter("spillway.redo.run"), slog.Default())

	hostHeader := fmt.Sprintf("mymachine.alice.spillway.redo.run:%s", port)
	req := httptest.NewRequest("GET", "/", nil)
	req.Host = hostHeader

	rr := httptest.NewRecorder()
	p.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.NotEmpty(t, gotHeaders.Get("X-Forwarded-For"))
	assert.Equal(t, hostHeader, gotHeaders.Get("X-Forwarded-Host"))
	assert.Equal(t, "https", gotHeaders.Get("X-Forwarded-Proto"))
}

func TestServeHTTP_BackendDown(t *testing.T) {
	// Start and immediately close a backend so the port is known but unreachable.
	backend := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	_, port, _ := splitHostPort(backend.Listener.Addr().String())
	backend.Close()

	store := &mockStore{
		lookupFn: func(_ context.Context, _, _ string, _ int) (string, error) {
			return "127.0.0.1", nil
		},
	}

	p := NewProxy(store, router.NewRouter("spillway.redo.run"), slog.Default())

	req := httptest.NewRequest("GET", "/", nil)
	req.Host = fmt.Sprintf("mymachine.alice.spillway.redo.run:%s", port)

	rr := httptest.NewRecorder()

	// The reverse proxy needs a moment; give it a tight deadline so the test is fast.
	ctx, cancel := context.WithTimeout(req.Context(), 2*time.Second)
	defer cancel()
	p.ServeHTTP(rr, req.WithContext(ctx))

	assert.Equal(t, http.StatusBadGateway, rr.Code)
}

// splitHostPort is a small helper that splits "host:port".
func splitHostPort(addr string) (host, port string, ok bool) {
	for i := len(addr) - 1; i >= 0; i-- {
		if addr[i] == ':' {
			return addr[:i], addr[i+1:], true
		}
	}
	return addr, "", false
}
