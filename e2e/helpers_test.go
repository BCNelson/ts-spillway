//go:build e2e

package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/redis/go-redis/v9"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"

	"tailscale.com/ipn/store/mem"
	"tailscale.com/net/netns"
	"tailscale.com/tailcfg"
	"tailscale.com/tsnet"
	"tailscale.com/tstest/integration"
	"tailscale.com/tstest/integration/testcontrol"
	"tailscale.com/types/logger"

	"github.com/bcnelson/ts-spillway/internal/certmanager"
	"github.com/bcnelson/ts-spillway/internal/config"
	"github.com/bcnelson/ts-spillway/internal/registry"
	"github.com/bcnelson/ts-spillway/internal/server"
)

// e2eEnv holds all the pieces of the end-to-end test environment.
type e2eEnv struct {
	controlURL string
	control    *testcontrol.Server
	mini       *miniredis.Miniredis
	rdb        *redis.Client
	store      *registry.RedisStore
	certStore  *certmanager.RedisCertStore
	certMgr    *certmanager.Manager
	srv        *server.Server
	apiPort    int
}

// startControl creates an in-process Tailscale test control plane with DERP.
// Follows the pattern from tailscale.com/tsnet/tsnet_test.go.
func startControl(t *testing.T) (controlURL string, control *testcontrol.Server) {
	t.Helper()

	netns.SetEnabled(false)
	t.Cleanup(func() {
		netns.SetEnabled(true)
	})

	derpMap := integration.RunDERPAndSTUN(t, logger.Discard, "127.0.0.1")
	control = &testcontrol.Server{
		DERPMap: derpMap,
		DNSConfig: &tailcfg.DNSConfig{
			Proxied: true,
		},
		MagicDNSDomain: "tail-scale.ts.net",
		Logf:           t.Logf,
	}
	control.HTTPTestServer = httptest.NewUnstartedServer(control)
	control.HTTPTestServer.Start()
	t.Cleanup(control.HTTPTestServer.Close)
	controlURL = control.HTTPTestServer.URL
	t.Logf("testcontrol listening on %s", controlURL)
	return controlURL, control
}

// startTSNode creates a tsnet.Server connected to the test control plane.
func startTSNode(t *testing.T, controlURL, hostname string) *tsnet.Server {
	t.Helper()

	tmp := filepath.Join(t.TempDir(), hostname)
	if err := os.MkdirAll(tmp, 0755); err != nil {
		t.Fatal(err)
	}

	s := &tsnet.Server{
		Dir:        tmp,
		ControlURL: controlURL,
		Hostname:   hostname,
		Store:      new(mem.Store),
		Ephemeral:  true,
	}
	t.Cleanup(func() { s.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	status, err := s.Up(ctx)
	if err != nil {
		t.Fatalf("tsnet.Up for %s: %v", hostname, err)
	}
	t.Logf("tsnet node %s up: %v", hostname, status.TailscaleIPs)
	return s
}

// containerNetwork holds info about the shared Docker network for Pebble ↔ challtestsrv.
type containerNetwork struct {
	name            string
	challtestDNSIP  string // container IP for challtestsrv DNS (port 8053)
	challtestAPIURL string // host-mapped URL for challtestsrv management API
}

// startChalltestSrv starts pebble-challtestsrv via testcontainers.
// Returns the Docker network, the container's internal DNS address (for Pebble),
// and the host-mapped management API URL (for our DNS provider).
func startChalltestSrv(t *testing.T, ctx context.Context, networkName string) containerNetwork {
	t.Helper()

	req := testcontainers.ContainerRequest{
		Image:        "ghcr.io/letsencrypt/pebble-challtestsrv:latest",
		ExposedPorts: []string{"8055/tcp"},
		Cmd:          []string{"-defaultIPv4", "0.0.0.0", "-defaultIPv6", "", "-dns01", ":8053", "-management", ":8055"},
		Networks:     []string{networkName},
		WaitingFor:   wait.ForHTTP("/").WithPort("8055/tcp").WithStatusCodeMatcher(func(status int) bool { return true }),
	}

	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		t.Fatalf("starting challtestsrv: %v", err)
	}
	t.Cleanup(func() {
		if err := container.Terminate(context.Background()); err != nil {
			t.Logf("warning: failed to terminate challtestsrv: %v", err)
		}
	})

	mappedPort, err := container.MappedPort(ctx, "8055")
	if err != nil {
		t.Fatalf("getting challtestsrv mapped port: %v", err)
	}

	host, err := container.Host(ctx)
	if err != nil {
		t.Fatalf("getting challtestsrv host: %v", err)
	}

	// Get container IP within the Docker network (for Pebble to use)
	cip, err := container.ContainerIP(ctx)
	if err != nil {
		t.Fatalf("getting challtestsrv container IP: %v", err)
	}

	t.Logf("challtestsrv: management API at %s:%s, DNS at %s:8053", host, mappedPort.Port(), cip)

	return containerNetwork{
		name:            networkName,
		challtestDNSIP:  cip,
		challtestAPIURL: fmt.Sprintf("http://%s:%s", host, mappedPort.Port()),
	}
}

// startPebble starts Pebble (ACME test server) via testcontainers, configured
// to use challtestsrv for DNS validation.
func startPebble(t *testing.T, ctx context.Context, networkName, challtestDNSAddr string) (directoryURL string) {
	t.Helper()

	req := testcontainers.ContainerRequest{
		Image:        "ghcr.io/letsencrypt/pebble:latest",
		ExposedPorts: []string{"14000/tcp"},
		Cmd:          []string{"-dnsserver", challtestDNSAddr},
		Env: map[string]string{
			"PEBBLE_VA_NOSLEEP": "1",
		},
		Networks:   []string{networkName},
		WaitingFor: wait.ForLog("Listening on"),
	}

	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		t.Fatalf("starting pebble: %v", err)
	}
	t.Cleanup(func() {
		if err := container.Terminate(context.Background()); err != nil {
			t.Logf("warning: failed to terminate pebble: %v", err)
		}
	})

	mappedPort, err := container.MappedPort(ctx, "14000")
	if err != nil {
		t.Fatalf("getting pebble mapped port: %v", err)
	}

	host, err := container.Host(ctx)
	if err != nil {
		t.Fatalf("getting pebble host: %v", err)
	}

	// Extract Pebble's test CA cert for lego trust
	reader, err := container.CopyFileFromContainer(ctx, "/test/certs/pebble.minica.pem")
	if err != nil {
		t.Fatalf("copying pebble CA cert: %v", err)
	}
	defer reader.Close()

	caCert, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("reading pebble CA cert: %v", err)
	}

	// Write CA cert to temp file and set LEGO_CA_CERTIFICATES
	caPath := filepath.Join(t.TempDir(), "pebble-ca.pem")
	if err := os.WriteFile(caPath, caCert, 0644); err != nil {
		t.Fatalf("writing pebble CA cert: %v", err)
	}
	t.Setenv("LEGO_CA_CERTIFICATES", caPath)

	directoryURL = fmt.Sprintf("https://%s:%s/dir", host, mappedPort.Port())
	t.Logf("pebble: directory at %s", directoryURL)
	return directoryURL
}

// e2eClient is a simulated spillway client that talks over Tailscale.
type e2eClient struct {
	t          *testing.T
	node       *tsnet.Server
	httpClient *http.Client
	serverAddr string // e.g. "spillway:9090"
}

// newE2EClient creates a tsnet-connected client that routes requests over Tailscale.
func newE2EClient(t *testing.T, controlURL, hostname, serverAddr string) *e2eClient {
	t.Helper()

	node := startTSNode(t, controlURL, hostname)

	httpClient := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return node.Dial(ctx, network, addr)
			},
		},
		Timeout: 30 * time.Second,
	}

	return &e2eClient{
		t:          t,
		node:       node,
		httpClient: httpClient,
		serverAddr: serverAddr,
	}
}

func (c *e2eClient) register(t *testing.T, ports []int) registerResponse {
	t.Helper()
	body, _ := json.Marshal(map[string]any{"ports": ports})
	resp, err := c.httpClient.Post(
		fmt.Sprintf("http://%s/api/v1/register", c.serverAddr),
		"application/json",
		bytes.NewReader(body),
	)
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		t.Fatalf("register: status %d: %s", resp.StatusCode, respBody)
	}
	var result registerResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("register: decode: %v", err)
	}
	return result
}

func (c *e2eClient) heartbeat(t *testing.T, ports []int) {
	t.Helper()
	body, _ := json.Marshal(map[string]any{"ports": ports})
	resp, err := c.httpClient.Post(
		fmt.Sprintf("http://%s/api/v1/heartbeat", c.serverAddr),
		"application/json",
		bytes.NewReader(body),
	)
	if err != nil {
		t.Fatalf("heartbeat: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		t.Fatalf("heartbeat: status %d: %s", resp.StatusCode, respBody)
	}
}

func (c *e2eClient) deregister(t *testing.T, ports []int) {
	t.Helper()
	body, _ := json.Marshal(map[string]any{"ports": ports})
	resp, err := c.httpClient.Post(
		fmt.Sprintf("http://%s/api/v1/deregister", c.serverAddr),
		"application/json",
		bytes.NewReader(body),
	)
	if err != nil {
		t.Fatalf("deregister: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		t.Fatalf("deregister: status %d: %s", resp.StatusCode, respBody)
	}
}

func (c *e2eClient) status(t *testing.T) statusResponse {
	t.Helper()
	resp, err := c.httpClient.Get(
		fmt.Sprintf("http://%s/api/v1/status", c.serverAddr),
	)
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		t.Fatalf("status: status %d: %s", resp.StatusCode, respBody)
	}
	var result statusResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("status: decode: %v", err)
	}
	return result
}

// API response types (mirrors server types)
type registerResponse struct {
	URLs []string `json:"urls"`
}

type statusResponse struct {
	Registrations []registrationInfo `json:"registrations"`
}

type registrationInfo struct {
	Port      int       `json:"port"`
	URLs      []string  `json:"urls"`
	ExpiresAt time.Time `json:"expires_at"`
}

// setupE2E wires up the full end-to-end test environment.
func setupE2E(t *testing.T) *e2eEnv {
	t.Helper()

	ctx := context.Background()

	// 1. Start testcontrol + DERP
	controlURL, control := startControl(t)

	// 2. Create shared Docker network
	networkName := fmt.Sprintf("e2e-test-%d", time.Now().UnixNano())
	network, err := testcontainers.GenericNetwork(ctx, testcontainers.GenericNetworkRequest{
		NetworkRequest: testcontainers.NetworkRequest{
			Name: networkName,
		},
	})
	if err != nil {
		t.Fatalf("creating docker network: %v", err)
	}
	t.Cleanup(func() {
		if err := network.Remove(context.Background()); err != nil {
			t.Logf("warning: failed to remove docker network: %v", err)
		}
	})

	// 3. Start challtestsrv
	cn := startChalltestSrv(t, ctx, networkName)

	// 4. Start Pebble pointed at challtestsrv DNS
	pebbleDir := startPebble(t, ctx, networkName, cn.challtestDNSIP+":8053")

	// 5. In-memory Redis
	mini := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mini.Addr()})
	t.Cleanup(func() { rdb.Close() })

	// 6. Create stores
	store := registry.NewRedisStore(rdb, 90*time.Second)
	certStore := certmanager.NewRedisCertStore(rdb)

	// 7. Create ACME issuer with challtestsrv DNS provider + Pebble directory
	dnsProvider := newChalltestProvider(cn.challtestAPIURL)
	issuer, err := certmanager.NewACMEIssuer(
		"test@example.com",
		pebbleDir,
		dnsProvider,
		dns01.DisableAuthoritativeNssPropagationRequirement(),
	)
	if err != nil {
		t.Fatalf("creating ACME issuer: %v", err)
	}

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
	certMgr := certmanager.NewManager(certStore, issuer, logger)

	// 8. Create and start spillway server with testcontrol overrides
	apiPort := 9090
	cfg := &config.ServerConfig{
		BaseDomain:          "spillway.test",
		RedisAddr:           mini.Addr(),
		PortRangeStart:      0,
		PortRangeEnd:        0,
		ACMEEmail:           "test@example.com",
		ACMEDirectory:       pebbleDir,
		TSStateDir:          t.TempDir(),
		TSHostname:          "spillway",
		RegistrationAPIPort: apiPort,
		HeartbeatTTL:        90,
	}

	srv := server.New(cfg, store, certMgr, logger)
	srv.WithTSOverrides(&server.TSOverrides{
		ControlURL: controlURL,
		Store:      new(mem.Store),
		Ephemeral:  true,
	})

	srvCtx, srvCancel := context.WithCancel(ctx)
	t.Cleanup(srvCancel)

	if err := srv.Start(srvCtx); err != nil {
		t.Fatalf("starting spillway server: %v", err)
	}
	t.Cleanup(srv.Close)

	t.Logf("e2e environment ready: control=%s, pebble=%s, redis=%s", controlURL, pebbleDir, mini.Addr())

	return &e2eEnv{
		controlURL: controlURL,
		control:    control,
		mini:       mini,
		rdb:        rdb,
		store:      store,
		certStore:  certStore,
		certMgr:    certMgr,
		srv:        srv,
		apiPort:    apiPort,
	}
}
