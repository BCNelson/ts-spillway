package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/bcnelson/ts-spillway/internal/config"
	"github.com/spf13/cobra"
)

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)

	cfg := config.LoadClientConfig()

	rootCmd := &cobra.Command{
		Use:   "spillway",
		Short: "Expose local ports to the public internet via spillway",
	}

	startCmd := &cobra.Command{
		Use:   "start <port-or-range>",
		Short: "Register ports and start heartbeat loop",
		Long:  "Register one or more ports with the spillway server.\nExamples: spillway start 8080, spillway start 8000-8050",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ports, err := parsePorts(args[0])
			if err != nil {
				return fmt.Errorf("invalid port specification %q: %w", args[0], err)
			}
			return runStart(cfg, ports)
		},
	}

	statusCmd := &cobra.Command{
		Use:   "status",
		Short: "Show active registrations",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runStatus(cfg)
		},
	}

	rootCmd.AddCommand(startCmd, statusCmd)

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

// buildAliasMap filters the configured aliases to only include ports that are being registered.
func buildAliasMap(allAliases map[int]string, ports []int) map[string]string {
	if len(allAliases) == 0 {
		return nil
	}
	portSet := make(map[int]bool, len(ports))
	for _, p := range ports {
		portSet[p] = true
	}
	aliases := make(map[string]string)
	for port, alias := range allAliases {
		if portSet[port] {
			if err := config.ValidateAlias(alias); err != nil {
				slog.Warn("skipping invalid alias", "port", port, "alias", alias, "error", err)
				continue
			}
			aliases[strconv.Itoa(port)] = alias
		}
	}
	if len(aliases) == 0 {
		return nil
	}
	return aliases
}

func runStart(cfg *config.ClientConfig, ports []int) error {
	baseURL := fmt.Sprintf("http://%s", cfg.ServerAddr)
	aliases := buildAliasMap(cfg.Aliases, ports)

	// Register
	reqBody := map[string]any{"ports": ports}
	if aliases != nil {
		reqBody["aliases"] = aliases
	}
	body, _ := json.Marshal(reqBody)
	resp, err := http.Post(baseURL+"/api/v1/register", "application/json", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("failed to register: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("registration failed with status %d", resp.StatusCode)
	}

	var regResp struct {
		URLs []string `json:"urls"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&regResp); err != nil {
		return fmt.Errorf("failed to decode response: %w", err)
	}

	fmt.Println("Registered! Your URLs:")
	for _, u := range regResp.URLs {
		fmt.Printf("  %s\n", u)
	}
	fmt.Println()
	fmt.Println("Press Ctrl+C to stop.")

	// Heartbeat loop
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			hbBody := map[string]any{"ports": ports}
			if aliases != nil {
				hbBody["aliases"] = aliases
			}
			hbData, _ := json.Marshal(hbBody)
			hbResp, err := http.Post(baseURL+"/api/v1/heartbeat", "application/json", bytes.NewReader(hbData))
			if err != nil {
				slog.Error("heartbeat failed", "error", err)
				continue
			}
			_ = hbResp.Body.Close()
			if hbResp.StatusCode != http.StatusOK {
				slog.Error("heartbeat returned non-OK", "status", hbResp.StatusCode)
			}

		case sig := <-sigCh:
			fmt.Printf("\nReceived %s, deregistering...\n", sig)
			deregBody := map[string]any{"ports": ports}
			if aliases != nil {
				deregBody["aliases"] = aliases
			}
			deregData, _ := json.Marshal(deregBody)
			deregResp, err := http.Post(baseURL+"/api/v1/deregister", "application/json", bytes.NewReader(deregData))
			if err != nil {
				slog.Error("deregistration failed", "error", err)
				return nil
			}
			_ = deregResp.Body.Close()
			fmt.Println("Deregistered. Goodbye!")
			return nil
		}
	}
}

func runStatus(cfg *config.ClientConfig) error {
	baseURL := fmt.Sprintf("http://%s", cfg.ServerAddr)
	resp, err := http.Get(baseURL + "/api/v1/status")
	if err != nil {
		return fmt.Errorf("failed to get status: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("status request failed with status %d", resp.StatusCode)
	}

	var statusResp struct {
		Registrations []struct {
			Port      int       `json:"port"`
			URLs      []string  `json:"urls"`
			ExpiresAt time.Time `json:"expires_at"`
			Alias     string    `json:"alias,omitempty"`
		} `json:"registrations"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&statusResp); err != nil {
		return fmt.Errorf("failed to decode response: %w", err)
	}

	if len(statusResp.Registrations) == 0 {
		fmt.Println("No active registrations.")
		return nil
	}

	fmt.Println("Active registrations:")
	for _, reg := range statusResp.Registrations {
		if reg.Alias != "" {
			fmt.Printf("  Port %d [alias: %s] (expires %s):\n", reg.Port, reg.Alias, reg.ExpiresAt.Format(time.RFC3339))
		} else {
			fmt.Printf("  Port %d (expires %s):\n", reg.Port, reg.ExpiresAt.Format(time.RFC3339))
		}
		for _, u := range reg.URLs {
			fmt.Printf("    %s\n", u)
		}
	}

	return nil
}

func parsePorts(spec string) ([]int, error) {
	if strings.Contains(spec, "-") {
		parts := strings.SplitN(spec, "-", 2)
		start, err := strconv.Atoi(parts[0])
		if err != nil {
			return nil, fmt.Errorf("invalid start port: %w", err)
		}
		end, err := strconv.Atoi(parts[1])
		if err != nil {
			return nil, fmt.Errorf("invalid end port: %w", err)
		}
		if start > end {
			return nil, fmt.Errorf("start port %d > end port %d", start, end)
		}
		if end-start > 1000 {
			return nil, fmt.Errorf("port range too large (max 1000)")
		}
		var ports []int
		for p := start; p <= end; p++ {
			ports = append(ports, p)
		}
		return ports, nil
	}

	port, err := strconv.Atoi(spec)
	if err != nil {
		return nil, fmt.Errorf("invalid port: %w", err)
	}
	return []int{port}, nil
}
