package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/faanross/dns-encryption-simulator/internal/config"
	"github.com/faanross/dns-encryption-simulator/internal/dns"
)

func main() {
	// =============================================================================
	// CONFIGURATION - Customize these values
	// =============================================================================

	cfg := &config.ServerConfig{
		Domain:     "timeserversync.test",
		ResponseIP: "127.0.0.1",
		TTL:        60,

		// Enable protocols
		EnablePlainDNS: true,  // Plain DNS on port 15353
		EnableDoH:      true,  // DoH on port 8443
		EnableDoT:      true,  // Not yet implemented
		EnableDoQ:      false, // Not yet implemented

		// TLS Configuration (for DoH, DoT, DoQ)
		TLSCertFile: "./certs/server.crt",
		TLSKeyFile:  "./certs/server.key",

		// Logging
		LogQueries: true,
		Verbose:    true,
	}

	// =============================================================================
	// INITIALIZATION
	// =============================================================================

	fmt.Println("╔════════════════════════════════════════════════╗")
	fmt.Println("║   DNS Encryption Simulator - Server           ║")
	fmt.Println("╚════════════════════════════════════════════════╝")
	fmt.Println()

	// Display configuration
	fmt.Println("Configuration:")
	fmt.Println("─────────────────────────────────────────────────")
	fmt.Printf("  Domain:      %s\n", cfg.Domain)
	fmt.Printf("  Response IP: %s\n", cfg.ResponseIP)
	fmt.Printf("  TTL:         %d seconds\n", cfg.TTL)
	fmt.Println("\nEnabled Protocols:")
	fmt.Printf("  Plain DNS:   %v (port 15353)\n", cfg.EnablePlainDNS)
	fmt.Printf("  DoH:         %v (port 8443)\n", cfg.EnableDoH)
	fmt.Printf("  DoT:         %v (port 8853)\n", cfg.EnableDoT)
	fmt.Printf("  DoQ:         %v\n", cfg.EnableDoQ)

	if cfg.EnableDoH || cfg.EnableDoT || cfg.EnableDoQ {
		fmt.Println("\nTLS Configuration:")
		fmt.Printf("  Certificate: %s\n", cfg.TLSCertFile)
		fmt.Printf("  Private Key: %s\n", cfg.TLSKeyFile)
	}
	fmt.Println()

	// =============================================================================
	// CREATE SERVERS
	// =============================================================================

	// Create the DNS handler (shared by all protocols)
	handler, err := dns.NewServer(
		cfg.Domain,
		cfg.ResponseIP,
		cfg.TTL,
		cfg.LogQueries,
		cfg.Verbose,
	)
	if err != nil {
		log.Fatalf("❌ Failed to create DNS handler: %v", err)
	}

	// Track running servers
	var wg sync.WaitGroup
	errChan := make(chan error, 2)

	// Start Plain DNS server
	if cfg.EnablePlainDNS {
		plainServer := dns.NewPlainDNSServer(handler, "127.0.0.1:15353")
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := plainServer.Start(); err != nil {
				errChan <- fmt.Errorf("Plain DNS server error: %w", err)
			}
		}()
	}

	// Start DoH server
	if cfg.EnableDoH {
		dohServer := dns.NewDoHServer(handler, "127.0.0.1:8443", cfg.TLSCertFile, cfg.TLSKeyFile)
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := dohServer.Start(); err != nil {
				errChan <- fmt.Errorf("DoH server error: %w", err)
			}
		}()
	}

	// Start DoT server
	if cfg.EnableDoT {
		dotServer := dns.NewDoTServer(handler, "127.0.0.1:8853", cfg.TLSCertFile, cfg.TLSKeyFile)
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := dotServer.Start(); err != nil {
				errChan <- fmt.Errorf("DoT server error: %w", err)
			}
		}()
	}

	// Give servers a moment to start
	time.Sleep(500 * time.Millisecond)

	// =============================================================================
	// SET UP SIGNAL HANDLING
	// =============================================================================

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	// Statistics printer
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				queryCount, uptime := handler.GetStats()
				qps := float64(queryCount) / uptime.Seconds()
				fmt.Printf("\n📊 Stats: %d queries | Uptime: %s | Avg: %.2f q/s\n\n",
					queryCount, uptime.Round(time.Second), qps)
			case <-sigChan:
				return
			}
		}
	}()

	fmt.Println("✓ All servers ready\n")

	// =============================================================================
	// WAIT FOR SHUTDOWN
	// =============================================================================

	// Wait for signal or error
	select {
	case sig := <-sigChan:
		fmt.Printf("\n\n⚠️  Received signal: %v\n", sig)
		fmt.Println("Shutting down servers...")

		// Print final statistics
		queryCount, uptime := handler.GetStats()
		fmt.Printf("\nFinal Statistics:\n")
		fmt.Printf("  Total Queries: %d\n", queryCount)
		fmt.Printf("  Uptime:        %s\n", uptime.Round(time.Second))
		if uptime.Seconds() > 0 {
			qps := float64(queryCount) / uptime.Seconds()
			fmt.Printf("  Average QPS:   %.2f\n", qps)
		}

		fmt.Println("\n✓ Shutdown complete")

	case err := <-errChan:
		log.Fatalf("❌ Server error: %v", err)
	}
}
