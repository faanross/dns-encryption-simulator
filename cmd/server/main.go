package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
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
		Domain:         "timeserversync.test", // LOCAL: Use .test for testing
		ResponseIP:     "127.0.0.1",           // LOCAL: Respond with localhost
		TTL:            60,                    // 60 second TTL
		EnablePlainDNS: true,                  // Enable plain DNS
		EnableDoH:      false,                 // Not yet implemented
		EnableDoT:      false,                 // Not yet implemented
		EnableDoQ:      false,                 // Not yet implemented
		LogQueries:     true,                  // Log all queries
		Verbose:        true,                  // Detailed logging
	}

	// =============================================================================
	// INITIALIZATION
	// =============================================================================

	fmt.Println("╔════════════════════════════════════════════════╗")
	fmt.Println("║   DNS Encryption Simulator - Server           ║")
	fmt.Println("╚════════════════════════════════════════════════╝")
	fmt.Println()

	// Validate configuration
	// Note: We skip TLS validation since we're only doing plain DNS for now
	if cfg.Domain == "" {
		log.Fatal("❌ Domain cannot be empty")
	}
	if cfg.ResponseIP == "" {
		log.Fatal("❌ Response IP cannot be empty")
	}

	// Display configuration
	fmt.Println("Configuration:")
	fmt.Println("─────────────────────────────────────────────────")
	fmt.Printf("  Domain:      %s\n", cfg.Domain)
	fmt.Printf("  Response IP: %s\n", cfg.ResponseIP)
	fmt.Printf("  TTL:         %d seconds\n", cfg.TTL)
	fmt.Println("\nEnabled Protocols:")
	fmt.Printf("  Plain DNS:   %v\n", cfg.EnablePlainDNS)
	fmt.Printf("  DoH:         %v (not implemented)\n", cfg.EnableDoH)
	fmt.Printf("  DoT:         %v (not implemented)\n", cfg.EnableDoT)
	fmt.Printf("  DoQ:         %v (not implemented)\n", cfg.EnableDoQ)
	fmt.Println()

	// =============================================================================
	// CREATE SERVER
	// =============================================================================

	// Create the DNS handler
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

	// Create plain DNS server on port 5353
	// (Port 53 requires root/admin privileges)
	plainServer := dns.NewPlainDNSServer(handler, "127.0.0.1:15353")

	// =============================================================================
	// SET UP SIGNAL HANDLING
	// =============================================================================

	// Set up signal handling for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	// Start statistics printer goroutine
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

	// Handle shutdown signal
	go func() {
		sig := <-sigChan
		fmt.Printf("\n\n⚠️  Received signal: %v\n", sig)
		fmt.Println("Shutting down server...")

		// Print final statistics
		queryCount, uptime := handler.GetStats()
		fmt.Printf("\nFinal Statistics:\n")
		fmt.Printf("  Total Queries: %d\n", queryCount)
		fmt.Printf("  Uptime:        %s\n", uptime.Round(time.Second))
		if uptime.Seconds() > 0 {
			qps := float64(queryCount) / uptime.Seconds()
			fmt.Printf("  Average QPS:   %.2f\n", qps)
		}

		// Stop the server
		if err := plainServer.Stop(); err != nil {
			log.Printf("Error stopping server: %v", err)
		}

		os.Exit(0)
	}()

	// =============================================================================
	// START SERVER
	// =============================================================================

	fmt.Println("✓ Server ready\n")

	// Start the server (blocks until stopped)
	if err := plainServer.Start(); err != nil {
		log.Fatalf("❌ Server error: %v", err)
	}
}
