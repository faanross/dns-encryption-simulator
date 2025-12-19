package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/faanross/dns-encryption-simulator/internal/config"
	"github.com/faanross/dns-encryption-simulator/internal/dns"
	"github.com/faanross/dns-encryption-simulator/internal/modes"
)

func main() {
	// =============================================================================
	// CONFIGURATION - Customize these values
	// =============================================================================

	cfg := &config.AgentConfig{
		// ========== SELECT MODE HERE ==========
		Mode: config.ModeDoT, // CHANGE THIS: 1=Plain, 2=DoH, 3=DoT, 4=DoQ

		// ========== TIMING ==========
		BaseDelay: 5 * time.Second, // Time between queries
		Jitter:    2 * time.Second, // Random variance (±2s)

		// ========== MODE 1: PLAIN DNS SETTINGS ==========
		ResolverType:    config.ResolverPublic,
		ResolverAddress: "127.0.0.1:15353", // Plain DNS server

		// ========== MODE 2: DoH SETTINGS ==========
		DoHServerURL: "https://127.0.0.1:8443/dns-query", // DoH endpoint

		// ========== MODE 3: DoT SETTINGS ==========
		DoTServerAddr: "127.0.0.1:8853",

		// ========== COMMON SETTINGS ==========
		TargetDomain:       "timeserversync.test",
		SubdomainMinLength: 45,
		SubdomainMaxLength: 60,
		TLSServerName:      "timeserversync.test",
		InsecureSkipVerify: true, // Allow self-signed certs for testing
	}

	// =============================================================================
	// INITIALIZATION
	// =============================================================================

	fmt.Println("╔════════════════════════════════════════════════╗")
	fmt.Println("║   DNS Encryption Simulator - Agent            ║")
	fmt.Println("╚════════════════════════════════════════════════╝")
	fmt.Println()

	// Validate configuration
	if err := cfg.Validate(); err != nil {
		log.Fatalf("❌ Configuration error: %v", err)
	}

	// Display configuration
	fmt.Println("Configuration:")
	fmt.Println("─────────────────────────────────────────────────")
	fmt.Printf("  Mode:           %s\n", cfg.Mode)
	fmt.Printf("  Target Domain:  %s\n", cfg.TargetDomain)
	fmt.Printf("  Base Delay:     %s\n", cfg.BaseDelay)
	fmt.Printf("  Jitter:         ±%s\n", cfg.Jitter)
	fmt.Printf("  Subdomain Len:  %d-%d chars\n", cfg.SubdomainMinLength, cfg.SubdomainMaxLength)

	// Show mode-specific settings
	switch cfg.Mode {
	case config.ModePlainDNS:
		fmt.Printf("  Resolver:       %s\n", cfg.ResolverAddress)
	case config.ModeDoH:
		fmt.Printf("  DoH Server:     %s\n", cfg.DoHServerURL)
		fmt.Printf("  TLS Verify:     %v\n", !cfg.InsecureSkipVerify)
	case config.ModeDoT:
		fmt.Printf("  DoT Server:     %s\n", cfg.DoTServerAddr)
		fmt.Printf("  TLS Verify:     %v\n", !cfg.InsecureSkipVerify)
	case config.ModeDoQ:
		fmt.Println("  DoQ:            Not yet implemented")
	}
	fmt.Println()

	// =============================================================================
	// CREATE COMPONENTS
	// =============================================================================

	// Create subdomain generator
	generator, err := dns.NewSubdomainGenerator(cfg.SubdomainMinLength, cfg.SubdomainMaxLength)
	if err != nil {
		log.Fatalf("❌ Failed to create subdomain generator: %v", err)
	}

	// Create the appropriate DNS client based on mode
	var client modes.DNSClient

	switch cfg.Mode {
	case config.ModePlainDNS:
		resolver := cfg.ResolverAddress
		fmt.Printf("Using Plain DNS resolver: %s\n\n", resolver)
		client = modes.NewPlainDNSClientAdapter(resolver, 10*time.Second)

	case config.ModeDoH:
		fmt.Printf("Using DoH endpoint: %s\n", cfg.DoHServerURL)
		fmt.Printf("TLS Server Name: %s\n", cfg.TLSServerName)
		if cfg.InsecureSkipVerify {
			fmt.Printf("⚠️  WARNING: TLS certificate verification disabled (testing mode)\n")
		}
		fmt.Println()
		client = modes.NewDoHClient(cfg.DoHServerURL, 10*time.Second, cfg.InsecureSkipVerify)

	case config.ModeDoT:
		fmt.Printf("Using DoT server: %s\n", cfg.DoTServerAddr)
		fmt.Printf("TLS Server Name: %s\n", cfg.TLSServerName)
		if cfg.InsecureSkipVerify {
			fmt.Printf("⚠️  WARNING: TLS certificate verification disabled (testing mode)\n")
		}
		fmt.Println()
		client = modes.NewDoTClient(cfg.DoTServerAddr, cfg.TLSServerName, 10*time.Second, cfg.InsecureSkipVerify)

	case config.ModeDoQ:
		log.Fatalf("❌ Mode 4 (DoQ) not yet implemented - coming in Phase 7")

	default:
		log.Fatalf("❌ Invalid mode: %d", cfg.Mode)
	}

	defer client.Close()

	// Create beacon
	beacon := dns.NewBeacon(client, generator, cfg.TargetDomain, cfg.BaseDelay, cfg.Jitter)

	// =============================================================================
	// SET UP SIGNAL HANDLING
	// =============================================================================

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		sig := <-sigChan
		fmt.Printf("\n\n⚠️  Received signal: %v\n", sig)
		fmt.Println("Shutting down gracefully...")
		cancel()
	}()

	// =============================================================================
	// START BEACONING
	// =============================================================================

	if err := beacon.Start(ctx); err != nil {
		if err == context.Canceled {
			fmt.Println("✓ Shutdown complete")
		} else {
			log.Fatalf("❌ Beacon error: %v", err)
		}
	}
}
