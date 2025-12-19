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
)

func main() {
	// =============================================================================
	// CONFIGURATION - Customize these values
	// =============================================================================

	cfg := &config.AgentConfig{
		Mode:               config.ModePlainDNS, // 1=Plain, 2=DoH, 3=DoT, 4=DoQ
		BaseDelay:          5 * time.Second,     // Time between queries
		Jitter:             2 * time.Second,     // Random variance (±2s)
		ResolverType:       config.ResolverPublic,
		ResolverAddress:    "127.0.0.1:15353",     // LOCAL: Our server on port 5353
		TargetDomain:       "timeserversync.test", // LOCAL: Use .test TLD for testing
		SubdomainMinLength: 45,
		SubdomainMaxLength: 60,
		TLSServerName:      "timeserversync.test",
		InsecureSkipVerify: false,
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
	fmt.Printf("  Resolver:       %s\n", cfg.ResolverAddress)
	fmt.Printf("  Base Delay:     %s\n", cfg.BaseDelay)
	fmt.Printf("  Jitter:         ±%s\n", cfg.Jitter)
	fmt.Printf("  Subdomain Len:  %d-%d chars\n", cfg.SubdomainMinLength, cfg.SubdomainMaxLength)
	fmt.Println()

	// Only Mode 1 (Plain DNS) is implemented in this phase
	if cfg.Mode != config.ModePlainDNS {
		log.Fatalf("❌ Only Mode 1 (Plain DNS) is implemented in Phase 3")
	}

	// =============================================================================
	// CREATE COMPONENTS
	// =============================================================================

	// Create subdomain generator
	generator, err := dns.NewSubdomainGenerator(cfg.SubdomainMinLength, cfg.SubdomainMaxLength)
	if err != nil {
		log.Fatalf("❌ Failed to create subdomain generator: %v", err)
	}

	// Determine which resolver to use
	resolver, err := dns.GetResolver(
		dns.ResolverType(cfg.ResolverType),
		cfg.ResolverAddress,
		cfg.TargetDomain,
	)
	if err != nil {
		log.Fatalf("❌ Failed to determine resolver: %v", err)
	}
	fmt.Printf("Using resolver: %s\n\n", resolver)

	// Create DNS client
	client := dns.NewPlainDNSClient(resolver, 10*time.Second)
	defer client.Close()

	// Create beacon
	beacon := dns.NewBeacon(client, generator, cfg.TargetDomain, cfg.BaseDelay, cfg.Jitter)

	// =============================================================================
	// SET UP SIGNAL HANDLING
	// =============================================================================

	// Create a context that we can cancel
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Set up signal handling for graceful shutdown
	// This catches Ctrl+C and allows clean exit
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	// Start a goroutine to handle signals
	go func() {
		sig := <-sigChan
		fmt.Printf("\n\n⚠️  Received signal: %v\n", sig)
		fmt.Println("Shutting down gracefully...")
		cancel() // Cancel the context to stop beacon
	}()

	// =============================================================================
	// START BEACONING
	// =============================================================================

	// Start the beacon loop (blocks until cancelled)
	if err := beacon.Start(ctx); err != nil {
		if err == context.Canceled {
			fmt.Println("✓ Shutdown complete")
		} else {
			log.Fatalf("❌ Beacon error: %v", err)
		}
	}
}
