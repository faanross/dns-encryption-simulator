package dns

import (
	"context"
	"crypto/rand"
	"fmt"
	"math/big"
	"time"
)

// Beacon represents a DNS beaconing client
// This simulates malware C2 behavior with periodic DNS queries
type Beacon struct {
	client    *PlainDNSClient
	generator *SubdomainGenerator
	domain    string
	baseDelay time.Duration
	jitter    time.Duration
}

// NewBeacon creates a new DNS beacon
func NewBeacon(client *PlainDNSClient, generator *SubdomainGenerator, domain string, baseDelay, jitter time.Duration) *Beacon {
	return &Beacon{
		client:    client,
		generator: generator,
		domain:    domain,
		baseDelay: baseDelay,
		jitter:    jitter,
	}
}

// Start begins the beaconing loop
// This will run indefinitely until the context is cancelled
func (b *Beacon) Start(ctx context.Context) error {
	fmt.Println("Starting DNS beacon loop...")
	fmt.Printf("Base delay: %s, Jitter: ±%s\n", b.baseDelay, b.jitter)
	fmt.Println("Press Ctrl+C to stop\n")

	queryCount := 0

	for {
		// Check if we should stop
		select {
		case <-ctx.Done():
			fmt.Printf("\nBeacon stopped after %d queries\n", queryCount)
			return ctx.Err()
		default:
			// Continue with query
		}

		queryCount++

		// Generate random subdomain
		fqdn, err := b.generator.GenerateWithDomain(b.domain)
		if err != nil {
			fmt.Printf("[ERROR] Failed to generate subdomain: %v\n", err)
			continue
		}

		// Send the query
		fmt.Printf("[%s] Query #%d: %s\n", time.Now().Format("15:04:05"), queryCount, fqdn)

		result, err := b.client.Query(ctx, fqdn)
		if err != nil {
			fmt.Printf("  ❌ Query failed: %v\n", err)
		} else {
			// Show response details
			fmt.Printf("  ✓ Response received in %s\n", result.RTT)
			if len(result.Answers) > 0 {
				fmt.Printf("  └─ Answer: %v\n", result.Answers)
			} else {
				fmt.Printf("  └─ No answer (NXDOMAIN or no A records)\n")
			}
		}

		// Calculate next delay with jitter
		delay := b.calculateDelay()
		fmt.Printf("  ⏱  Next query in %s\n\n", delay)

		// Wait for the calculated delay
		select {
		case <-time.After(delay):
			// Continue to next query
		case <-ctx.Done():
			fmt.Printf("\nBeacon stopped after %d queries\n", queryCount)
			return ctx.Err()
		}
	}
}

// calculateDelay adds random jitter to the base delay
// This makes the beacon appear more realistic and evades simple interval-based detection
func (b *Beacon) calculateDelay() time.Duration {
	if b.jitter == 0 {
		return b.baseDelay
	}

	// Generate random jitter between -jitter and +jitter
	// For example, if jitter is 2 seconds, we'll get a value between -2s and +2s
	maxJitter := int64(b.jitter)
	jitterRange := maxJitter * 2 // Total range is 2x jitter (from -jitter to +jitter)

	// Generate secure random number
	randomJitter, err := rand.Int(rand.Reader, big.NewInt(jitterRange))
	if err != nil {
		// If random generation fails, just use base delay
		return b.baseDelay
	}

	// Convert to signed value and adjust
	// Subtract maxJitter to shift range from [0, 2*jitter] to [-jitter, +jitter]
	jitterValue := time.Duration(randomJitter.Int64() - maxJitter)

	// Calculate final delay
	finalDelay := b.baseDelay + jitterValue

	// Ensure we never have a negative or zero delay
	if finalDelay < time.Second {
		finalDelay = time.Second
	}

	return finalDelay
}
