package dns

import (
	"context"
	"crypto/rand"
	"fmt"
	"math/big"
	"time"

	"github.com/faanross/dns-encryption-simulator/internal/modes"
)

// Beacon represents a DNS beaconing client
type Beacon struct {
	client    modes.DNSClient
	generator *SubdomainGenerator
	domain    string
	baseDelay time.Duration
	jitter    time.Duration
}

// NewBeacon creates a new DNS beacon
func NewBeacon(client modes.DNSClient, generator *SubdomainGenerator, domain string, baseDelay, jitter time.Duration) *Beacon {
	return &Beacon{
		client:    client,
		generator: generator,
		domain:    domain,
		baseDelay: baseDelay,
		jitter:    jitter,
	}
}

// Start begins the beaconing loop
func (b *Beacon) Start(ctx context.Context) error {
	fmt.Println("Starting DNS beacon loop...")
	fmt.Printf("Base delay: %s, Jitter: ±%s\n", b.baseDelay, b.jitter)
	fmt.Println("Press Ctrl+C to stop\n")

	queryCount := 0

	for {
		select {
		case <-ctx.Done():
			fmt.Printf("\nBeacon stopped after %d queries\n", queryCount)
			return ctx.Err()
		default:
		}

		queryCount++

		fqdn, err := b.generator.GenerateWithDomain(b.domain)
		if err != nil {
			fmt.Printf("[ERROR] Failed to generate subdomain: %v\n", err)
			continue
		}

		fmt.Printf("[%s] Query #%d: %s\n", time.Now().Format("15:04:05"), queryCount, fqdn)

		result, err := b.client.Query(ctx, fqdn)
		if err != nil {
			fmt.Printf("  ❌ Query failed: %v\n", err)
		} else {
			fmt.Printf("  ✓ Response received in %s\n", result.RTT)
			if len(result.Answers) > 0 {
				fmt.Printf("  └─ Answer: %v\n", result.Answers)
			} else {
				fmt.Printf("  └─ No answer (NXDOMAIN or no A records)\n")
			}
		}

		delay := b.calculateDelay()
		fmt.Printf("  ⏱  Next query in %s\n\n", delay)

		select {
		case <-time.After(delay):
		case <-ctx.Done():
			fmt.Printf("\nBeacon stopped after %d queries\n", queryCount)
			return ctx.Err()
		}
	}
}

// calculateDelay adds random jitter to the base delay
func (b *Beacon) calculateDelay() time.Duration {
	if b.jitter == 0 {
		return b.baseDelay
	}

	maxJitter := int64(b.jitter)
	jitterRange := maxJitter * 2

	randomJitter, err := rand.Int(rand.Reader, big.NewInt(jitterRange))
	if err != nil {
		return b.baseDelay
	}

	jitterValue := time.Duration(randomJitter.Int64() - maxJitter)
	finalDelay := b.baseDelay + jitterValue

	if finalDelay < time.Second {
		finalDelay = time.Second
	}

	return finalDelay
}
