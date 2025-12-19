package dns

import (
	"crypto/rand"
	"encoding/base32"
	"fmt"
	"math/big"
	"strings"
)

// SubdomainGenerator creates random high-entropy subdomains
// that simulate DNS tunneling behavior
type SubdomainGenerator struct {
	minLength int
	maxLength int
	encoding  *base32.Encoding
}

// NewSubdomainGenerator creates a new generator with specified length constraints
func NewSubdomainGenerator(minLength, maxLength int) (*SubdomainGenerator, error) {
	// Validate lengths against DNS constraints
	if minLength < 1 || minLength > 63 {
		return nil, fmt.Errorf("minLength must be 1-63, got %d", minLength)
	}
	if maxLength < minLength || maxLength > 63 {
		return nil, fmt.Errorf("maxLength must be between %d and 63, got %d", minLength, maxLength)
	}

	// Use Base32 encoding without padding
	// Base32 uses: A-Z and 2-7 (all DNS-safe characters)
	// We remove padding ('=') since DNS doesn't like it
	encoding := base32.StdEncoding.WithPadding(base32.NoPadding)

	return &SubdomainGenerator{
		minLength: minLength,
		maxLength: maxLength,
		encoding:  encoding,
	}, nil
}

// Generate creates a random subdomain of length between min and max
func (g *SubdomainGenerator) Generate() (string, error) {
	// Pick a random length between min and max
	length, err := g.randomLength()
	if err != nil {
		return "", fmt.Errorf("failed to generate random length: %w", err)
	}

	// Calculate how many random bytes we need
	// Base32 encoding: 5 bytes -> 8 characters
	// So we need: (targetLength * 5) / 8 bytes (rounded up)
	// We'll generate extra and trim to exact length
	bytesNeeded := ((length * 5) / 8) + 1

	// Generate cryptographically random bytes
	randomBytes := make([]byte, bytesNeeded)
	if _, err := rand.Read(randomBytes); err != nil {
		return "", fmt.Errorf("failed to generate random bytes: %w", err)
	}

	// Encode to Base32
	encoded := g.encoding.EncodeToString(randomBytes)

	// Convert to lowercase (more common in DNS)
	// Real tunneling tools often use lowercase to blend in
	encoded = strings.ToLower(encoded)

	// Trim to exact desired length
	if len(encoded) > length {
		encoded = encoded[:length]
	}

	return encoded, nil
}

// randomLength returns a random number between minLength and maxLength (inclusive)
func (g *SubdomainGenerator) randomLength() (int, error) {
	// If min and max are the same, no randomness needed
	if g.minLength == g.maxLength {
		return g.minLength, nil
	}

	// Calculate range
	rangeSize := g.maxLength - g.minLength + 1

	// Generate cryptographically secure random number in range
	n, err := rand.Int(rand.Reader, big.NewInt(int64(rangeSize)))
	if err != nil {
		return 0, err
	}

	return g.minLength + int(n.Int64()), nil
}

// GenerateWithDomain creates a full FQDN with random subdomain
// Example: "a7k2m9qlp3r8sv7x4j2n6b9c5d1f3g8h.timeserversync.com"
func (g *SubdomainGenerator) GenerateWithDomain(domain string) (string, error) {
	subdomain, err := g.Generate()
	if err != nil {
		return "", err
	}

	fqdn := fmt.Sprintf("%s.%s", subdomain, domain)

	// Validate total FQDN length (DNS limit is 253 characters)
	if len(fqdn) > 253 {
		return "", fmt.Errorf("FQDN too long: %d characters (max 253)", len(fqdn))
	}

	return fqdn, nil
}

// Stats returns statistics about generated subdomains for testing/debugging
type GeneratorStats struct {
	MinLength     int
	MaxLength     int
	EncodingType  string
	SampleOutputs []string
}

// GetStats generates statistics and sample outputs
// Useful for verifying the generator is working correctly
func (g *SubdomainGenerator) GetStats(sampleCount int) (*GeneratorStats, error) {
	stats := &GeneratorStats{
		MinLength:     g.minLength,
		MaxLength:     g.maxLength,
		EncodingType:  "Base32 (lowercase, no padding)",
		SampleOutputs: make([]string, 0, sampleCount),
	}

	// Generate sample outputs
	for i := 0; i < sampleCount; i++ {
		sample, err := g.Generate()
		if err != nil {
			return nil, fmt.Errorf("failed to generate sample %d: %w", i, err)
		}
		stats.SampleOutputs = append(stats.SampleOutputs, sample)
	}

	return stats, nil
}
