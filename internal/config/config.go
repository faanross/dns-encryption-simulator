package config

import (
	"fmt"
	"time"
)

// OperationMode represents the DNS protocol mode to use
type OperationMode int

const (
	ModePlainDNS OperationMode = 1 // Plain DNS over UDP (port 53)
	ModeDoH      OperationMode = 2 // DNS-over-HTTPS (port 443)
	ModeDoT      OperationMode = 3 // DNS-over-TLS (port 853)
	ModeDoQ      OperationMode = 4 // DNS-over-QUIC (port 853 UDP)
)

// String returns a human-readable name for the mode
// This is useful for logging and debugging
func (m OperationMode) String() string {
	switch m {
	case ModePlainDNS:
		return "Plain DNS"
	case ModeDoH:
		return "DNS-over-HTTPS (DoH)"
	case ModeDoT:
		return "DNS-over-TLS (DoT)"
	case ModeDoQ:
		return "DNS-over-QUIC (DoQ)"
	default:
		return "Unknown"
	}
}

// ResolverType indicates which type of DNS resolver to use
type ResolverType int

const (
	ResolverLocal         ResolverType = 1 // Use system's default resolver
	ResolverPublic        ResolverType = 2 // Use a specific public resolver (e.g., 8.8.8.8)
	ResolverAuthoritative ResolverType = 3 // Query authoritative nameserver directly
)

// AgentConfig holds all configuration for the DNS agent
// This is what we'll customize at the top of the agent's main.go
type AgentConfig struct {
	// ========== OPERATION MODE ==========
	// Mode selects which DNS protocol to use (1-4)
	Mode OperationMode

	// ========== TIMING PARAMETERS ==========
	// BaseDelay is the base time to wait between queries
	// Example: 5 * time.Second means 5 seconds between queries
	BaseDelay time.Duration

	// Jitter adds randomness to timing to appear more realistic
	// Example: 2 * time.Second means ±2 seconds of randomness
	// If BaseDelay=5s and Jitter=2s, actual delay will be between 3-7 seconds
	Jitter time.Duration

	// ========== RESOLVER CONFIGURATION ==========
	// ResolverType determines which resolver to use
	ResolverType ResolverType

	// ResolverAddress is the IP:PORT of the resolver (for ResolverPublic or ResolverAuthoritative)
	// Examples:
	//   - "8.8.8.8:53" for Google DNS
	//   - "1.1.1.1:53" for Cloudflare DNS
	//   - "your-server-ip:53" for direct to authoritative
	ResolverAddress string

	// ========== DOMAIN CONFIGURATION ==========
	// TargetDomain is the base domain for queries (e.g., "timeserversync.com")
	TargetDomain string

	// SubdomainMinLength is minimum length of random subdomain (default: 45)
	SubdomainMinLength int

	// SubdomainMaxLength is maximum length of random subdomain (default: 60)
	// DNS labels have a 63-character limit, so we stay under that
	SubdomainMaxLength int

	// ========== TLS CONFIGURATION (for DoH/DoT/DoQ) ==========
	// ServerName for TLS SNI (Server Name Indication)
	// This is what appears in the TLS handshake
	TLSServerName string

	// InsecureSkipVerify allows self-signed certificates (for testing)
	// WARNING: Set to false in production
	InsecureSkipVerify bool

	// ========== DoH CONFIGURATION ==========
	// DoHServerURL is the full URL to the DoH endpoint
	// Example: "https://timeserversync.test:8443/dns-query"
	DoHServerURL string

	// ========== DoT CONFIGURATION ==========
	// DoTServerAddr is the address of the DoT server (IP:port)
	// Example: "127.0.0.1:8853"
	DoTServerAddr string
}

// ServerConfig holds all configuration for the DNS server
type ServerConfig struct {
	// ========== DOMAIN CONFIGURATION ==========
	// Domain is the authoritative domain this server handles
	Domain string

	// ResponseIP is the IP address to return in A record responses
	ResponseIP string

	// TTL is the Time-To-Live for DNS responses (in seconds)
	TTL uint32

	// ========== LISTENER CONFIGURATION ==========
	// Enable/disable each protocol listener
	EnablePlainDNS bool // UDP port 53
	EnableDoH      bool // HTTPS port 443
	EnableDoT      bool // TLS port 853
	EnableDoQ      bool // QUIC port 853

	// ========== TLS CONFIGURATION ==========
	// Paths to TLS certificate and key files
	// Required for DoH, DoT, and DoQ
	TLSCertFile string
	TLSKeyFile  string

	// ========== LOGGING ==========
	// LogQueries enables detailed query logging
	LogQueries bool

	// Verbose enables debug logging
	Verbose bool
}

// Validate checks if the agent configuration is valid
// This helps catch configuration errors before we try to run
func (c *AgentConfig) Validate() error {
	// Check mode is valid (1-4)
	if c.Mode < ModePlainDNS || c.Mode > ModeDoQ {
		return fmt.Errorf("invalid mode %d: must be 1-4", c.Mode)
	}

	// Check we have a target domain
	if c.TargetDomain == "" {
		return fmt.Errorf("target domain cannot be empty")
	}

	// Check subdomain lengths are reasonable
	if c.SubdomainMinLength < 1 || c.SubdomainMinLength > 63 {
		return fmt.Errorf("subdomain min length must be 1-63, got %d", c.SubdomainMinLength)
	}
	if c.SubdomainMaxLength < c.SubdomainMinLength || c.SubdomainMaxLength > 63 {
		return fmt.Errorf("subdomain max length must be between min (%d) and 63, got %d",
			c.SubdomainMinLength, c.SubdomainMaxLength)
	}

	// Check resolver configuration
	if c.ResolverType == ResolverPublic || c.ResolverType == ResolverAuthoritative {
		if c.ResolverAddress == "" {
			return fmt.Errorf("resolver address required for resolver type %d", c.ResolverType)
		}
	}

	// Check TLS configuration for encrypted modes
	if c.Mode != ModePlainDNS {
		if c.TLSServerName == "" {
			return fmt.Errorf("TLS server name required for encrypted DNS modes")
		}
	}

	return nil
}

// Validate checks if the server configuration is valid
func (c *ServerConfig) Validate() error {
	// Check we have a domain
	if c.Domain == "" {
		return fmt.Errorf("domain cannot be empty")
	}

	// Check we have a response IP
	if c.ResponseIP == "" {
		return fmt.Errorf("response IP cannot be empty")
	}

	// Check at least one listener is enabled
	if !c.EnablePlainDNS && !c.EnableDoH && !c.EnableDoT && !c.EnableDoQ {
		return fmt.Errorf("at least one protocol listener must be enabled")
	}

	// Check TLS configuration if encrypted protocols are enabled
	if c.EnableDoH || c.EnableDoT || c.EnableDoQ {
		if c.TLSCertFile == "" || c.TLSKeyFile == "" {
			return fmt.Errorf("TLS certificate and key required for encrypted protocols")
		}
	}

	return nil
}

// DefaultAgentConfig returns a sensible default configuration
// You can use this as a starting point and modify what you need
func DefaultAgentConfig() *AgentConfig {
	return &AgentConfig{
		Mode:               ModePlainDNS,    // Start with plain DNS
		BaseDelay:          5 * time.Second, // 5 seconds between queries
		Jitter:             2 * time.Second, // ±2 seconds randomness
		ResolverType:       ResolverPublic,  // Use public resolver
		ResolverAddress:    "8.8.8.8:53",    // Google DNS
		TargetDomain:       "timeserversync.com",
		SubdomainMinLength: 45, // Realistic tunnel length
		SubdomainMaxLength: 60, // Close to 63 char limit
		TLSServerName:      "timeserversync.com",
		InsecureSkipVerify: false, // Require valid certs
		DoHServerURL:       "https://127.0.0.1:8443/dns-query",
		DoTServerAddr:      "127.0.0.1:8853",
	}
}

// DefaultServerConfig returns a sensible default configuration
func DefaultServerConfig() *ServerConfig {
	return &ServerConfig{
		Domain:         "timeserversync.com",
		ResponseIP:     "1.2.3.4", // Dummy IP
		TTL:            60,        // 60 second TTL
		EnablePlainDNS: true,      // Enable all modes by default
		EnableDoH:      true,
		EnableDoT:      true,
		EnableDoQ:      false, // DoQ might not be fully implemented
		TLSCertFile:    "/etc/letsencrypt/live/timeserversync.com/fullchain.pem",
		TLSKeyFile:     "/etc/letsencrypt/live/timeserversync.com/privkey.pem",
		LogQueries:     true,
		Verbose:        false,
	}
}
