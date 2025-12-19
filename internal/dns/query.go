package dns

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/miekg/dns"
)

// QueryResult contains the results of a DNS query
type QueryResult struct {
	Domain    string        // The FQDN that was queried
	Response  *dns.Msg      // The full DNS response message
	RTT       time.Duration // Round-trip time
	Server    string        // Which server answered
	Error     error         // Any error that occurred
	Answers   []string      // IP addresses from answer section (if any)
	QueryTime time.Time     // When the query was sent
}

// PlainDNSClient performs standard DNS queries over UDP
type PlainDNSClient struct {
	resolver string        // DNS server address (IP:port)
	timeout  time.Duration // Query timeout
	client   *dns.Client   // Underlying DNS client
}

// NewPlainDNSClient creates a new plain DNS client
func NewPlainDNSClient(resolver string, timeout time.Duration) *PlainDNSClient {
	// Create the underlying DNS client
	// We use UDP for standard DNS queries
	client := &dns.Client{
		Net:     "udp",   // Use UDP transport
		Timeout: timeout, // How long to wait for response
		UDPSize: 4096,    // Max UDP packet size (standard)
	}

	return &PlainDNSClient{
		resolver: resolver,
		timeout:  timeout,
		client:   client,
	}
}

// Query sends a DNS A record query for the specified domain
func (c *PlainDNSClient) Query(ctx context.Context, domain string) (*QueryResult, error) {
	// Create a new DNS message (query)
	msg := new(dns.Msg)

	// Set the query parameters
	// SetQuestion formats: "domain.com." with trailing dot (FQDN format)
	// dns.TypeA means we want IPv4 addresses
	// dns.ClassINET means Internet class (standard)
	msg.SetQuestion(dns.Fqdn(domain), dns.TypeA)

	// Enable recursion desired flag
	// This tells the server we want it to resolve recursively if needed
	msg.RecursionDesired = true

	// Record when we send the query
	queryTime := time.Now()

	// Send the query and wait for response
	// Exchange() handles:
	// - Sending the query to the resolver
	// - Waiting for the response
	// - Retries (if needed)
	// - Timeout handling
	response, rtt, err := c.client.Exchange(msg, c.resolver)

	result := &QueryResult{
		Domain:    domain,
		Response:  response,
		RTT:       rtt,
		Server:    c.resolver,
		Error:     err,
		QueryTime: queryTime,
		Answers:   make([]string, 0),
	}

	// If there was an error, return early
	if err != nil {
		return result, fmt.Errorf("DNS query failed: %w", err)
	}

	// Check if we got a response
	if response == nil {
		return result, fmt.Errorf("no response received")
	}

	// Parse the answer section to extract IP addresses
	// The answer section contains the actual DNS records
	for _, answer := range response.Answer {
		// Check if this is an A record (IPv4 address)
		if a, ok := answer.(*dns.A); ok {
			result.Answers = append(result.Answers, a.A.String())
		}
	}

	return result, nil
}

// QueryWithRetry performs a query with automatic retries on failure
func (c *PlainDNSClient) QueryWithRetry(ctx context.Context, domain string, maxRetries int) (*QueryResult, error) {
	var lastErr error

	for attempt := 0; attempt <= maxRetries; attempt++ {
		// Check if context was cancelled
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		// Attempt the query
		result, err := c.Query(ctx, domain)

		// If successful, return immediately
		if err == nil {
			if attempt > 0 {
				// Log that we succeeded after retries (for debugging)
				fmt.Printf("Query succeeded after %d retries\n", attempt)
			}
			return result, nil
		}

		// Save the error
		lastErr = err

		// If this wasn't the last attempt, wait before retrying
		if attempt < maxRetries {
			// Exponential backoff: wait longer after each failure
			backoff := time.Duration(attempt+1) * time.Second
			fmt.Printf("Query failed (attempt %d/%d), retrying in %s: %v\n",
				attempt+1, maxRetries+1, backoff, err)

			select {
			case <-time.After(backoff):
				// Continue to next attempt
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
	}

	return nil, fmt.Errorf("query failed after %d attempts: %w", maxRetries+1, lastErr)
}

// Close cleans up any resources
func (c *PlainDNSClient) Close() error {
	// Plain DNS client doesn't maintain connections
	// So nothing to clean up
	return nil
}

// ResolverType determines what resolver to use
type ResolverType int

const (
	ResolverTypeLocal         ResolverType = 1 // System resolver
	ResolverTypePublic        ResolverType = 2 // Specific public resolver
	ResolverTypeAuthoritative ResolverType = 3 // Direct to authoritative NS
)

// GetResolver determines which DNS resolver to use based on configuration
func GetResolver(resolverType ResolverType, customAddress string, domain string) (string, error) {
	switch resolverType {
	case ResolverTypeLocal:
		// Use the system's configured DNS resolver
		// This reads from /etc/resolv.conf on Linux or system settings on Windows
		return getSystemResolver()

	case ResolverTypePublic:
		// Use the provided custom address
		if customAddress == "" {
			return "", fmt.Errorf("custom resolver address required for public resolver type")
		}
		// Ensure it has a port
		if _, _, err := net.SplitHostPort(customAddress); err != nil {
			// Add default DNS port if not specified
			return customAddress + ":53", nil
		}
		return customAddress, nil

	case ResolverTypeAuthoritative:
		// Look up the authoritative nameserver for the domain
		return getAuthoritativeNameserver(domain)

	default:
		return "", fmt.Errorf("unknown resolver type: %d", resolverType)
	}
}

// getSystemResolver gets the system's default DNS resolver
func getSystemResolver() (string, error) {
	// Read the system's DNS configuration
	config, err := dns.ClientConfigFromFile("/etc/resolv.conf")
	if err != nil {
		// On Windows or if /etc/resolv.conf doesn't exist, use a fallback
		// In a real implementation, you'd use Windows API to get DNS servers
		return "8.8.8.8:53", nil // Fallback to Google DNS
	}

	if len(config.Servers) == 0 {
		return "", fmt.Errorf("no DNS servers configured")
	}

	// Use the first configured server
	// Add port 53 if not specified
	server := config.Servers[0]
	if _, _, err := net.SplitHostPort(server); err != nil {
		server = server + ":53"
	}

	return server, nil
}

// getAuthoritativeNameserver finds the authoritative nameserver for a domain
func getAuthoritativeNameserver(domain string) (string, error) {
	// For now, we'll implement a simple version
	// In production, this would do a full NS record lookup

	// Create a temporary client to query for NS records
	client := &dns.Client{Net: "udp", Timeout: 5 * time.Second}
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(domain), dns.TypeNS)
	msg.RecursionDesired = true

	// Query a public resolver for the NS records
	response, _, err := client.Exchange(msg, "8.8.8.8:53")
	if err != nil {
		return "", fmt.Errorf("failed to lookup NS records: %w", err)
	}

	// Extract the first nameserver
	for _, answer := range response.Answer {
		if ns, ok := answer.(*dns.NS); ok {
			// We have a nameserver name, now resolve it to an IP
			nsIP, err := net.ResolveIPAddr("ip4", ns.Ns)
			if err != nil {
				continue // Try next NS
			}
			return nsIP.String() + ":53", nil
		}
	}

	return "", fmt.Errorf("no authoritative nameserver found for %s", domain)
}
