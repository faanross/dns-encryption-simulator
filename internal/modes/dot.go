package modes

import (
	"context"
	"crypto/tls"
	"fmt"
	"time"

	"github.com/miekg/dns"
)

// DoTClient performs DNS-over-TLS queries
type DoTClient struct {
	serverAddr         string // Server address (IP:port)
	tlsServerName      string // SNI for TLS handshake
	timeout            time.Duration
	insecureSkipVerify bool
	client             *dns.Client
}

// NewDoTClient creates a new DNS-over-TLS client
func NewDoTClient(serverAddr string, tlsServerName string, timeout time.Duration, insecureSkipVerify bool) *DoTClient {
	// Configure TLS
	tlsConfig := &tls.Config{
		ServerName:         tlsServerName, // This appears in TLS SNI field
		InsecureSkipVerify: insecureSkipVerify,
		MinVersion:         tls.VersionTLS12,
	}

	// Create DNS client with TLS transport
	// The key difference from plain DNS: we use "tcp-tls" instead of "udp"
	client := &dns.Client{
		Net:       "tcp-tls", // This tells miekg/dns to use TLS over TCP
		Timeout:   timeout,
		TLSConfig: tlsConfig,
	}

	return &DoTClient{
		serverAddr:         serverAddr,
		tlsServerName:      tlsServerName,
		timeout:            timeout,
		insecureSkipVerify: insecureSkipVerify,
		client:             client,
	}
}

// Query sends a DNS query over TLS
func (c *DoTClient) Query(ctx context.Context, domain string) (*QueryResult, error) {
	// Build DNS query message
	// This is identical to plain DNS - the protocol is the same
	// Only the transport (TLS) is different
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(domain), dns.TypeA)
	msg.RecursionDesired = true

	// Record query start time
	queryTime := time.Now()

	// Send the query over TLS
	// The miekg/dns library handles:
	// - TLS handshake
	// - SNI (Server Name Indication)
	// - Certificate verification (unless InsecureSkipVerify is true)
	// - Sending DNS message over the encrypted connection
	response, rtt, err := c.client.Exchange(msg, c.serverAddr)

	result := &QueryResult{
		Domain:    domain,
		Response:  response,
		RTT:       rtt,
		Server:    c.serverAddr,
		Error:     err,
		QueryTime: queryTime,
		Answers:   make([]string, 0),
	}

	// If there was an error, return early
	if err != nil {
		return result, fmt.Errorf("DoT query failed: %w", err)
	}

	// Check if we got a response
	if response == nil {
		return result, fmt.Errorf("no response received")
	}

	// Parse the answer section to extract IP addresses
	for _, answer := range response.Answer {
		if a, ok := answer.(*dns.A); ok {
			result.Answers = append(result.Answers, a.A.String())
		}
	}

	return result, nil
}

// Close cleans up resources
func (c *DoTClient) Close() error {
	// DoT client doesn't maintain persistent connections in our implementation
	// The miekg/dns library handles connection lifecycle
	return nil
}
