package modes

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/miekg/dns"
)

// DoHClient performs DNS-over-HTTPS queries
type DoHClient struct {
	serverURL          string // Full URL to DoH endpoint
	httpClient         *http.Client
	timeout            time.Duration
	insecureSkipVerify bool
}

// NewDoHClient creates a new DNS-over-HTTPS client
func NewDoHClient(serverURL string, timeout time.Duration, insecureSkipVerify bool) *DoHClient {
	// Configure TLS
	tlsConfig := &tls.Config{
		InsecureSkipVerify: insecureSkipVerify,
		MinVersion:         tls.VersionTLS12, // Require TLS 1.2 or higher
	}

	// Create HTTP client with TLS and timeout
	// We use HTTP/2 which is standard for DoH
	httpClient := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig:     tlsConfig,
			ForceAttemptHTTP2:   true, // Prefer HTTP/2
			MaxIdleConns:        10,
			IdleConnTimeout:     90 * time.Second,
			TLSHandshakeTimeout: 10 * time.Second,
		},
	}

	return &DoHClient{
		serverURL:          serverURL,
		httpClient:         httpClient,
		timeout:            timeout,
		insecureSkipVerify: insecureSkipVerify,
	}
}

// Query sends a DNS query over HTTPS
func (c *DoHClient) Query(ctx context.Context, domain string) (*QueryResult, error) {
	// Build DNS query message
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(domain), dns.TypeA)
	msg.RecursionDesired = true

	// Pack the DNS message into wire format (binary)
	// This is the actual DNS protocol message, just transported over HTTPS
	wireFormat, err := msg.Pack()
	if err != nil {
		return nil, fmt.Errorf("failed to pack DNS message: %w", err)
	}

	// Record query start time
	queryTime := time.Now()

	// Create HTTP POST request
	// RFC 8484 specifies POST method with application/dns-message content type
	req, err := http.NewRequestWithContext(ctx, "POST", c.serverURL, bytes.NewReader(wireFormat))
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %w", err)
	}

	// Set required headers for DoH
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")

	// Send the request
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return &QueryResult{
			Domain:    domain,
			Error:     err,
			QueryTime: queryTime,
		}, fmt.Errorf("HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	// Calculate round-trip time
	rtt := time.Since(queryTime)

	// Check HTTP status
	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return &QueryResult{
			Domain:    domain,
			RTT:       rtt,
			Error:     fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(bodyBytes)),
			QueryTime: queryTime,
		}, fmt.Errorf("server returned HTTP %d", resp.StatusCode)
	}

	// Read response body
	responseBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return &QueryResult{
			Domain:    domain,
			RTT:       rtt,
			Error:     err,
			QueryTime: queryTime,
		}, fmt.Errorf("failed to read response: %w", err)
	}

	// Unpack DNS response from wire format
	dnsResponse := new(dns.Msg)
	if err := dnsResponse.Unpack(responseBytes); err != nil {
		return &QueryResult{
			Domain:    domain,
			RTT:       rtt,
			Error:     err,
			QueryTime: queryTime,
		}, fmt.Errorf("failed to unpack DNS response: %w", err)
	}

	// Extract answers
	result := &QueryResult{
		Domain:    domain,
		Response:  dnsResponse,
		RTT:       rtt,
		Server:    c.serverURL,
		QueryTime: queryTime,
		Answers:   make([]string, 0),
	}

	for _, answer := range dnsResponse.Answer {
		if a, ok := answer.(*dns.A); ok {
			result.Answers = append(result.Answers, a.A.String())
		}
	}

	return result, nil
}

// Close cleans up resources
func (c *DoHClient) Close() error {
	c.httpClient.CloseIdleConnections()
	return nil
}

// QueryResult contains the results of a DNS query
// (This matches the structure in dns/query.go)
type QueryResult struct {
	Domain    string
	Response  *dns.Msg
	RTT       time.Duration
	Server    string
	Error     error
	Answers   []string
	QueryTime time.Time
}
