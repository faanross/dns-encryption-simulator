package modes

import (
	"context"
	"time"

	"github.com/miekg/dns"
)

// DNSClient is an interface that both Plain DNS and DoH clients implement
// This allows the beacon to work with any DNS transport
type DNSClient interface {
	Query(ctx context.Context, domain string) (*QueryResult, error)
	Close() error
}

// Ensure both client types implement the interface
var (
	_ DNSClient = (*PlainDNSClientAdapter)(nil)
	_ DNSClient = (*DoHClient)(nil)
)

// PlainDNSClientAdapter adapts the plain DNS client to the DNSClient interface
type PlainDNSClientAdapter struct {
	client   *dns.Client
	resolver string
}

// NewPlainDNSClientAdapter creates an adapter for plain DNS
func NewPlainDNSClientAdapter(resolver string, timeout time.Duration) *PlainDNSClientAdapter {
	client := &dns.Client{
		Net:     "udp",
		Timeout: timeout,
		UDPSize: 4096,
	}

	return &PlainDNSClientAdapter{
		client:   client,
		resolver: resolver,
	}
}

// Query sends a plain DNS query
func (c *PlainDNSClientAdapter) Query(ctx context.Context, domain string) (*QueryResult, error) {
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(domain), dns.TypeA)
	msg.RecursionDesired = true

	queryTime := time.Now()
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

	if err != nil {
		return result, err
	}

	if response == nil {
		return result, nil
	}

	for _, answer := range response.Answer {
		if a, ok := answer.(*dns.A); ok {
			result.Answers = append(result.Answers, a.A.String())
		}
	}

	return result, nil
}

// Close cleans up resources
func (c *PlainDNSClientAdapter) Close() error {
	return nil
}
