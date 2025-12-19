package dns

import (
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// Server represents a DNS server that can listen on multiple protocols
type Server struct {
	domain     string
	responseIP net.IP
	ttl        uint32
	logQueries bool
	verbose    bool

	// Statistics
	mu         sync.Mutex
	queryCount uint64
	startTime  time.Time
}

// NewServer creates a new DNS server
func NewServer(domain string, responseIP string, ttl uint32, logQueries bool, verbose bool) (*Server, error) {
	// Parse the response IP
	ip := net.ParseIP(responseIP)
	if ip == nil {
		return nil, fmt.Errorf("invalid IP address: %s", responseIP)
	}

	return &Server{
		domain:     dns.Fqdn(domain), // Ensure FQDN format with trailing dot
		responseIP: ip,
		ttl:        ttl,
		logQueries: logQueries,
		verbose:    verbose,
		startTime:  time.Now(),
	}, nil
}

// ServeDNS handles incoming DNS queries
// This implements the dns.Handler interface from miekg/dns
func (s *Server) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	// Create a response message
	msg := new(dns.Msg)
	msg.SetReply(r) // This sets up the response properly (copies ID, question, etc.)

	// Increment query counter
	s.mu.Lock()
	s.queryCount++
	currentCount := s.queryCount
	s.mu.Unlock()

	// Log the query if enabled
	if s.logQueries && len(r.Question) > 0 {
		q := r.Question[0]
		clientAddr := w.RemoteAddr().String()

		fmt.Printf("[%s] Query #%d from %s\n",
			time.Now().Format("15:04:05"),
			currentCount,
			clientAddr)
		fmt.Printf("  └─ %s %s\n",
			dns.TypeToString[q.Qtype],
			q.Name)
	}

	// Process each question in the query
	// Usually there's only one question per query
	for _, question := range r.Question {
		s.handleQuestion(msg, &question)
	}

	// Set response code
	// If we added answers, it's success (NOERROR)
	// If no answers, it's NXDOMAIN (domain doesn't exist)
	if len(msg.Answer) > 0 {
		msg.SetRcode(r, dns.RcodeSuccess)
	} else {
		msg.SetRcode(r, dns.RcodeNameError) // NXDOMAIN
	}

	// Send the response
	if err := w.WriteMsg(msg); err != nil {
		log.Printf("Failed to write response: %v", err)
	}

	if s.verbose && len(msg.Answer) > 0 {
		fmt.Printf("  ✓ Sent %d answer(s)\n\n", len(msg.Answer))
	}
}

// handleQuestion processes a single DNS question
func (s *Server) handleQuestion(msg *dns.Msg, question *dns.Question) {
	// Check if the question is for our domain or a subdomain of it
	if !s.isOurDomain(question.Name) {
		// Not our domain, don't answer
		if s.verbose {
			fmt.Printf("  ⊘ Not our domain, ignoring\n\n")
		}
		return
	}

	// Handle different query types
	switch question.Qtype {
	case dns.TypeA:
		// A record query - return IPv4 address
		rr := &dns.A{
			Hdr: dns.RR_Header{
				Name:   question.Name,
				Rrtype: dns.TypeA,
				Class:  dns.ClassINET,
				Ttl:    s.ttl,
			},
			A: s.responseIP.To4(), // Convert to IPv4 format
		}
		msg.Answer = append(msg.Answer, rr)

	case dns.TypeAAAA:
		// AAAA record query - IPv6 (we don't support, so no answer)
		if s.verbose {
			fmt.Printf("  ⊘ AAAA query, no IPv6 support\n\n")
		}

	case dns.TypeNS:
		// Nameserver query - return our server as authoritative
		rr := &dns.NS{
			Hdr: dns.RR_Header{
				Name:   question.Name,
				Rrtype: dns.TypeNS,
				Class:  dns.ClassINET,
				Ttl:    s.ttl,
			},
			Ns: fmt.Sprintf("ns1.%s", s.domain),
		}
		msg.Answer = append(msg.Answer, rr)

	default:
		// Other query types - we don't support
		if s.verbose {
			fmt.Printf("  ⊘ Unsupported query type: %s\n\n",
				dns.TypeToString[question.Qtype])
		}
	}
}

// isOurDomain checks if a queried domain is our domain or a subdomain of it
func (s *Server) isOurDomain(name string) bool {
	name = dns.Fqdn(name) // Ensure trailing dot

	// Check exact match
	if name == s.domain {
		return true
	}

	// Check if it's a subdomain
	// For example: "abc123.timeserversync.test." is a subdomain of "timeserversync.test."
	if dns.IsSubDomain(s.domain, name) {
		return true
	}

	return false
}

// GetStats returns server statistics
func (s *Server) GetStats() (uint64, time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.queryCount, time.Since(s.startTime)
}

// PlainDNSServer wraps the Server for plain DNS (UDP) operation
type PlainDNSServer struct {
	handler   *Server
	udpServer *dns.Server
	address   string
}

// NewPlainDNSServer creates a server that listens on UDP
func NewPlainDNSServer(handler *Server, address string) *PlainDNSServer {
	return &PlainDNSServer{
		handler: handler,
		address: address,
	}
}

// Start begins listening for DNS queries
func (s *PlainDNSServer) Start() error {
	// Create UDP server
	s.udpServer = &dns.Server{
		Addr:    s.address,
		Net:     "udp",
		Handler: s.handler, // Use our handler for processing queries
	}

	fmt.Printf("Starting Plain DNS server on %s (UDP)\n", s.address)

	// ListenAndServe blocks until server stops
	if err := s.udpServer.ListenAndServe(); err != nil {
		return fmt.Errorf("failed to start UDP server: %w", err)
	}

	return nil
}

// Stop gracefully shuts down the server
func (s *PlainDNSServer) Stop() error {
	if s.udpServer != nil {
		return s.udpServer.Shutdown()
	}
	return nil
}
