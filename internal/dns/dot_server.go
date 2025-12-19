package dns

import (
	"crypto/tls"
	"fmt"

	"github.com/miekg/dns"
)

// DoTServer handles DNS-over-TLS requests
type DoTServer struct {
	handler  *Server // Reuse our existing DNS handler
	server   *dns.Server
	address  string
	certFile string
	keyFile  string
}

// NewDoTServer creates a new DoT server
func NewDoTServer(handler *Server, address string, certFile string, keyFile string) *DoTServer {
	return &DoTServer{
		handler:  handler,
		address:  address,
		certFile: certFile,
		keyFile:  keyFile,
	}
}

// Start begins listening for DoT requests
func (s *DoTServer) Start() error {
	// Load TLS certificate
	cert, err := tls.LoadX509KeyPair(s.certFile, s.keyFile)
	if err != nil {
		return fmt.Errorf("failed to load TLS certificate: %w", err)
	}

	// Configure TLS
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
		CurvePreferences: []tls.CurveID{
			tls.CurveP256,
			tls.X25519,
		},
		PreferServerCipherSuites: true,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
		},
	}

	// Create DNS server with TLS
	// The miekg/dns library makes this very simple
	// We just specify "tcp-tls" as the network type
	s.server = &dns.Server{
		Addr:      s.address,
		Net:       "tcp-tls", // This enables TLS for incoming connections
		Handler:   s.handler, // Reuse our existing DNS handler
		TLSConfig: tlsConfig,
	}

	fmt.Printf("Starting DoT server on %s (TLS)\n", s.address)

	// Start listening
	// This blocks until server stops
	if err := s.server.ListenAndServe(); err != nil {
		return fmt.Errorf("failed to start DoT server: %w", err)
	}

	return nil
}

// Stop gracefully shuts down the server
func (s *DoTServer) Stop() error {
	if s.server != nil {
		return s.server.Shutdown()
	}
	return nil
}
