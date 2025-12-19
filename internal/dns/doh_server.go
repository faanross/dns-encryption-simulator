package dns

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"time"

	"github.com/miekg/dns"
)

// DoHServer handles DNS-over-HTTPS requests
type DoHServer struct {
	handler    *Server // Reuse our existing DNS handler
	httpServer *http.Server
	address    string
	certFile   string
	keyFile    string
}

// NewDoHServer creates a new DoH server
func NewDoHServer(handler *Server, address string, certFile string, keyFile string) *DoHServer {
	return &DoHServer{
		handler:  handler,
		address:  address,
		certFile: certFile,
		keyFile:  keyFile,
	}
}

// Start begins listening for DoH requests
func (s *DoHServer) Start() error {
	// Create HTTP server with DoH handler
	mux := http.NewServeMux()

	// RFC 8484 specifies /dns-query as the standard endpoint
	mux.HandleFunc("/dns-query", s.handleDoHRequest)

	// Also handle root for easier testing
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(http.StatusOK)
			fmt.Fprintf(w, "DNS-over-HTTPS Server\nUse /dns-query endpoint for DNS queries\n")
			return
		}
		http.NotFound(w, r)
	})

	// Configure TLS
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
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

	s.httpServer = &http.Server{
		Addr:         s.address,
		Handler:      mux,
		TLSConfig:    tlsConfig,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	fmt.Printf("Starting DoH server on %s (HTTPS)\n", s.address)

	// Start HTTPS server
	// This blocks until server stops
	if err := s.httpServer.ListenAndServeTLS(s.certFile, s.keyFile); err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("failed to start HTTPS server: %w", err)
	}

	return nil
}

// handleDoHRequest processes a DNS-over-HTTPS request
func (s *DoHServer) handleDoHRequest(w http.ResponseWriter, r *http.Request) {
	// Only accept POST for now (most common)
	// GET is also valid per RFC 8484 but less common
	if r.Method != http.MethodPost {
		http.Error(w, "Only POST method supported", http.StatusMethodNotAllowed)
		return
	}

	// Verify content type
	contentType := r.Header.Get("Content-Type")
	if contentType != "application/dns-message" {
		http.Error(w, "Content-Type must be application/dns-message", http.StatusBadRequest)
		return
	}

	// Read DNS message from request body
	body, err := io.ReadAll(r.Body)
	if err != nil {
		log.Printf("Failed to read request body: %v", err)
		http.Error(w, "Failed to read request", http.StatusBadRequest)
		return
	}

	// Unpack DNS query from wire format
	query := new(dns.Msg)
	if err := query.Unpack(body); err != nil {
		log.Printf("Failed to unpack DNS message: %v", err)
		http.Error(w, "Invalid DNS message", http.StatusBadRequest)
		return
	}

	// Create a response message
	response := new(dns.Msg)
	response.SetReply(query)

	// Use our existing DNS handler logic
	// We'll create a fake ResponseWriter that captures the DNS response
	dnsWriter := &dohResponseWriter{
		response: response,
	}

	// Process the query using our existing handler
	s.handler.ServeDNS(dnsWriter, query)

	// Pack the DNS response into wire format
	responseBytes, err := response.Pack()
	if err != nil {
		log.Printf("Failed to pack DNS response: %v", err)
		http.Error(w, "Failed to create response", http.StatusInternalServerError)
		return
	}

	// Send HTTP response with DNS message
	w.Header().Set("Content-Type", "application/dns-message")
	w.WriteHeader(http.StatusOK)
	w.Write(responseBytes)
}

// Stop gracefully shuts down the server
func (s *DoHServer) Stop() error {
	if s.httpServer != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return s.httpServer.Shutdown(ctx)
	}
	return nil
}

// dohResponseWriter implements dns.ResponseWriter for DoH
// This allows us to reuse our existing DNS handler logic
type dohResponseWriter struct {
	response *dns.Msg
}

func (w *dohResponseWriter) WriteMsg(m *dns.Msg) error {
	// Copy the response
	w.response = m
	return nil
}

func (w *dohResponseWriter) Write([]byte) (int, error) {
	return 0, fmt.Errorf("Write not supported in DoH")
}

func (w *dohResponseWriter) LocalAddr() net.Addr {
	return nil
}

func (w *dohResponseWriter) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0}
}

func (w *dohResponseWriter) TsigStatus() error {
	return nil
}

func (w *dohResponseWriter) TsigTimersOnly(bool) {}

func (w *dohResponseWriter) Hijack() {}

func (w *dohResponseWriter) Close() error {
	return nil
}
