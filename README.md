# DNS Encryption Simulator

Educational tool for demonstrating DNS tunneling across different encryption modes.

## Purpose

This simulator helps threat hunters and security defenders understand what network telemetry looks like when adversaries use different DNS encryption protocols for command-and-control communication.

## Modes

1. **Plain DNS** - Baseline, no encryption (UDP port 53)
2. **DNS-over-HTTPS (DoH)** - Encrypted via HTTPS (TCP port 443)
3. **DNS-over-TLS (DoT)** - Encrypted via TLS (TCP port 853)
4. **DNS-over-QUIC (DoQ)** - Encrypted via QUIC (UDP port 853)