/*
File: config.go
Description: Provides a gnet.Conn to net.Conn adapter for use with the TLS
handshake, and a config builder that constructs TLS configurations from
file paths. Supports TLS 1.3 and optional mTLS.
*/
package tls

import (
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"net"
	"os"
	"sync/atomic"
	"time"

	"github.com/panjf2000/gnet/v2"
)

// GnetConnAdapter wraps a gnet.Conn to satisfy net.Conn and expose the
// Peek/InboundBuffered methods that the TLS library requires for non-blocking
// handshake negotiation.
type GnetConnAdapter struct {
	c gnet.Conn
}

// NewGnetConnAdapter wraps a gnet.Conn so it can be passed to the TLS library.
func NewGnetConnAdapter(c gnet.Conn) *GnetConnAdapter {
	return &GnetConnAdapter{c: c}
}

func (a *GnetConnAdapter) Read(b []byte) (int, error) {
	buf, err := a.c.Peek(len(b))
	if len(buf) > 0 {
		n := copy(b, buf)
		_, _ = a.c.Discard(n)
		return n, nil
	}
	if err != nil {
		return 0, ErrNotEnough
	}
	return 0, nil
}

func (a *GnetConnAdapter) Write(b []byte) (int, error) {
	return a.c.Write(b)
}

func (a *GnetConnAdapter) Close() error {
	return a.c.Close()
}

func (a *GnetConnAdapter) LocalAddr() net.Addr  { return a.c.LocalAddr() }
func (a *GnetConnAdapter) RemoteAddr() net.Addr { return a.c.RemoteAddr() }

// SetDeadline is a no-op. Timeout enforcement is handled by the gnet event loop.
func (a *GnetConnAdapter) SetDeadline(t time.Time) error { return nil }

// SetReadDeadline is a no-op. Timeout enforcement is handled by the gnet event loop.
func (a *GnetConnAdapter) SetReadDeadline(t time.Time) error { return nil }

// SetWriteDeadline is a no-op. Timeout enforcement is handled by the gnet event loop.
func (a *GnetConnAdapter) SetWriteDeadline(t time.Time) error { return nil }

// Peek returns the next n bytes without advancing the read cursor.
// Required by the TLS library for non-blocking handshake negotiation.
func (a *GnetConnAdapter) Peek(n int) ([]byte, error) {
	return a.c.Peek(n)
}

// InboundBuffered returns the number of bytes currently buffered in the
// read buffer. Required by the TLS library for non-blocking handshake negotiation.
func (a *GnetConnAdapter) InboundBuffered() int {
	return a.c.InboundBuffered()
}

// ConfigStore publishes immutable TLS configurations to protocol listeners.
// Existing connections retain the configuration loaded when they were accepted;
// new connections observe the latest configuration after an atomic replacement.
type ConfigStore struct {
	current atomic.Pointer[Config]
}

// NewConfigStore returns a store initialized with cfg. A nil configuration is
// rejected because a reload must never downgrade an encrypted listener to plaintext.
func NewConfigStore(cfg *Config) (*ConfigStore, error) {
	if cfg == nil {
		return nil, fmt.Errorf("tls: config store requires a non-nil config")
	}
	store := new(ConfigStore)
	store.current.Store(cfg)
	return store, nil
}

// Load returns the immutable configuration used for the next accepted connection.
func (s *ConfigStore) Load() *Config {
	if s == nil {
		return nil
	}
	return s.current.Load()
}

// Store atomically publishes cfg for future connections.
func (s *ConfigStore) Store(cfg *Config) error {
	if s == nil || cfg == nil {
		return fmt.Errorf("tls: cannot store a nil config")
	}
	s.current.Store(cfg)
	return nil
}

// BuildConfig constructs a *Config from cert/key/CA file paths.
// If certPath and keyPath are empty, returns (nil, nil) to signal TLS is disabled.
// If caPath is non-empty, client certificate verification is enabled (mTLS).
// Forces TLS 1.3 as the minimum and maximum version.
func BuildConfig(certPath, keyPath, caPath string) (*Config, error) {
	cfg, _, err := loadConfig(certPath, keyPath, caPath)
	return cfg, err
}

// loadConfig reads a complete TLS snapshot and returns a content fingerprint.
// The fingerprint covers the certificate chain, private key, and optional client CA,
// so CA-only rotations and reused certificate serials are not mistaken for no-ops.
func loadConfig(certPath, keyPath, caPath string) (*Config, [sha256.Size]byte, error) {
	var fingerprint [sha256.Size]byte
	if (certPath == "") != (keyPath == "") {
		return nil, fingerprint, fmt.Errorf("tls: both cert and key are required")
	}
	if certPath == "" && keyPath == "" {
		return nil, fingerprint, nil
	}

	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fingerprint, fmt.Errorf("tls: failed to read certificate file: %w", err)
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fingerprint, fmt.Errorf("tls: failed to read key file: %w", err)
	}
	cert, err := X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fingerprint, fmt.Errorf("tls: failed to load certificate/key: %w", err)
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return nil, fingerprint, fmt.Errorf("tls: failed to parse leaf certificate: %w", err)
	}
	cert.Leaf = leaf

	cfg := &Config{
		Certificates: []Certificate{cert},
		MinVersion:   VersionTLS13,
		MaxVersion:   VersionTLS13,
	}

	var caPEM []byte
	if caPath != "" {
		caPEM, err = os.ReadFile(caPath)
		if err != nil {
			return nil, fingerprint, fmt.Errorf("tls: failed to read CA file: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caPEM) {
			return nil, fingerprint, fmt.Errorf("tls: failed to parse CA certificate")
		}
		cfg.ClientCAs = pool
		cfg.ClientAuth = RequireAndVerifyClientCert
	}

	h := sha256.New()
	_, _ = h.Write([]byte{0})
	_, _ = h.Write(certPEM)
	_, _ = h.Write([]byte{1})
	_, _ = h.Write(keyPEM)
	_, _ = h.Write([]byte{2})
	_, _ = h.Write(caPEM)
	copy(fingerprint[:], h.Sum(nil))
	return cfg, fingerprint, nil
}

// IsMTLS returns true if the config requires client certificate verification.
func IsMTLS(cfg *Config) bool {
	return cfg != nil && cfg.ClientAuth == RequireAndVerifyClientCert
}
