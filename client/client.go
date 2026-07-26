package client

import (
	"time"

	"github.com/Saxy/Tellstone/internal/network"
)

// Client is a synchronous connection to a Tellstone server.
// Client methods must not be called concurrently.
type Client struct {
	c *network.Client
}

// Dial connects to a Tellstone server pool via the specified TCP address.
func Dial(addr string, timeout time.Duration) (*Client, error) {
	c, err := network.Dial(addr, timeout)
	if err != nil {
		return nil, err
	}
	return &Client{c: c}, nil
}

// DialTLS connects to a Tellstone server with TLS 1.3 encryption.
// certPath/keyPath are the client certificate and key for mTLS (pass empty for one-way TLS).
// caPath is the CA certificate to verify the server (pass empty to skip verification).
func DialTLS(addr string, certPath, keyPath, caPath string, timeout time.Duration) (*Client, error) {
	c, err := network.DialTLS(addr, certPath, keyPath, caPath, timeout)
	if err != nil {
		return nil, err
	}
	return &Client{c: c}, nil
}

// Close closes the underlying network connection.
// Calling Close on a nil client returns nil.
func (c *Client) Close() error {
	if c == nil || c.c == nil {
		return nil
	}
	return c.c.Close()
}

// Set stores a binary key-value pair with a millisecond-based TTL inside the remote engine.
func (c *Client) Set(key, value []byte, ttlMs int64, scratchBuf []byte) ([]byte, error) {
	if err := c.valid(); err != nil {
		return nil, err
	}
	return c.c.Set(key, value, ttlMs, scratchBuf)
}

// Get retrieves a binary value from the remote engine using its key identifier.
func (c *Client) Get(key []byte, scratchBuf []byte) ([]byte, error) {
	if err := c.valid(); err != nil {
		return nil, err
	}
	return c.c.Get(key, scratchBuf)
}

// Delete removes a key-value entity permanently from the remote cluster space.
func (c *Client) Delete(key []byte, scratchBuf []byte) ([]byte, error) {
	if err := c.valid(); err != nil {
		return nil, err
	}
	return c.c.Delete(key, scratchBuf)
}

func (c *Client) valid() error {
	if c == nil || c.c == nil {
		return ErrClientClosed
	}
	return nil
}
