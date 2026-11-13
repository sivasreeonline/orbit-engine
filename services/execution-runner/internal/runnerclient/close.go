package runnerclient

import (
	"crypto/ed25519"
	"net/http"
)

// Close clears the client's in-memory signing key and closes idle transport
// connections. The caller must stop all client operations before calling Close.
func (c *Client) Close() error {
	if c == nil {
		return nil
	}
	for index := range c.privateKey {
		c.privateKey[index] = 0
	}
	c.privateKey = ed25519.PrivateKey(nil)
	if c.httpClient == nil {
		return nil
	}
	transport, ok := c.httpClient.Transport.(*http.Transport)
	if !ok || transport == nil {
		return nil
	}
	transport.CloseIdleConnections()
	return nil
}
