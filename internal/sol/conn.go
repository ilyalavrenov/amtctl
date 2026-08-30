package sol

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"sync"
)

// Conn is one AMT redirection session carrying a serial-over-LAN stream.
type Conn struct {
	conn net.Conn

	user, pass string

	// AMT rejects interleaved frames, and the heartbeat reply is written from
	// the receive goroutine while keystrokes are written from the send one.
	wmu sync.Mutex
}

// Dial opens a redirection connection. useTLS selects port 16995 over 16994.
func Dial(ctx context.Context, host, user, pass string, useTLS bool) (*Conn, error) {
	port := "16994"
	if useTLS {
		port = "16995"
	}

	addr := net.JoinHostPort(host, port)
	dialer := &net.Dialer{}

	var (
		conn net.Conn
		err  error
	)

	if useTLS {
		// AMT ships a self-signed redirection certificate with no CA to pin
		// against.
		cfg := &tls.Config{InsecureSkipVerify: true} //nolint:gosec // see above
		conn, err = (&tls.Dialer{NetDialer: dialer, Config: cfg}).DialContext(ctx, "tcp", addr)
	} else {
		conn, err = dialer.DialContext(ctx, "tcp", addr)
	}

	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", addr, err)
	}

	return &Conn{conn: conn, user: user, pass: pass}, nil
}

// Close drops the connection without the protocol teardown.
func (c *Conn) Close() error {
	if err := c.conn.Close(); err != nil {
		return fmt.Errorf("close redirection connection: %w", err)
	}

	return nil
}

// write serializes sends.
func (c *Conn) write(b []byte) error {
	c.wmu.Lock()
	defer c.wmu.Unlock()

	_, err := c.conn.Write(b)

	return err //nolint:wrapcheck // callers name the message being written
}

// Open runs the full handshake: session start, authentication, SOL start.
func (c *Conn) Open() error {
	start := make([]byte, lenStartRedirectionSession)
	start[0] = msgStartRedirectionSession
	copy(start[4:], "SOL ")

	if err := c.write(start); err != nil {
		return fmt.Errorf("start redirection session: %w", err)
	}

	reply := make([]byte, lenStartRedirectionSessionReply)
	if _, err := io.ReadFull(c.conn, reply); err != nil {
		return fmt.Errorf("read session start reply: %w", err)
	}

	if reply[0] != msgStartRedirectionSessionReply {
		return fmt.Errorf("unexpected reply %#x to session start", reply[0])
	}

	if reply[1] != authStatusSuccess {
		return fmt.Errorf("redirection session refused (status %#x)", reply[1])
	}

	if err := c.authenticate(); err != nil {
		return err
	}

	return c.startSOL()
}
