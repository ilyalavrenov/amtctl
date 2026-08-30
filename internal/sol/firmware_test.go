package sol

import (
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// Credentials and challenge values the fake firmware is configured with.
const (
	testUser  = "admin"
	testPass  = "P@ssw0rd"
	testRealm = "Digest:A4070000000000000000000000000000"
	testNonce = "1qtFAg8AAAAAAAAAdMWkxSHtVaGjSQPn"

	// testTimeout bounds every socket operation, so a protocol mistake fails
	// instead of hanging the suite.
	testTimeout = 10 * time.Second
)

// serverConfig scripts one fake firmware endpoint.
type serverConfig struct {
	methods []byte // auth methods answered to the method query
	realm   string
	nonce   string
	qop     string // third challenge element, RFC 2617 only
	user    string
	pass    string
	stream  []byte // written to the client once the SOL session is open
	hangUp  bool   // half-close after the stream instead of waiting for a teardown
}

// firmware accepts the test credentials over RFC 2617 and answers a qop list.
func firmware() serverConfig {
	return serverConfig{
		methods: []byte{authPlain, authRFC2069, authRFC2617},
		realm:   testRealm,
		nonce:   testNonce,
		qop:     "auth,auth-int",
		user:    testUser,
		pass:    testPass,
	}
}

// redirServer is a TCP listener speaking the firmware half of the redirection
// protocol. Its recorded fields are written by the serving goroutine, so read
// them only after wait returns.
type redirServer struct {
	cfg  serverConfig
	ln   net.Listener
	done chan struct{}

	err      error  // first protocol violation seen
	received []byte // everything the client wrote once the SOL session was open

	// Both sides of the RFC 2617 comparison, so a regression shows the hashes
	// rather than a bare authentication failure.
	digestGot, digestWant string
}

// newServer starts a fake firmware on a loopback port. It serves one connection
// and is closed, and its protocol errors reported, at test end.
func newServer(t *testing.T, cfg serverConfig) *redirServer {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	s := &redirServer{cfg: cfg, ln: ln, done: make(chan struct{})}

	go s.accept()

	t.Cleanup(func() {
		_ = ln.Close()

		s.wait(t)

		if s.err != nil {
			t.Errorf("fake firmware: %v", s.err)
		}
	})

	return s
}

func (s *redirServer) addr() string {
	return s.ln.Addr().String()
}

// wait blocks until the firmware is done, which makes its recorded fields safe
// to read.
func (s *redirServer) wait(t *testing.T) {
	t.Helper()

	select {
	case <-s.done:
	case <-time.After(testTimeout):
		t.Fatal("fake firmware never finished")
	}
}

func (s *redirServer) accept() {
	defer close(s.done)

	conn, err := s.ln.Accept()
	if err != nil {
		return // the listener closed before a client arrived
	}

	defer conn.Close()

	if err := conn.SetDeadline(time.Now().Add(testTimeout)); err != nil {
		s.err = err

		return
	}

	s.serve(conn)
}

func (s *redirServer) serve(conn net.Conn) {
	authenticated, err := s.handshake(conn)
	if err != nil {
		// A client that gave up mid-handshake hangs up; that is how the negative
		// tests end.
		if !hungUp(err) {
			s.err = err
		}

		return
	}

	if !authenticated {
		return
	}

	read := make(chan struct{})

	go func() {
		defer close(read)

		buf := make([]byte, inputBufferSize)

		for {
			n, err := conn.Read(buf)
			s.received = append(s.received, buf[:n]...)

			if err != nil {
				return
			}
		}
	}()

	if _, err := conn.Write(s.cfg.stream); err != nil {
		s.err = err
	}

	// A half-close is a clean remote EOF: bytes already written still reach the
	// client, unlike Close.
	if tcp, ok := conn.(*net.TCPConn); s.cfg.hangUp && ok {
		_ = tcp.CloseWrite()
	}

	<-read
}

// handshake runs the firmware side up to an open SOL session. False means the
// credentials were refused, which is not a protocol error.
func (s *redirServer) handshake(conn net.Conn) (bool, error) {
	if err := s.startSession(conn); err != nil {
		return false, err
	}

	authenticated, err := s.authenticate(conn)
	if err != nil || !authenticated {
		return false, err
	}

	return true, s.startSOL(conn)
}

func (s *redirServer) startSession(conn net.Conn) error {
	req := make([]byte, lenStartRedirectionSession)
	if err := readFull(conn, req, "session start"); err != nil {
		return err
	}

	if req[0] != msgStartRedirectionSession {
		return fmt.Errorf("session start has type %#x", req[0])
	}

	if name := string(req[4:]); name != "SOL " {
		return fmt.Errorf("session start names %q, want %q", name, "SOL ")
	}

	reply := make([]byte, lenStartRedirectionSessionReply)
	reply[0] = msgStartRedirectionSessionReply
	reply[1] = authStatusSuccess

	_, err := conn.Write(reply)

	return err
}

func (s *redirServer) startSOL(conn net.Conn) error {
	req := make([]byte, lenStartSOLRedirection)
	if err := readFull(conn, req, "SOL start"); err != nil {
		return err
	}

	if req[0] != msgStartSOLRedirection {
		return fmt.Errorf("SOL start has type %#x", req[0])
	}

	reply := make([]byte, lenStartSOLRedirectionReply)
	reply[0] = msgStartSOLRedirectionReply
	reply[1] = authStatusSuccess

	_, err := conn.Write(reply)

	return err
}
