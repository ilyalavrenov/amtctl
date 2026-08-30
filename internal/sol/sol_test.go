package sol

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// dial opens a client against the fake firmware. Dial hardcodes the port, so it
// cannot be used here.
func dial(t *testing.T, s *redirServer, pass string) *Conn {
	t.Helper()

	conn, err := net.Dial("tcp", s.addr())
	require.NoError(t, err)
	require.NoError(t, conn.SetDeadline(time.Now().Add(testTimeout)))
	t.Cleanup(func() { _ = conn.Close() })

	return &Conn{conn: conn, user: testUser, pass: pass}
}

// idle stands in for a console nobody is typing at. Run's input goroutine only
// unblocks on the next read, so the reader releases at test end.
func idle(t *testing.T) io.Reader {
	t.Helper()

	done := make(chan struct{})
	t.Cleanup(func() { close(done) })

	return blockedReader{done}
}

type blockedReader struct{ done <-chan struct{} }

func (b blockedReader) Read([]byte) (int, error) {
	<-b.done

	return 0, io.EOF
}

// solFrame builds one SOL data message.
func solFrame(kind byte, payload string) []byte {
	frame := make([]byte, lenSOLDataHeader+len(payload))
	frame[0] = kind
	binary.LittleEndian.PutUint16(frame[8:10], uint16(len(payload)))
	copy(frame[lenSOLDataHeader:], payload)

	return frame
}

func heartbeat() []byte {
	frame := make([]byte, lenHeartbeat)
	frame[0] = msgSOLHeartbeat

	return frame
}

// teardown is the END_SOL_REDIRECTION message Run sends before it closes.
func teardown() []byte {
	frame := make([]byte, lenHeartbeat)
	frame[0] = msgEndSOLRedirection

	return frame
}

// The full handshake against a device answering the qop list "auth,auth-int".
func TestOpenHandshake(t *testing.T) {
	t.Parallel()

	s := newServer(t, firmware())
	c := dial(t, s, testPass)

	require.NoError(t, c.Open())
	require.NoError(t, c.Close())

	s.wait(t)

	// The firmware recomputed the response, so a digestResponse regression
	// surfaces as a mismatch.
	assert.Equal(t, s.digestWant, s.digestGot)
	assert.NotEmpty(t, s.digestWant, "the digest exchange has to have happened")
}

func TestOpenAuthentication(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name    string
		methods []byte
		qop     string
		pass    string
		wantErr string
	}{
		{name: "rfc2617 with a qop list", methods: []byte{authPlain, authRFC2069, authRFC2617}, qop: "auth,auth-int"},
		{name: "rfc2617 with a single qop", methods: []byte{authRFC2617}, qop: "auth"},
		{name: "rfc2069 when 2617 is not offered", methods: []byte{authPlain, authRFC2069}},
		{name: "plain when digest is not offered", methods: []byte{authPlain}},
		{name: "qop auth-int alone", methods: []byte{authRFC2617}, qop: "auth-int", wantErr: `offered qop "auth-int", need auth`},
		{name: "no method in common", methods: []byte{0x02}, wantErr: "no supported auth method"},
		{name: "wrong password", methods: []byte{authRFC2617}, qop: "auth", pass: "hunter2", wantErr: "rejected the credentials"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			cfg := firmware()
			cfg.methods = tc.methods

			if tc.qop != "" {
				cfg.qop = tc.qop
			}

			pass := testPass
			if tc.pass != "" {
				pass = tc.pass
			}

			err := dial(t, newServer(t, cfg), pass).Open()

			if tc.wantErr != "" {
				require.ErrorContains(t, err, tc.wantErr)

				return
			}

			assert.NoError(t, err)
		})
	}
}

// A heartbeat or controls message landing between two data frames must not
// desynchronize the parser.
func TestRunStreamsConsoleOutput(t *testing.T) {
	t.Parallel()

	controls := make([]byte, lenSOLControlsFromHost)
	controls[0] = msgSOLControlsFromHost

	end := make([]byte, lenEndSOLRedirectionReply)
	end[0] = msgEndSOLRedirectionReply

	cfg := firmware()
	cfg.stream = bytes.Join([][]byte{
		solFrame(msgSOLDataFromHost, "boot"),
		heartbeat(),
		controls,
		solFrame(msgSOLDataFromHost, "ing..."),
		heartbeat(),
		end,
	}, nil)

	s := newServer(t, cfg)
	c := dial(t, s, testPass)
	require.NoError(t, c.Open())

	var out bytes.Buffer

	require.NoError(t, c.Run(t.Context(), idle(t), &out), "the firmware ended the session cleanly")
	assert.Equal(t, "booting...", out.String())

	s.wait(t)

	// Heartbeats must come back verbatim or the firmware drops the session.
	assert.Equal(t, bytes.Join([][]byte{heartbeat(), heartbeat(), teardown()}, nil), s.received)
}

func TestRunDetachesOnEscape(t *testing.T) {
	t.Parallel()

	s := newServer(t, firmware())
	c := dial(t, s, testPass)
	require.NoError(t, c.Open())

	var out bytes.Buffer

	input := "hi" + string(rune(EscapeByte)) + "not sent"
	require.NoError(t, c.Run(t.Context(), strings.NewReader(input), &out), "a detach is a clean exit")

	s.wait(t)

	// Everything before the escape byte reaches the host and nothing after it.
	assert.Equal(t, append(solFrame(msgSOLDataToHost, "hi"), teardown()...), s.received)
}

func TestRunEndsOnRemoteHangUp(t *testing.T) {
	t.Parallel()

	cfg := firmware()
	cfg.stream = solFrame(msgSOLDataFromHost, "bye")
	cfg.hangUp = true

	c := dial(t, newServer(t, cfg), testPass)
	require.NoError(t, c.Open())

	var out bytes.Buffer

	require.NoError(t, c.Run(t.Context(), idle(t), &out), "the host closing the console is not a failure")
	assert.Equal(t, "bye", out.String())
}

func TestSendChunksAtTransmitBuffer(t *testing.T) {
	t.Parallel()

	s := newServer(t, firmware())
	c := dial(t, s, testPass)
	require.NoError(t, c.Open())

	payload := strings.Repeat("x", maxTransmitBuffer+7)
	require.NoError(t, c.send([]byte(payload)))
	require.NoError(t, c.Close())

	s.wait(t)

	full := solFrame(msgSOLDataToHost, payload[:maxTransmitBuffer])
	rest := solFrame(msgSOLDataToHost, payload[maxTransmitBuffer:])

	assert.Equal(t, append(full, rest...), s.received)
}

// A data frame arriving in pieces must be reassembled by its declared length.
// net.Pipe delivers each write as its own read; TCP cannot guarantee the split.
func TestReceiveReassemblesSplitFrame(t *testing.T) {
	t.Parallel()

	client, server := net.Pipe()
	t.Cleanup(func() { _ = client.Close() })
	require.NoError(t, client.SetDeadline(time.Now().Add(testTimeout)))

	frame := solFrame(msgSOLDataFromHost, "hello")

	go func() {
		defer server.Close()

		for _, chunk := range [][]byte{frame[:3], frame[3:12], frame[12:]} {
			if _, err := server.Write(chunk); err != nil {
				return
			}
		}
	}()

	c := &Conn{conn: client}

	var out bytes.Buffer

	require.ErrorIs(t, c.receive(&out), io.EOF, "the stream ends after one whole frame")
	assert.Equal(t, "hello", out.String())
}

// authRequest's declared payload length must match the bytes that follow it, or
// the firmware reads the next message at the wrong offset.
func TestAuthRequestEncoding(t *testing.T) {
	t.Parallel()

	b, err := authRequest(authRFC2617, "admin", "", "", digestURI, "", "", "", "")
	require.NoError(t, err)

	assert.Equal(t, []byte{msgAuthenticateSession, 0, 0, 0, authRFC2617}, b[:5], "message header")

	declared := int(binary.LittleEndian.Uint32(b[5:lenAuthHeader]))
	assert.Equal(t, len(b)-lenAuthHeader, declared, "declared payload length vs. bytes written")

	// Eight elements, each with a one-byte length prefix.
	assert.Equal(t, len("admin")+len(digestURI)+8, declared)

	elements, err := parseElements(b[lenAuthHeader:])
	require.NoError(t, err)
	assert.Equal(t, []string{"admin", "", "", digestURI, "", "", "", ""}, elements)
}

func TestHasQOPAuth(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name string
		qop  string
		want bool
	}{
		{"single value", "auth", true},
		{"list", "auth,auth-int", true},
		{"list with spaces", "auth-int, auth", true},
		{"auth-int only", "auth-int", false},
		{"empty", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			assert.Equal(t, tc.want, hasQOPAuth(tc.qop), "hasQOPAuth(%q)", tc.qop)
		})
	}
}

// Known-answer check, so a refactor cannot silently change what is sent.
func TestDigestResponseKnownAnswer(t *testing.T) {
	t.Parallel()

	got := digestResponse(authRFC2617, "admin", "P@ssw0rd", "Digest:AF000000",
		"0000000f", "0123456789abcdef0123456789abcdef", "auth")

	assert.Equal(t, "f7adb15fa517806a266166b685f0f149", got)
}

// An over-long element must be rejected, not silently truncated by the
// single-byte length prefix.
func TestAuthRequestRejectsOverlongElement(t *testing.T) {
	t.Parallel()

	_, err := authRequest(authRFC2617, "admin", strings.Repeat("a", maxElementLen+1))
	require.Error(t, err, "element longer than the length prefix can encode")

	_, err = authRequest(authRFC2617, "admin", strings.Repeat("a", maxElementLen))
	assert.NoError(t, err, "element of exactly the maximum length")
}
