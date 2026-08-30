package sol

import (
	"crypto/md5" //nolint:gosec // MD5 is mandated by the AMT redirection digest handshake
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"
)

// authRequest builds an AUTHENTICATE_SESSION message whose payload is a series
// of length-prefixed elements.
func authRequest(method byte, elements ...string) ([]byte, error) {
	n := 0

	for _, e := range elements {
		// The length prefix is one byte, so an over-long element would be
		// silently truncated. realm and nonce come from the firmware, so this
		// is a trust boundary.
		if len(e) > maxElementLen {
			return nil, fmt.Errorf("auth element of %d bytes exceeds the %d-byte limit", len(e), maxElementLen)
		}

		n += 1 + len(e)
	}

	b := make([]byte, lenAuthHeader, lenAuthHeader+n)
	b[0] = msgAuthenticateSession
	b[4] = method
	binary.LittleEndian.PutUint32(b[5:lenAuthHeader], uint32(n))

	for _, e := range elements {
		b = append(b, byte(len(e))) //nolint:gosec // bounded by the maxElementLen check above
		b = append(b, e...)
	}

	return b, nil
}

func (c *Conn) writeAuth(method byte, elements ...string) error {
	msg, err := authRequest(method, elements...)
	if err != nil {
		return err
	}

	return c.write(msg)
}

func (c *Conn) readAuthReply(method byte) (byte, []byte, error) {
	header := make([]byte, lenAuthHeader)
	if _, err := io.ReadFull(c.conn, header); err != nil {
		return 0, nil, fmt.Errorf("read auth reply header: %w", err)
	}

	if header[0] != msgAuthenticateSessionReply {
		return 0, nil, fmt.Errorf("unexpected reply %#x during authentication", header[0])
	}

	if header[4] != method {
		return 0, nil, fmt.Errorf("auth reply for method %#x, expected %#x", header[4], method)
	}

	n := binary.LittleEndian.Uint32(header[5:lenAuthHeader])
	if n > maxAuthPayload {
		return 0, nil, fmt.Errorf("auth reply payload too large (%d bytes)", n)
	}

	payload := make([]byte, n)
	if _, err := io.ReadFull(c.conn, payload); err != nil {
		return 0, nil, fmt.Errorf("read auth reply payload: %w", err)
	}

	return header[1], payload, nil
}

func parseElements(b []byte) ([]string, error) {
	var out []string

	for len(b) > 0 {
		n := int(b[0])
		if 1+n > len(b) {
			return nil, errors.New("truncated element in auth payload")
		}

		out = append(out, string(b[1:1+n]))
		b = b[1+n:]
	}

	return out, nil
}

func (c *Conn) authenticate() error {
	if err := c.writeAuth(authQueryMethods); err != nil {
		return fmt.Errorf("query auth methods: %w", err)
	}

	status, payload, err := c.readAuthReply(authQueryMethods)
	if err != nil {
		return err
	}

	if status != authStatusSuccess {
		return fmt.Errorf("auth method query refused (status %#x)", status)
	}

	offered := make(map[byte]bool, len(payload))
	for _, m := range payload {
		offered[m] = true
	}

	switch {
	case offered[authRFC2617]:
		return c.authDigest(authRFC2617)
	case offered[authRFC2069]:
		return c.authDigest(authRFC2069)
	case offered[authPlain]:
		return c.authPlain()
	default:
		return fmt.Errorf("no supported auth method offered (got %v)", payload)
	}
}

func (c *Conn) authPlain() error {
	if err := c.writeAuth(authPlain, c.user, c.pass); err != nil {
		return fmt.Errorf("send plain auth: %w", err)
	}

	return c.expectAuthSuccess(authPlain)
}

// hasQOPAuth reports whether the server's qop list includes "auth". Firmware
// answers a list ("auth,auth-int"), not a bare value.
func hasQOPAuth(qop string) bool {
	for v := range strings.SplitSeq(qop, ",") {
		if strings.TrimSpace(v) == "auth" {
			return true
		}
	}

	return false
}

func md5hex(parts ...string) string {
	sum := md5.Sum([]byte(strings.Join(parts, ":"))) //nolint:gosec // see the package import

	return hex.EncodeToString(sum[:])
}

// challenge asks for the digest parameters. AMT answers with a failure status
// carrying realm, nonce and qop; that is the handshake, not a rejection.
func (c *Conn) challenge(method byte) (realm, nonce, qop string, err error) { //nolint:nonamedreturns // three same-typed results
	probe := []string{c.user, "", "", digestURI, "", "", ""}
	if method == authRFC2617 {
		probe = append(probe, "")
	}

	if werr := c.writeAuth(method, probe...); werr != nil {
		return "", "", "", fmt.Errorf("send digest probe: %w", werr)
	}

	status, payload, rerr := c.readAuthReply(method)
	if rerr != nil {
		return "", "", "", rerr
	}

	if status != authStatusFail {
		return "", "", "", fmt.Errorf("expected digest challenge, got status %#x", status)
	}

	elements, perr := parseElements(payload)
	if perr != nil {
		return "", "", "", perr
	}

	if len(elements) < 2 {
		return "", "", "", fmt.Errorf("digest challenge has %d elements, need realm and nonce", len(elements))
	}

	if len(elements) > 2 {
		qop = elements[2]
	}

	return elements[0], elements[1], qop, nil
}

// digestResponse computes the response element for the redirection digest.
// RFC 2617 folds the nonce count, cnonce and qop into the hash; RFC 2069 does not.
func digestResponse(method byte, user, pass, realm, nonce, cnonce, qop string) string {
	ha1 := md5hex(user, realm, pass)
	ha2 := md5hex(digestMethod, digestURI)

	if method == authRFC2617 {
		return md5hex(ha1, nonce, digestNC, cnonce, qop, ha2)
	}

	return md5hex(ha1, nonce, ha2)
}

func (c *Conn) authDigest(method byte) error {
	realm, nonce, qop, err := c.challenge(method)
	if err != nil {
		return err
	}

	if method == authRFC2617 {
		if !hasQOPAuth(qop) {
			return fmt.Errorf("server offered qop %q, need auth", qop)
		}

		qop = "auth"
	}

	cnonce, err := randomHex(cnonceBytes)
	if err != nil {
		return err
	}

	response := digestResponse(method, c.user, c.pass, realm, nonce, cnonce, qop)

	reply := []string{c.user, realm, nonce, digestURI, cnonce, digestNC, response}
	if method == authRFC2617 {
		reply = append(reply, qop)
	}

	if err := c.writeAuth(method, reply...); err != nil {
		return fmt.Errorf("send digest response: %w", err)
	}

	return c.expectAuthSuccess(method)
}

func (c *Conn) expectAuthSuccess(method byte) error {
	status, _, err := c.readAuthReply(method)
	if err != nil {
		return err
	}

	if status != authStatusSuccess {
		return fmt.Errorf("AMT rejected the credentials (auth status %#x)", status)
	}

	return nil
}

func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate cnonce: %w", err)
	}

	return hex.EncodeToString(b), nil
}
