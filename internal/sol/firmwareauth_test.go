package sol

import (
	"fmt"
	"net"
)

func (s *redirServer) authenticate(conn net.Conn) (bool, error) {
	method, _, err := readAuthRequest(conn)
	if err != nil {
		return false, err
	}

	if method != authQueryMethods {
		return false, fmt.Errorf("first auth request used method %#x, want the method query", method)
	}

	if _, err := conn.Write(authReply(authStatusSuccess, authQueryMethods, s.cfg.methods)); err != nil {
		return false, err
	}

	method, elements, err := readAuthRequest(conn)
	if err != nil {
		return false, err
	}

	switch method {
	case authPlain:
		return s.finishAuth(conn, method, len(elements) == 2 && elements[0] == s.cfg.user && elements[1] == s.cfg.pass)
	case authRFC2069, authRFC2617:
		return s.challenge(conn, method, elements)
	default:
		return false, fmt.Errorf("client picked auth method %#x, which was not offered", method)
	}
}

// challenge answers the digest probe on a failure status, as the firmware does,
// then checks the response that follows.
func (s *redirServer) challenge(conn net.Conn, method byte, probe []string) (bool, error) {
	if len(probe) == 0 || probe[0] != s.cfg.user {
		return false, fmt.Errorf("digest probe carried %q as the username", probe)
	}

	elements := []string{s.cfg.realm, s.cfg.nonce}
	if method == authRFC2617 {
		elements = append(elements, s.cfg.qop)
	}

	if _, err := conn.Write(authReply(authStatusFail, method, encodeElements(elements...))); err != nil {
		return false, err
	}

	replied, response, err := readAuthRequest(conn)
	if err != nil {
		return false, err
	}

	if replied != method {
		return false, fmt.Errorf("digest response used method %#x, want %#x", replied, method)
	}

	ok, err := s.verifyDigest(method, response)
	if err != nil {
		return false, err
	}

	return s.finishAuth(conn, method, ok)
}

// verifyDigest recomputes the response by hand rather than through
// digestResponse, so a regression there cannot cancel itself out.
func (s *redirServer) verifyDigest(method byte, e []string) (bool, error) {
	want := 7
	if method == authRFC2617 {
		want = 8
	}

	if len(e) != want {
		return false, fmt.Errorf("digest response has %d elements, want %d", len(e), want)
	}

	if e[1] != s.cfg.realm || e[2] != s.cfg.nonce {
		return false, fmt.Errorf("digest response echoed realm %q nonce %q", e[1], e[2])
	}

	if e[3] != "/RedirectionService" {
		return false, fmt.Errorf("digest response used URI %q", e[3])
	}

	// The firmware accepts one nonce count and only the qop value the client
	// committed to hashing.
	if e[5] != "00000002" {
		return false, fmt.Errorf("digest response used nonce count %q", e[5])
	}

	if method == authRFC2617 && e[7] != "auth" {
		return false, fmt.Errorf("digest response used qop %q, want the narrowed value", e[7])
	}

	ha1 := md5sum(s.cfg.user + ":" + s.cfg.realm + ":" + s.cfg.pass)
	ha2 := md5sum("POST:/RedirectionService")

	s.digestWant = md5sum(ha1 + ":" + e[2] + ":" + ha2)
	if method == authRFC2617 {
		s.digestWant = md5sum(ha1 + ":" + e[2] + ":" + e[5] + ":" + e[4] + ":" + e[7] + ":" + ha2)
	}

	s.digestGot = e[6]

	return e[0] == s.cfg.user && s.digestGot == s.digestWant, nil
}

func (s *redirServer) finishAuth(conn net.Conn, method byte, ok bool) (bool, error) {
	status := byte(authStatusFail)
	if ok {
		status = authStatusSuccess
	}

	_, err := conn.Write(authReply(status, method, nil))

	return ok, err
}
