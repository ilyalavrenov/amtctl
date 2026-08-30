package amt

import (
	"crypto/md5" //nolint:gosec // MD5 is the only algorithm AMT's WSMAN digest offers
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
)

// cnonceBytes is the client nonce length. RFC 2617 leaves it to the client.
const cnonceBytes = 8

// digest answers AMT's RFC 2617 challenge. AMT offers no other scheme on the
// WSMAN port, so the first request goes out unauthenticated and the 401 it
// draws primes the credentials for every later one.
type digest struct {
	next       http.RoundTripper
	user, pass string

	mu    sync.Mutex
	realm string
	nonce string
	nc    uint64
}

func (d *digest) RoundTrip(req *http.Request) (*http.Response, error) {
	res, err := d.attempt(req)
	if err != nil || res.StatusCode != http.StatusUnauthorized {
		return res, err
	}

	challenge := res.Header.Get("WWW-Authenticate")

	// Drain before closing so the connection stays reusable; AMT allows few.
	_, _ = io.Copy(io.Discard, res.Body) //nolint:errcheck // draining is best effort
	_ = res.Body.Close()

	if err := d.prime(challenge); err != nil {
		return nil, err
	}

	return d.attempt(req)
}

// attempt sends a fresh copy of req. RoundTrip must not touch its argument, and
// the retry needs the body rewound.
func (d *digest) attempt(req *http.Request) (*http.Response, error) {
	auth, err := d.authorization(req.URL.RequestURI())
	if err != nil {
		return nil, err
	}

	body, err := req.GetBody()
	if err != nil {
		return nil, fmt.Errorf("rewind request body: %w", err)
	}

	out := req.Clone(req.Context())
	out.Body = body

	if auth != "" {
		out.Header.Set("Authorization", auth)
	}

	return d.next.RoundTrip(out) //nolint:wrapcheck // the caller names the request
}

// authorization returns the header for uri, or "" before the first challenge.
func (d *digest) authorization(uri string) (string, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.realm == "" {
		return "", nil
	}

	cnonce, err := randomHex(cnonceBytes)
	if err != nil {
		return "", err
	}

	d.nc++
	nc := fmt.Sprintf("%08x", d.nc)

	ha1 := md5hex(d.user, d.realm, d.pass)
	ha2 := md5hex(http.MethodPost, uri)

	parts := []string{
		`username="` + d.user + `"`,
		`realm="` + d.realm + `"`,
		`nonce="` + d.nonce + `"`,
		`uri="` + uri + `"`,
		`response="` + md5hex(ha1, d.nonce, nc, cnonce, "auth", ha2) + `"`,
		// nc is unquoted in RFC 2617, but AMT's parser expects the quoted form
		// its own tooling sends.
		`qop="auth"`, `nc="` + nc + `"`, `cnonce="` + cnonce + `"`,
	}

	return "Digest " + strings.Join(parts, ","), nil
}

// prime records the parameters of a challenge. A fresh nonce restarts the
// count, which the server uses to reject replays.
func (d *digest) prime(challenge string) error {
	rest, ok := strings.CutPrefix(strings.TrimSpace(challenge), "Digest ")
	if !ok {
		return fmt.Errorf("unsupported authentication challenge %q", challenge)
	}

	var realm, nonce, qop string

	for _, field := range splitFields(rest) {
		key, value, found := strings.Cut(field, "=")
		if !found {
			continue
		}

		value = strings.Trim(strings.TrimSpace(value), `"`)

		switch strings.TrimSpace(key) {
		case "realm":
			realm = value
		case "nonce":
			nonce = value
		case "qop":
			qop = value
		}
	}

	if realm == "" || nonce == "" {
		return fmt.Errorf("digest challenge %q has no realm or nonce", challenge)
	}

	if !hasQOPAuth(qop) {
		return fmt.Errorf("server offered qop %q, need auth", qop)
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	if nonce != d.nonce {
		d.nc = 0
	}

	d.realm, d.nonce = realm, nonce

	return nil
}

// splitFields splits a challenge on the commas between parameters. qop is
// itself a comma-separated list, so the ones inside quotes have to survive.
func splitFields(challenge string) []string {
	quoted := false

	return strings.FieldsFunc(challenge, func(r rune) bool {
		if r == '"' {
			quoted = !quoted
		}

		return r == ',' && !quoted
	})
}

// hasQOPAuth reports whether the server's qop list includes "auth".
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

func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate cnonce: %w", err)
	}

	return hex.EncodeToString(b), nil
}
