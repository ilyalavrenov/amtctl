package amt

import (
	"crypto/md5"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// guard is a fake AMT endpoint that answers an unauthenticated request with a
// digest challenge and records the credentials every later request carries.
type guard struct {
	mu         sync.Mutex
	challenges int
	authorized []string
}

func (g *guard) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Authorization")

	g.mu.Lock()
	defer g.mu.Unlock()

	if auth == "" {
		g.challenges++

		// A qop list is what firmware answers, and only "auth" may come back.
		w.Header().Set("WWW-Authenticate",
			`Digest realm="Digest:AF000000", nonce="7f2c9c1e", stale="false", qop="auth,auth-int"`)
		w.WriteHeader(http.StatusUnauthorized)

		return
	}

	g.authorized = append(g.authorized, auth)

	_, _ = io.WriteString(w, envelope("<CIM_AssociatedPowerManagementService><PowerState>2</PowerState>"+
		"</CIM_AssociatedPowerManagementService>"))
}

// credentials parses the parameters of one Authorization header. The values
// amtctl sends never contain a comma, so splitting on one is enough here.
func credentials(fields string) map[string]string {
	out := make(map[string]string)

	for field := range strings.SplitSeq(fields, ",") {
		key, value, _ := strings.Cut(field, "=")
		out[key] = strings.Trim(value, `"`)
	}

	return out
}

func md5sum(parts ...string) string {
	return fmt.Sprintf("%x", md5.Sum([]byte(strings.Join(parts, ":"))))
}

func TestDigestHandshake(t *testing.T) {
	t.Parallel()

	g := &guard{}

	srv := httptest.NewServer(g)
	t.Cleanup(srv.Close)

	c := newClient(srv.URL+"/wsman", "admin", "secret")

	_, err := c.FetchPowerState(t.Context())
	require.NoError(t, err)

	_, err = c.FetchPowerState(t.Context())
	require.NoError(t, err)

	// One challenge covers every later request: the credentials are reused.
	assert.Equal(t, 1, g.challenges)
	require.Len(t, g.authorized, 2)

	ha1 := md5sum("admin", "Digest:AF000000", "secret")
	ha2 := md5sum(http.MethodPost, "/wsman")

	for i, header := range g.authorized {
		fields, ok := strings.CutPrefix(header, "Digest ")
		assert.True(t, ok, "Authorization=%q", header)

		got := credentials(fields)

		assert.Equal(t, "admin", got["username"])
		assert.Equal(t, "Digest:AF000000", got["realm"])
		assert.Equal(t, "7f2c9c1e", got["nonce"])
		assert.Equal(t, "/wsman", got["uri"])
		assert.Equal(t, "auth", got["qop"])

		// The count rises per request so the server can reject a replay.
		assert.Equal(t, fmt.Sprintf("%08x", i+1), got["nc"])

		want := md5sum(ha1, "7f2c9c1e", got["nc"], got["cnonce"], "auth", ha2)
		assert.Equal(t, want, got["response"], "request %d", i)
	}
}

func TestDigestRejectsAnUnsupportedChallenge(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("WWW-Authenticate", `Basic realm="AMT"`)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	t.Cleanup(srv.Close)

	_, err := newClient(srv.URL+"/wsman", "admin", "secret").FetchPowerState(t.Context())
	assert.ErrorContains(t, err, "unsupported authentication challenge")
}
