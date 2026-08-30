package sol

import (
	"crypto/md5"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
)

// readAuthRequest reads one AUTHENTICATE_SESSION message and returns its method
// and elements.
func readAuthRequest(conn net.Conn) (byte, []string, error) {
	header := make([]byte, lenAuthHeader)
	if err := readFull(conn, header, "auth request header"); err != nil {
		return 0, nil, err
	}

	if header[0] != msgAuthenticateSession {
		return 0, nil, fmt.Errorf("auth request has type %#x", header[0])
	}

	payload := make([]byte, binary.LittleEndian.Uint32(header[5:lenAuthHeader]))
	if err := readFull(conn, payload, "auth request payload"); err != nil {
		return 0, nil, err
	}

	elements, err := splitElements(payload)
	if err != nil {
		return 0, nil, err
	}

	return header[4], elements, nil
}

// authReply frames an AUTHENTICATE_SESSION reply around an opaque payload.
func authReply(status, method byte, payload []byte) []byte {
	b := make([]byte, lenAuthHeader, lenAuthHeader+len(payload))
	b[0] = msgAuthenticateSessionReply
	b[1] = status
	b[4] = method
	binary.LittleEndian.PutUint32(b[5:lenAuthHeader], uint32(len(payload)))

	return append(b, payload...)
}

func encodeElements(elements ...string) []byte {
	var b []byte

	for _, e := range elements {
		b = append(b, byte(len(e)))
		b = append(b, e...)
	}

	return b
}

// splitElements decodes by hand rather than through parseElements, so the server
// stays an independent reading of the wire format.
func splitElements(b []byte) ([]string, error) {
	var out []string

	for len(b) > 0 {
		end := int(b[0]) + 1
		if end > len(b) {
			return nil, errors.New("truncated element in auth payload")
		}

		out = append(out, string(b[1:end]))
		b = b[end:]
	}

	return out, nil
}

func readFull(conn net.Conn, b []byte, what string) error {
	if _, err := io.ReadFull(conn, b); err != nil {
		return fmt.Errorf("read %s: %w", what, err)
	}

	return nil
}

func md5sum(s string) string {
	sum := md5.Sum([]byte(s))

	return hex.EncodeToString(sum[:])
}

// hungUp reports a client that closed the connection, which is not a protocol
// violation.
func hungUp(err error) bool {
	return errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, net.ErrClosed)
}
