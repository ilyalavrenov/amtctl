package sol

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// ErrDetached is returned when the escape key ends the session. It is a clean
// exit, not a failure.
var ErrDetached = errors.New("detached")

func (c *Conn) startSOL() error {
	req := make([]byte, lenStartSOLRedirection)
	req[0] = msgStartSOLRedirection
	binary.LittleEndian.PutUint16(req[8:10], maxTransmitBuffer)
	binary.LittleEndian.PutUint16(req[10:12], transmitBufferTimeout)
	binary.LittleEndian.PutUint16(req[12:14], transmitOverflowTimeout)
	binary.LittleEndian.PutUint16(req[14:16], hostSessionRxTimeout)
	binary.LittleEndian.PutUint16(req[16:18], hostFIFORxFlushTimeout)
	binary.LittleEndian.PutUint16(req[18:20], heartbeatInterval)

	if err := c.write(req); err != nil {
		return fmt.Errorf("start SOL: %w", err)
	}

	reply := make([]byte, lenStartSOLRedirectionReply)
	if _, err := io.ReadFull(c.conn, reply); err != nil {
		return fmt.Errorf("read SOL start reply: %w", err)
	}

	if reply[0] != msgStartSOLRedirectionReply {
		return fmt.Errorf("unexpected reply %#x to SOL start", reply[0])
	}

	if reply[1] != authStatusSuccess {
		return fmt.Errorf("SOL redirection refused (status %#x): is SOL enabled on this device?", reply[1])
	}

	return nil
}

// send frames console input as SOL_DATA_TO_HOST, splitting at the buffer size
// the firmware agreed to in START_SOL_REDIRECTION.
func (c *Conn) send(p []byte) error {
	for len(p) > 0 {
		n := min(len(p), maxTransmitBuffer)

		frame := make([]byte, lenSOLDataHeader+n)
		frame[0] = msgSOLDataToHost
		binary.LittleEndian.PutUint16(frame[8:10], uint16(n))
		copy(frame[lenSOLDataHeader:], p[:n])

		if err := c.write(frame); err != nil {
			return err
		}

		p = p[n:]
	}

	return nil
}

// errSessionEnded reports a clean END_SOL_REDIRECTION_REPLY from the firmware.
var errSessionEnded = errors.New("session ended")

// handleMessage consumes the remainder of one inbound message, given its
// already-read type byte.
func (c *Conn) handleMessage(kind byte, header []byte, out io.Writer) error {
	switch kind {
	case msgSOLDataFromHost:
		if _, err := io.ReadFull(c.conn, header[1:lenSOLDataHeader]); err != nil {
			return fmt.Errorf("read SOL data header: %w", err)
		}

		n := int64(binary.LittleEndian.Uint16(header[8:10]))
		if _, err := io.CopyN(out, c.conn, n); err != nil {
			return fmt.Errorf("read SOL payload: %w", err)
		}

		return nil

	case msgSOLHeartbeat, msgSOLKeepAlivePing:
		frame := make([]byte, lenHeartbeat)
		frame[0] = kind

		if _, err := io.ReadFull(c.conn, frame[1:]); err != nil {
			return fmt.Errorf("read heartbeat: %w", err)
		}

		// Echoing the heartbeat is what keeps the session open.
		if err := c.write(frame); err != nil {
			return fmt.Errorf("echo heartbeat: %w", err)
		}

		return nil

	case msgSOLControlsFromHost:
		if _, err := io.ReadFull(c.conn, header[1:lenSOLControlsFromHost]); err != nil {
			return fmt.Errorf("read SOL controls: %w", err)
		}

		return nil

	case msgEndSOLRedirectionReply:
		if _, err := io.ReadFull(c.conn, make([]byte, lenEndSOLRedirectionReply-1)); err != nil {
			return fmt.Errorf("read SOL end reply: %w", err)
		}

		return errSessionEnded

	default:
		return fmt.Errorf("unexpected redirection message %#x", kind)
	}
}

// receive dispatches inbound messages until the session ends. Framing follows
// each message's declared length, so a heartbeat arriving mid-stream cannot
// desynchronize the parser.
func (c *Conn) receive(out io.Writer) error {
	header := make([]byte, lenSOLDataHeader)

	for {
		if _, err := io.ReadFull(c.conn, header[:1]); err != nil {
			return fmt.Errorf("read message type: %w", err)
		}

		if err := c.handleMessage(header[0], header, out); err != nil {
			if errors.Is(err, errSessionEnded) {
				return nil
			}

			return err
		}
	}
}

// forward copies console input to the host until the escape key is pressed.
func (c *Conn) forward(in io.Reader) error {
	buf := make([]byte, inputBufferSize)

	for {
		n, err := in.Read(buf)

		if serr := c.forwardChunk(buf[:n]); serr != nil {
			return serr
		}

		if err != nil {
			return fmt.Errorf("read console input: %w", err)
		}
	}
}

// forwardChunk sends one chunk, stopping at the escape byte if present.
func (c *Conn) forwardChunk(chunk []byte) error {
	before, _, found := bytes.Cut(chunk, []byte{EscapeByte})
	if !found {
		return c.send(chunk)
	}

	if err := c.send(before); err != nil {
		return err
	}

	return ErrDetached
}

// Run pumps the console in both directions until either side ends. A clean
// detach or EOF returns nil. Run closes the connection, so the caller must not.
//
// Cancelling ctx closes the connection, which unblocks the receive side. The
// input goroutine only unblocks on the next read from in.
func (c *Conn) Run(ctx context.Context, in io.Reader, out io.Writer) error {
	done := make(chan error, 2)

	go func() { done <- c.forward(in) }()
	go func() { done <- c.receive(out) }()

	// Closing the connection is the only way to unblock a pending read.
	stopped := make(chan struct{})
	defer close(stopped)

	go func() {
		select {
		case <-ctx.Done():
			_ = c.conn.Close()
		case <-stopped:
		}
	}()

	err := <-done

	// Ask the firmware to close the session, else the next attach is refused by
	// one it still considers open.
	end := make([]byte, lenHeartbeat)
	end[0] = msgEndSOLRedirection
	_ = c.write(end) //nolint:errcheck // teardown is best-effort; the session is ending regardless
	_ = c.conn.Close()

	if errors.Is(err, ErrDetached) || errors.Is(err, io.EOF) {
		return nil
	}

	return err
}
