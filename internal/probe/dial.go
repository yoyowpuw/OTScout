package probe

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/yoyowpuw/OTScout/internal/protocol"
	"github.com/yoyowpuw/OTScout/internal/safety"
)

// maxResponse bounds how much will be read from one exchange.
//
// Every reply this project understands is a few hundred bytes. The ceiling is
// here so that a host answering with an endless stream, whether by fault or on
// purpose, cannot make the scanner allocate without limit.
const maxResponse = 64 * 1024

// NetDialer is the real transport. It is the only type in the project that
// opens a socket to equipment.
//
// It carries no retry, no fallback and no port scanning. A connection that does
// not come up is reported and the run moves on, because deciding to try again is
// a pacing decision and pacing belongs to the safety engine.
type NetDialer struct{}

// Dial opens the connection for one exchange.
func (NetDialer) Dial(ctx context.Context, ex safety.Exchange, timeouts safety.Timeouts) (safety.Conn, error) {
	dialer := net.Dialer{Timeout: timeouts.Connect}
	conn, err := dialer.DialContext(ctx, ex.Target.Transport, ex.Target.Address())
	if err != nil {
		return nil, fmt.Errorf("%w: %v", safety.ErrUnreachable, err)
	}
	return &netConn{conn: conn, protocol: ex.Protocol}, nil
}

type netConn struct {
	conn     net.Conn
	protocol string
}

// Exchange writes one request and reads the reply.
func (c *netConn) Exchange(ctx context.Context, request []byte, readTimeout time.Duration) ([]byte, error) {
	if deadline, ok := ctx.Deadline(); ok {
		if until := time.Until(deadline); until < readTimeout {
			readTimeout = until
		}
	}

	if err := c.conn.SetWriteDeadline(time.Now().Add(readTimeout)); err != nil {
		return nil, err
	}
	if _, err := c.conn.Write(request); err != nil {
		return nil, fmt.Errorf("%w: %v", safety.ErrUnreachable, err)
	}

	return c.read(readTimeout)
}

// read collects bytes until the protocol says the reply is whole.
//
// The decoders already distinguish a frame that ends early from bytes that are
// not the protocol at all, so that judgement is reused here rather than
// duplicated as a second implementation of every header. A partial frame means
// read more; anything else means stop.
//
// The deadline is absolute over the whole reply rather than reset per read, so a
// device that dribbles one byte at a time cannot hold the socket open forever.
func (c *netConn) read(timeout time.Duration) ([]byte, error) {
	deadline := time.Now().Add(timeout)
	if err := c.conn.SetReadDeadline(deadline); err != nil {
		return nil, err
	}

	var collected []byte
	buf := make([]byte, 4096)

	for {
		n, err := c.conn.Read(buf)
		if n > 0 {
			collected = append(collected, buf[:n]...)
			if len(collected) > maxResponse {
				return collected[:maxResponse], nil
			}
			if c.complete(collected) {
				return collected, nil
			}
		}
		if err != nil {
			if len(collected) > 0 {
				// Something came back, even if the stream then ended or the
				// clock ran out. A short reply is an observation, and throwing
				// it away would turn a talkative device into a silent one.
				return collected, nil
			}
			var netErr net.Error
			switch {
			case errors.Is(err, io.EOF):
				return nil, fmt.Errorf("%w: the device closed the connection without replying", safety.ErrNoAnswer)
			case errors.As(err, &netErr) && netErr.Timeout():
				return nil, safety.ErrNoAnswer
			default:
				return nil, fmt.Errorf("%w: %v", safety.ErrUnreachable, err)
			}
		}
	}
}

// complete reports whether the bytes so far form a whole reply.
func (c *netConn) complete(collected []byte) bool {
	decode := decoderFor(c.protocol)
	if decode == nil {
		// Without a decoder there is no way to know, so one read is taken as the
		// whole answer rather than blocking until the deadline.
		return true
	}
	_, err := decode(collected)
	return !errors.Is(err, protocol.ErrTruncated)
}

func (c *netConn) Close() error { return c.conn.Close() }

func decoderFor(name string) protocol.Decoder {
	switch name {
	case protocol.NameModbus:
		return protocol.DecodeModbusResponse
	case protocol.NameENIP:
		return protocol.DecodeENIPResponse
	case protocol.NameS7comm:
		return protocol.DecodeS7Response
	case protocol.NameBACnet:
		return protocol.DecodeBACnetResponse
	default:
		return nil
	}
}
