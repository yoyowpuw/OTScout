// Package protocol implements the wire formats otscout reads and, for active
// probing, writes.
//
// Response decoding and request building live together on purpose. The passive
// path decodes responses it finds in a packet capture, and the active path builds
// a request and decodes the reply. Both use the same decoder, so a fingerprint
// that works on a capture works on the wire and vice versa. Keeping them apart
// would let the two drift, and a fingerprint that only works in one mode is a
// fingerprint that will eventually be wrong in the other.
//
// Every request builder here produces a read-only operation. There is no encoder
// in this package for a write, a reset or a stop, which is the first of the
// structural guarantees described in docs/SAFETY.md.
package protocol

import (
	"errors"
	"fmt"

	"github.com/yoyowpuw/OTScout/internal/asset"
)

// Well known ports for the protocols implemented here.
const (
	PortModbus = 502
	PortS7comm = 102
	PortENIP   = 44818
	PortBACnet = 47808
)

// Names of the protocols implemented here, used as template and evidence labels.
const (
	NameModbus = "modbus"
	NameENIP   = "enip"
	NameS7comm = "s7comm"
	NameBACnet = "bacnet"
)

// ErrNotThisProtocol means the bytes are not a message of the protocol whose
// decoder was called. Decoders return this instead of a generic error so that the
// passive path can try several decoders against one payload without treating a
// mismatch as a failure.
var ErrNotThisProtocol = errors.New("payload is not a message of this protocol")

// ErrTruncated means the message is a valid start but ends early. A capture cut
// mid-conversation is normal, so this is reported separately from corruption.
var ErrTruncated = errors.New("message ends before its declared length")

// ErrDeviceError means the device answered with a protocol level error. That is
// still a useful observation: something is listening and speaks the protocol.
type ErrDeviceError struct {
	Protocol string
	Code     int
	Detail   string
}

func (e *ErrDeviceError) Error() string {
	return fmt.Sprintf("%s device returned error %d: %s", e.Protocol, e.Code, e.Detail)
}

// Observation is what a decoder recovered from a response.
//
// Fields holds the protocol level values exactly as the device reported them, and
// Identity holds the same information mapped onto the canonical model. Both are
// kept: Fields is what the evidence view shows, and Identity is what the matcher
// consumes.
type Observation struct {
	Protocol string            `json:"protocol"`
	Fields   map[string]string `json:"fields,omitempty"`
	Identity asset.Identity    `json:"identity"`
	Notes    []string          `json:"notes,omitempty"`
	// Role is set when the protocol reveals the device function directly, as
	// EtherNet/IP does through its CIP device type.
	Role asset.Role `json:"role,omitempty"`
}

func newObservation(protocolName string) Observation {
	return Observation{Protocol: protocolName, Fields: make(map[string]string)}
}

func (o *Observation) set(key, value string) {
	if value == "" {
		return
	}
	if o.Fields == nil {
		o.Fields = make(map[string]string)
	}
	o.Fields[key] = value
}

func (o *Observation) note(format string, args ...any) {
	o.Notes = append(o.Notes, fmt.Sprintf(format, args...))
}

// Empty reports whether the decoder recovered nothing usable.
func (o Observation) Empty() bool {
	return len(o.Fields) == 0 && o.Identity.Empty()
}

// Decoder decodes a single response payload for one protocol.
type Decoder func(payload []byte) (Observation, error)

// PassiveDecoders returns the decoders the ingest path should try against traffic
// seen on a given port. Ports are a hint, not a guarantee, so a decoder that does
// not recognise the payload returns ErrNotThisProtocol and the caller moves on.
func PassiveDecoders(port int) []Decoder {
	switch port {
	case PortModbus:
		return []Decoder{DecodeModbusResponse}
	case PortENIP:
		return []Decoder{DecodeENIPResponse}
	case PortS7comm:
		return []Decoder{DecodeS7Response}
	case PortBACnet:
		return []Decoder{DecodeBACnetResponse}
	default:
		return nil
	}
}

// AllDecoders returns every decoder, for payloads seen on a port we have no
// expectation about.
func AllDecoders() []Decoder {
	return []Decoder{
		DecodeModbusResponse,
		DecodeENIPResponse,
		DecodeS7Response,
		DecodeBACnetResponse,
	}
}
