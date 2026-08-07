package probe

import (
	"errors"

	"github.com/yoyowpuw/OTScout/internal/asset"
	"github.com/yoyowpuw/OTScout/internal/protocol"
	"github.com/yoyowpuw/OTScout/internal/safety"
)

// Observation is one decoded reply, kept with enough context to explain itself.
type Observation struct {
	Host       string
	Port       int
	Transport  string
	TemplateID string
	Step       string

	// Protocol is what the decoder claimed, which is not always what the
	// template expected. A device answering EtherNet/IP on the Modbus port is
	// worth recording as what it is.
	Protocol string

	// Request and Response are the bytes as they went out and came back. They
	// are kept so that a claim about a device can be checked against the packet
	// that produced it, which is the difference between an observation and an
	// assertion.
	Request  asset.HexBytes
	Response asset.HexBytes

	Fields   map[string]string
	Identity asset.Identity
	Role     asset.Role
	Notes    []string

	// Refusal holds a protocol level error, which is still an observation: the
	// device is listening and speaks the protocol, it just declined this call.
	Refusal string
}

// Interpreter decodes replies as they arrive.
//
// It exists for two audiences. The safety engine consults it so the deny list
// can recognise a device before the next probe goes out, and the probe command
// keeps everything it produced so the inventory can be built at the end. Those
// are the same decode, so doing it once here keeps them from disagreeing.
//
// Replies accumulate in the order received. A run is sequential by construction,
// so this needs no lock and having none is a reminder that adding concurrency
// would not be a local change.
type Interpreter struct {
	observations []Observation
}

// NewInterpreter builds an empty interpreter.
func NewInterpreter() *Interpreter { return &Interpreter{} }

// Interpret decodes one reply and returns whatever identity it carried.
func (i *Interpreter) Interpret(ex safety.Exchange, step safety.Step, response []byte) asset.Identity {
	obs := Observation{
		Host:       ex.Target.Host,
		Port:       ex.Target.Port,
		Transport:  ex.Target.Transport,
		TemplateID: ex.TemplateID,
		Step:       step.Purpose,
		Request:    asset.HexBytes(step.Request),
		Response:   asset.HexBytes(response),
	}

	decode := decoderFor(ex.Protocol)
	if decode == nil {
		i.observations = append(i.observations, obs)
		return asset.Identity{}
	}

	decoded, err := decode(response)

	var deviceErr *protocol.ErrDeviceError
	switch {
	case errors.Is(err, protocol.ErrNotThisProtocol):
		// The template asked in one protocol and something else answered. That
		// is recorded rather than dropped, because a service on an unexpected
		// port is ordinary in a plant and the operator should see it, but no
		// identity is claimed from bytes nothing could parse.
		obs.Notes = append(obs.Notes, "the reply is not "+ex.Protocol)
		i.observations = append(i.observations, obs)
		return asset.Identity{}

	case errors.As(err, &deviceErr):
		obs.Refusal = err.Error()

	case errors.Is(err, protocol.ErrTruncated):
		obs.Notes = append(obs.Notes, "the reply ended before its declared length")
	}

	obs.Protocol = decoded.Protocol
	obs.Fields = decoded.Fields
	obs.Identity = decoded.Identity
	obs.Role = decoded.Role
	obs.Notes = append(obs.Notes, decoded.Notes...)
	i.observations = append(i.observations, obs)

	return decoded.Identity
}

// Observations returns everything decoded so far, in the order received.
func (i *Interpreter) Observations() []Observation {
	out := make([]Observation, len(i.observations))
	copy(out, i.observations)
	return out
}
