package protocol

import (
	"encoding/hex"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// Params are the values a template supplies to a request builder.
//
// They are strings because they arrive from YAML written by people, and because
// a builder that parses its own parameters can say what it wanted when one is
// wrong. Numbers may be written in decimal or, with an 0x prefix, in hex, since
// protocol documentation gives them both ways.
type Params map[string]string

// RequestBuilder turns parameters into the bytes of one request.
type RequestBuilder func(Params) ([]byte, error)

// builders is the complete set of messages this project can put on a wire.
//
// This map is the boundary. A template names an entry here and supplies
// parameters; it cannot supply bytes, so there is no template that can ask a
// device to do something the map does not already offer. Adding an entry is
// therefore a decision to let a new kind of packet reach industrial equipment,
// and TestThePackageEncodesNoWrites makes that decision show up in a diff.
var builders = map[string]RequestBuilder{
	"modbus.read-device-identification": func(p Params) ([]byte, error) {
		transactionID, err := p.number("transaction_id", 0, 0xFFFF)
		if err != nil {
			return nil, err
		}
		unitID, err := p.number("unit_id", 1, 0xFF)
		if err != nil {
			return nil, err
		}
		readCode, err := p.number("read_code", int(ModbusReadBasic), 0xFF)
		if err != nil {
			return nil, err
		}
		return ModbusDeviceIDRequest(uint16(transactionID), byte(unitID), byte(readCode)), nil
	},

	"enip.list-identity": func(p Params) ([]byte, error) {
		context, err := p.senderContext()
		if err != nil {
			return nil, err
		}
		return ENIPListIdentityRequest(context), nil
	},

	"s7comm.connection-request": func(p Params) ([]byte, error) {
		source, err := p.number("source_tsap", 0x0100, 0xFFFF)
		if err != nil {
			return nil, err
		}
		dest, err := p.number("dest_tsap", 0x0102, 0xFFFF)
		if err != nil {
			return nil, err
		}
		return S7ConnectionRequest(uint16(source), uint16(dest)), nil
	},

	"s7comm.setup-communication": func(p Params) ([]byte, error) {
		reference, err := p.number("pdu_reference", 0, 0xFFFF)
		if err != nil {
			return nil, err
		}
		return S7SetupCommunication(uint16(reference)), nil
	},

	"s7comm.read-szl": func(p Params) ([]byte, error) {
		reference, err := p.number("pdu_reference", 0, 0xFFFF)
		if err != nil {
			return nil, err
		}
		szlID, err := p.number("szl_id", int(SZLComponentIdentification), 0xFFFF)
		if err != nil {
			return nil, err
		}
		szlIndex, err := p.number("szl_index", 0, 0xFFFF)
		if err != nil {
			return nil, err
		}
		return S7ReadSZLRequest(uint16(reference), uint16(szlID), uint16(szlIndex)), nil
	},

	"bacnet.who-is": func(Params) ([]byte, error) {
		return BACnetWhoIsRequest(), nil
	},

	"bacnet.read-property": func(p Params) ([]byte, error) {
		invokeID, err := p.number("invoke_id", 0, 0xFF)
		if err != nil {
			return nil, err
		}
		property, err := p.number("property", int(BACnetPropModelName), 0xFFFFFF)
		if err != nil {
			return nil, err
		}
		return BACnetReadPropertyRequest(byte(invokeID), uint32(property)), nil
	},
}

// BuildRequest produces the bytes of a named request.
func BuildRequest(name string, params Params) ([]byte, error) {
	build, ok := builders[name]
	if !ok {
		return nil, fmt.Errorf("no request builder named %q; the ones that exist are %s",
			name, strings.Join(BuilderNames(), ", "))
	}
	request, err := build(params)
	if err != nil {
		return nil, fmt.Errorf("builder %s: %w", name, err)
	}
	return request, nil
}

// HasBuilder reports whether a name is one this build can send.
func HasBuilder(name string) bool {
	_, ok := builders[name]
	return ok
}

// BuilderNames lists every request this build can send, sorted.
func BuilderNames() []string {
	names := make([]string, 0, len(builders))
	for name := range builders {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// number reads a parameter that may be decimal or, with an 0x prefix, hex.
//
// The ceiling is checked here rather than left to the conversion at the call
// site, because a value that overflows its field silently becomes a different
// value, and a template with a typo would then send something nobody wrote.
func (p Params) number(name string, fallback, max int) (int, error) {
	raw, ok := p[name]
	if !ok {
		return fallback, nil
	}
	value, err := strconv.ParseInt(strings.TrimSpace(raw), 0, 32)
	if err != nil {
		return 0, fmt.Errorf("parameter %s: %w", name, err)
	}
	if value < 0 || value > int64(max) {
		return 0, fmt.Errorf("parameter %s is %d, which is outside the range 0 to %d that the field holds",
			name, value, max)
	}
	return int(value), nil
}

func (p Params) senderContext() ([8]byte, error) {
	var out [8]byte
	raw, ok := p["sender_context"]
	if !ok {
		return out, nil
	}
	decoded, err := hex.DecodeString(strings.ReplaceAll(strings.TrimSpace(raw), " ", ""))
	if err != nil {
		return out, fmt.Errorf("parameter sender_context: %w", err)
	}
	if len(decoded) != len(out) {
		return out, fmt.Errorf("parameter sender_context must be %d bytes, got %d", len(out), len(decoded))
	}
	copy(out[:], decoded)
	return out, nil
}
