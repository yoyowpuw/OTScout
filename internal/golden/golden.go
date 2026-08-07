// Package golden holds recorded ICS device responses and the identity each one
// is expected to produce.
//
// A fingerprint is a claim about what a sequence of bytes on the wire means, and
// there are only two ways to check such a claim. One is to put the tool in front
// of the equipment, which is expensive, slow, and available to almost nobody: the
// people most able to review this project are the least able to keep a Siemens
// rack and a Rockwell chassis on a desk. The other is to keep the bytes.
//
// This corpus is the second way. Every fixture pairs a response frame with the
// identity, the protocol fields and the decoder verdict it must yield, so a
// contributor who adds a decoder or widens a parser learns in CI whether they
// broke a device they have never seen. Without it the project could accept
// changes it has no way to evaluate, which for a tool that reports vulnerable
// equipment is not a gap in test coverage but a way of being wrong quietly.
//
// The corpus is embedded rather than read from testdata so that any package can
// use it, including the active probe, whose request templates are checked against
// the same recordings that the passive decoders are.
package golden

import (
	"bytes"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"sort"
	"strings"

	"github.com/yoyowpuw/OTScout/internal/asset"
	"github.com/yoyowpuw/OTScout/internal/protocol"
)

//go:embed corpus/*.json
var corpusFS embed.FS

const corpusDir = "corpus"

// Provenance records where a fixture's bytes came from. It is a required field
// because the answer changes how much the fixture proves.
type Provenance string

const (
	// ProvenanceCaptured means the bytes were taken off a wire or out of a
	// capture file, from the real device or emulator named by the fixture.
	ProvenanceCaptured Provenance = "captured"

	// ProvenanceConstructed means the bytes were assembled to match what the
	// cited software emits for the cited configuration, rather than observed.
	//
	// A constructed fixture is weaker evidence than a capture and is never
	// described as one. It is still worth having: the emulators this project
	// cites are open source, so their output is derivable from a source file a
	// reviewer can open, and TestConstructedFixturesMatchTheEmulatorTheyCite
	// re-derives it on every run rather than trusting this comment. Replacing a
	// constructed fixture with a real capture, leaving the expectations
	// untouched, is a contribution the project actively wants.
	ProvenanceConstructed Provenance = "constructed"
)

// Verdict is the outcome a decoder is expected to reach.
type Verdict string

const (
	// VerdictDecoded means the decoder returned no error.
	VerdictDecoded Verdict = "decoded"

	// VerdictDeviceError means the device answered with a protocol level
	// refusal. That is a successful observation, not a failure: something is
	// listening and it speaks the protocol.
	VerdictDeviceError Verdict = "device-error"

	// VerdictNotThisProtocol means the decoder correctly declined the payload.
	VerdictNotThisProtocol Verdict = "not-this-protocol"

	// VerdictTruncated means the frame is a valid start that ends early.
	VerdictTruncated Verdict = "truncated"
)

// Fixture is one recorded exchange and everything expected of it.
type Fixture struct {
	// ID names the fixture and must match its file name.
	ID string `json:"id"`

	// Summary says in one line what this fixture is here to prove.
	Summary string `json:"summary"`

	Device Device `json:"device"`

	// Port and Transport are where the exchange was observed. They are not
	// decoration: the passive path chooses decoders by port, so a fixture on a
	// non-standard port exercises a different route through the code.
	Port      int    `json:"port"`
	Transport string `json:"transport"`

	// Request is what elicited the response, when anything did. A fixture taken
	// from a passive capture of somebody else's poll has no request of ours.
	Request *Request `json:"request,omitempty"`

	// Response is the frame under test, as it appeared on the wire.
	Response asset.HexBytes `json:"response"`

	Expect Expectation `json:"expect"`
}

// Device describes what produced the bytes and how the fixture was obtained.
type Device struct {
	// Emulator or product that produced the response, for example "conpot".
	Source string `json:"source"`

	// Description is what the device presents itself as.
	Description string `json:"description"`

	Provenance Provenance `json:"provenance"`

	// License is the terms the recorded bytes arrive under, for a fixture taken
	// from somebody else's capture.
	//
	// A capture is a published work and most of the ones worth having are
	// licensed, so redistributing one inside this repository is an obligation
	// rather than a copy. Naming the license in the fixture keeps that obligation
	// attached to the bytes it applies to, which is the only place it can be
	// checked and the only place someone removing a fixture would think to look.
	License string `json:"license,omitempty"`

	// Derivation explains, for a constructed fixture, how the bytes follow from
	// the references. It is required for constructed fixtures and pointless for
	// captured ones.
	Derivation string `json:"derivation,omitempty"`

	// References are the sources a reviewer can check the fixture against.
	References []string `json:"references"`
}

// Request is the message sent to obtain the response.
//
// Builder and Params name a request the active probe can rebuild, which is what
// ties this corpus to the probe templates: a template claiming to speak a
// protocol is replayed against these fixtures, and its bytes have to match what
// the recorded device actually answered.
type Request struct {
	Builder string            `json:"builder"`
	Params  map[string]string `json:"params,omitempty"`
	Bytes   asset.HexBytes    `json:"bytes"`
}

// Expectation is the decoder output the fixture pins.
type Expectation struct {
	// Protocol is the decoder that must claim this payload.
	Protocol string `json:"protocol"`

	Verdict Verdict `json:"verdict"`

	// ErrorDetail is the message accompanying a device error, so that a change
	// in how a refusal is explained is caught rather than silently accepted.
	ErrorDetail string `json:"error_detail,omitempty"`

	Fields   map[string]string `json:"fields,omitempty"`
	Identity asset.Identity    `json:"identity,omitzero"`
	Role     asset.Role        `json:"role,omitempty"`
	Notes    []string          `json:"notes,omitempty"`
}

// Load reads every fixture in the embedded corpus, sorted by id.
func Load() ([]Fixture, error) {
	entries, err := fs.ReadDir(corpusFS, corpusDir)
	if err != nil {
		return nil, fmt.Errorf("read golden corpus: %w", err)
	}

	fixtures := make([]Fixture, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		raw, err := corpusFS.ReadFile(path.Join(corpusDir, entry.Name()))
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", entry.Name(), err)
		}
		var f Fixture
		decoder := json.NewDecoder(bytes.NewReader(raw))
		// A misspelled key in a fixture would otherwise be dropped in silence,
		// and a fixture that silently expects nothing passes every test.
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&f); err != nil {
			return nil, fmt.Errorf("parse %s: %w", entry.Name(), err)
		}
		if want := strings.TrimSuffix(entry.Name(), ".json"); f.ID != want {
			return nil, fmt.Errorf("fixture %s declares id %q, which does not match its file name", entry.Name(), f.ID)
		}
		fixtures = append(fixtures, f)
	}

	sort.Slice(fixtures, func(i, j int) bool { return fixtures[i].ID < fixtures[j].ID })
	return fixtures, nil
}

// FileName is where a fixture belongs on disk, relative to the package.
func (f Fixture) FileName() string {
	return path.Join(corpusDir, f.ID+".json")
}

// Decoders returns the decoders the passive path would try for this fixture,
// which is what the port implies rather than what the fixture claims.
//
// A service on a port nobody expects is ordinary in a plant, and the fallback to
// trying every decoder is the code path that handles it. Choosing the decoder
// from the fixture's own expectation would test neither.
func (f Fixture) Decoders() []protocol.Decoder {
	if decoders := protocol.PassiveDecoders(f.Port); len(decoders) > 0 {
		return decoders
	}
	return protocol.AllDecoders()
}

// Replay runs the fixture through the decoders its port selects and returns the
// observation, the decoder verdict and the error the decoder gave.
//
// A decoder that returns ErrNotThisProtocol is passed over, exactly as the ingest
// path passes over it, so what comes back is the verdict of whichever decoder
// claimed the payload. When none does, the verdict is VerdictNotThisProtocol.
func (f Fixture) Replay() (protocol.Observation, Verdict, error) {
	for _, decode := range f.Decoders() {
		obs, err := decode(f.Response)
		if errors.Is(err, protocol.ErrNotThisProtocol) {
			continue
		}
		return obs, verdictFor(err), err
	}
	return protocol.Observation{}, VerdictNotThisProtocol, protocol.ErrNotThisProtocol
}

func verdictFor(err error) Verdict {
	var deviceErr *protocol.ErrDeviceError
	switch {
	case err == nil:
		return VerdictDecoded
	case errors.As(err, &deviceErr):
		return VerdictDeviceError
	case errors.Is(err, protocol.ErrTruncated):
		return VerdictTruncated
	default:
		return VerdictNotThisProtocol
	}
}

// Observed builds the expectation a fixture actually produces, which is what the
// runner compares against the recorded one and what -update writes back.
func (f Fixture) Observed() (Expectation, error) {
	obs, verdict, err := f.Replay()

	out := Expectation{
		Protocol: obs.Protocol,
		Verdict:  verdict,
		Fields:   obs.Fields,
		Identity: obs.Identity,
		Role:     obs.Role,
		Notes:    obs.Notes,
	}
	if len(out.Fields) == 0 {
		out.Fields = nil
	}
	if verdict == VerdictDeviceError && err != nil {
		out.ErrorDetail = err.Error()
	}
	return out, nil
}

// BuildRequest rebuilds a recorded request from its builder name and parameters.
//
// The builders live in the protocol package rather than here, because they are
// the same closed set the active probe draws from. A fixture that names one is
// therefore checking the bytes a real scan would send, which is the whole reason
// the corpus records the request alongside the response.
func BuildRequest(r Request) ([]byte, error) {
	return protocol.BuildRequest(r.Builder, protocol.Params(r.Params))
}
