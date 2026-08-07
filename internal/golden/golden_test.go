package golden

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/yoyowpuw/OTScout/internal/protocol"
)

// update rewrites the expectation block of every fixture from what the decoders
// currently produce.
//
// This exists so that adding a fixture means recording bytes and describing where
// they came from, rather than hand writing a field map. It is also the dangerous
// switch in this package: run it after a change and the corpus will agree with
// whatever the code now does, including the wrong thing. The diff it produces is
// the review, and a diff that changes a fixture the change was not about is the
// signal to stop.
var update = flag.Bool("update", false, "rewrite fixture expectations from the current decoders")

func TestCorpusDecodesToTheRecordedIdentity(t *testing.T) {
	fixtures, err := Load()
	if err != nil {
		t.Fatalf("load corpus: %v", err)
	}
	if len(fixtures) == 0 {
		t.Fatal("the golden corpus is empty, so nothing about the decoders is being checked")
	}

	for _, f := range fixtures {
		t.Run(f.ID, func(t *testing.T) {
			got, err := f.Observed()
			if err != nil {
				t.Fatalf("replay: %v", err)
			}

			if *update {
				f.Expect = got
				if err := rewrite(f); err != nil {
					t.Fatalf("rewrite fixture: %v", err)
				}
				return
			}

			if !reflect.DeepEqual(got, f.Expect) {
				t.Errorf("%s\n\ndecoded:\n%s\n\nrecorded:\n%s\n\n"+
					"If the new output is right, re-record with:\n"+
					"  go test ./internal/golden -update",
					f.Summary, render(got), render(f.Expect))
			}
		})
	}
}

// TestCorpusRequestsMatchTheBuilders keeps the active probe honest against the
// passive corpus.
//
// A fixture records both what was asked and what came back. If a request builder
// is changed, the recorded reply is no longer a reply to anything this build can
// send, and the fixture stops being evidence about the probe even though it still
// passes as evidence about the decoder. This is what notices.
func TestCorpusRequestsMatchTheBuilders(t *testing.T) {
	fixtures, err := Load()
	if err != nil {
		t.Fatalf("load corpus: %v", err)
	}

	for _, f := range fixtures {
		if f.Request == nil {
			continue
		}
		t.Run(f.ID, func(t *testing.T) {
			built, err := BuildRequest(*f.Request)
			if err != nil {
				t.Fatalf("build request: %v", err)
			}
			if string(built) != string(f.Request.Bytes) {
				t.Errorf("builder %s no longer produces the request this reply answered\n got %x\nwant %x",
					f.Request.Builder, built, []byte(f.Request.Bytes))
			}
		})
	}
}

// TestCorpusRequestsAreReadOnly re-states, against the recorded bytes, the
// guarantee that docs/SAFETY.md makes about this build.
//
// The protocol package promises that no encoder in it can produce a write. Here
// that promise is checked at the only place it finally matters, which is the
// bytes actually addressed to equipment.
func TestCorpusRequestsAreReadOnly(t *testing.T) {
	fixtures, err := Load()
	if err != nil {
		t.Fatalf("load corpus: %v", err)
	}

	// Function codes and services that change state. A request carrying one of
	// these would mean an encoder for it exists somewhere, which is the thing
	// the design forbids.
	modbusWrites := map[byte]string{
		0x05: "write single coil",
		0x06: "write single register",
		0x0F: "write multiple coils",
		0x10: "write multiple registers",
		0x16: "mask write register",
		0x17: "read/write multiple registers",
	}
	bacnetWrites := map[byte]string{
		0x0F: "WriteProperty",
		0x10: "WritePropertyMultiple",
		0x11: "DeviceCommunicationControl",
		0x14: "ReinitializeDevice",
	}

	for _, f := range fixtures {
		if f.Request == nil {
			continue
		}
		t.Run(f.ID, func(t *testing.T) {
			raw := []byte(f.Request.Bytes)
			switch f.Expect.Protocol {
			case protocol.NameModbus:
				// The function code sits after the seven byte MBAP header.
				if len(raw) > 7 {
					if name, bad := modbusWrites[raw[7]]; bad {
						t.Errorf("the request is a Modbus %s, which this build must not be able to encode", name)
					}
				}
			case protocol.NameBACnet:
				// A confirmed request carries its service choice fourth in the
				// APDU, which starts after the BVLL and NPDU headers.
				if len(raw) > 9 && raw[4] == 0x01 && raw[6]&0xF0 == 0x00 {
					if name, bad := bacnetWrites[raw[9]]; bad {
						t.Errorf("the request is a BACnet %s, which this build must not be able to encode", name)
					}
				}
			}
		})
	}
}

func TestCorpusIsWellFormed(t *testing.T) {
	fixtures, err := Load()
	if err != nil {
		t.Fatalf("load corpus: %v", err)
	}

	seen := make(map[string]bool, len(fixtures))
	for _, f := range fixtures {
		t.Run(f.ID, func(t *testing.T) {
			if seen[f.ID] {
				t.Fatalf("duplicate fixture id %q", f.ID)
			}
			seen[f.ID] = true

			if strings.TrimSpace(f.Summary) == "" {
				t.Error("a fixture needs a summary saying what it is here to prove")
			}
			if len(f.Response) == 0 {
				t.Error("a fixture with no response bytes tests nothing")
			}
			if f.Port <= 0 || f.Port > 65535 {
				t.Errorf("port %d is not a port", f.Port)
			}
			if f.Transport != "tcp" && f.Transport != "udp" {
				t.Errorf("transport %q must be tcp or udp", f.Transport)
			}
			if strings.TrimSpace(f.Device.Source) == "" {
				t.Error("a fixture must name the software or device that produced it")
			}
			if len(f.Device.References) == 0 {
				t.Error("a fixture must cite something a reviewer can check it against")
			}
			switch f.Device.Provenance {
			case ProvenanceCaptured:
				if f.Device.Derivation != "" {
					t.Error("a captured fixture has nothing to derive, so it must not claim a derivation")
				}
				if strings.TrimSpace(f.Device.License) == "" {
					t.Error("a captured fixture redistributes somebody else's recording, so it must name the terms it arrives under")
				}
			case ProvenanceConstructed:
				if strings.TrimSpace(f.Device.Derivation) == "" {
					t.Error("a constructed fixture must say how its bytes follow from its references")
				}
				if f.Device.License != "" {
					t.Error("a constructed fixture is derived here rather than copied, so it carries no third party terms")
				}
			default:
				t.Errorf("provenance %q must be %q or %q", f.Device.Provenance, ProvenanceCaptured, ProvenanceConstructed)
			}
			switch f.Expect.Verdict {
			case VerdictDecoded, VerdictDeviceError, VerdictTruncated:
				if f.Expect.Protocol == "" {
					t.Errorf("verdict %q means a decoder claimed the payload, so the fixture must say which one", f.Expect.Verdict)
				}
			case VerdictNotThisProtocol:
				// Naming a protocol here would be a contradiction, and it would
				// also make the fixture pass TestEveryProtocolHasAFixture, so a
				// decoder could end up counted as covered by a frame it refused.
				if f.Expect.Protocol != "" {
					t.Errorf("the fixture expects no decoder to claim the payload but names %q", f.Expect.Protocol)
				}
				if !f.Expect.Identity.Empty() || f.Expect.Role != "" || len(f.Expect.Fields) > 0 {
					t.Error("a declined payload must yield no identity, role or fields")
				}
			default:
				t.Errorf("verdict %q is not one this runner understands", f.Expect.Verdict)
			}
		})
	}
}

// TestEveryProtocolHasAFixture stops a protocol from being added, or kept, with
// no recorded device behind it.
func TestEveryProtocolHasAFixture(t *testing.T) {
	fixtures, err := Load()
	if err != nil {
		t.Fatalf("load corpus: %v", err)
	}

	covered := make(map[string]int)
	captured := make(map[string]int)
	for _, f := range fixtures {
		covered[f.Expect.Protocol]++
		if f.Device.Provenance == ProvenanceCaptured {
			captured[f.Expect.Protocol]++
		}
	}
	for _, name := range []string{protocol.NameModbus, protocol.NameENIP, protocol.NameS7comm, protocol.NameBACnet} {
		if covered[name] == 0 {
			t.Errorf("no fixture in the corpus exercises the %s decoder", name)
		}
		// An emulator is written from the same specification the decoder is, so
		// the two can agree perfectly and both be wrong about the equipment.
		// Requiring one recording of real hardware per protocol is what keeps the
		// corpus from becoming a conversation between two readings of a document.
		if captured[name] == 0 {
			t.Errorf("every fixture for %s comes from an emulator, so nothing in the corpus says a real device behaves this way", name)
		}
	}
}

// TestCorpusHoldsTrafficThatMustBeDeclined keeps the negative half of the corpus
// from being quietly dropped.
//
// Passive discovery falls back to trying every decoder on a port nothing is
// registered for, so the decoders are asked constantly about payloads that are
// none of their business. What they refuse is as much a part of their behaviour as
// what they accept, and a wrong acceptance is worse than a miss: it invents a
// protocol, which becomes a role, a Purdue level, and an advisory search against
// equipment the device is not.
func TestCorpusHoldsTrafficThatMustBeDeclined(t *testing.T) {
	fixtures, err := Load()
	if err != nil {
		t.Fatalf("load corpus: %v", err)
	}

	declined := 0
	for _, f := range fixtures {
		if f.Expect.Verdict == VerdictNotThisProtocol {
			declined++
		}
	}
	if declined < 2 {
		t.Errorf("the corpus holds %d payload that every decoder must refuse, which is too few to say the decoders are strict", declined)
	}
}

// TestFixturesOnUnexpectedPortsStillFindTheirDecoder covers the case a plant
// produces constantly and a lab never does: an industrial service reachable
// somewhere other than its registered port.
func TestFixturesOnUnexpectedPortsStillFindTheirDecoder(t *testing.T) {
	fixtures, err := Load()
	if err != nil {
		t.Fatalf("load corpus: %v", err)
	}

	found := false
	for _, f := range fixtures {
		if len(protocol.PassiveDecoders(f.Port)) > 0 || f.Expect.Protocol == "" {
			continue
		}
		found = true
		t.Run(f.ID, func(t *testing.T) {
			obs, _, _ := f.Replay()
			if obs.Protocol != f.Expect.Protocol {
				t.Errorf("on port %d the fallback picked %q, want %q", f.Port, obs.Protocol, f.Expect.Protocol)
			}
		})
	}
	if !found {
		t.Error("no fixture sits on an unregistered port, so the fallback that finds a decoder by content is untested")
	}
}

// rewrite writes a fixture back to disk in the corpus directory.
func rewrite(f Fixture) error {
	encoded, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(f.FileName(), append(encoded, '\n'), 0o644)
}

// render prints an expectation the way a failure is easiest to read: one field
// per line, sorted, with the long hex strings left out.
func render(e Expectation) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "  protocol: %s\n", e.Protocol)
	fmt.Fprintf(&sb, "  verdict:  %s\n", e.Verdict)
	if e.ErrorDetail != "" {
		fmt.Fprintf(&sb, "  error:    %s\n", e.ErrorDetail)
	}
	if e.Role != "" {
		fmt.Fprintf(&sb, "  role:     %s\n", e.Role)
	}
	if !e.Identity.Empty() || e.Identity.Serial != "" {
		fmt.Fprintf(&sb, "  identity: %s\n", identityLine(e))
	}
	keys := make([]string, 0, len(e.Fields))
	for key := range e.Fields {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		fmt.Fprintf(&sb, "  field %s = %q\n", key, e.Fields[key])
	}
	for _, note := range e.Notes {
		fmt.Fprintf(&sb, "  note:     %s\n", note)
	}
	return strings.TrimRight(sb.String(), "\n")
}

func identityLine(e Expectation) string {
	parts := make([]string, 0, 8)
	for _, pair := range [][2]string{
		{"vendor", e.Identity.Vendor},
		{"product", e.Identity.Product},
		{"family", e.Identity.Family},
		{"model", e.Identity.Model},
		{"catalog", e.Identity.CatalogNumber},
		{"firmware", e.Identity.Firmware},
		{"serial", e.Identity.Serial},
	} {
		if pair[1] != "" {
			parts = append(parts, pair[0]+"="+pair[1])
		}
	}
	if len(parts) == 0 {
		return "(nothing)"
	}
	return strings.Join(parts, " ")
}
