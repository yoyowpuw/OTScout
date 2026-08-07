package probe

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/yoyowpuw/OTScout/internal/golden"
	"github.com/yoyowpuw/OTScout/internal/safety"
)

// replayServer answers requests with recorded bytes from the golden corpus.
//
// It is not an emulator and does not pretend to be one. It reads a request,
// discards it and writes the next scripted response, which is enough to exercise
// the one thing that cannot be tested any other way: the path from a template,
// through the socket, through framing and decoding, into an inventory entry.
// Whether the bytes are the right answer to that request is settled by the
// corpus, not here.
type replayServer struct {
	t         *testing.T
	responses [][]byte
	// requests holds what the probe actually sent, so a test can check that the
	// template put the bytes it advertised on the wire.
	requests [][]byte
	addr     string
	done     chan struct{}
}

func startReplayTCP(t *testing.T, responses [][]byte) *replayServer {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	s := &replayServer{t: t, responses: responses, addr: listener.Addr().String(), done: make(chan struct{})}
	go func() {
		defer close(s.done)
		defer listener.Close()
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		buf := make([]byte, 4096)
		for _, response := range s.responses {
			if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
				return
			}
			n, err := conn.Read(buf)
			if err != nil {
				return
			}
			s.requests = append(s.requests, append([]byte(nil), buf[:n]...))
			if _, err := conn.Write(response); err != nil {
				return
			}
		}
	}()

	t.Cleanup(func() {
		listener.Close()
		select {
		case <-s.done:
		case <-time.After(2 * time.Second):
		}
	})
	return s
}

func startReplayUDP(t *testing.T, responses [][]byte) *replayServer {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	s := &replayServer{t: t, responses: responses, addr: conn.LocalAddr().String(), done: make(chan struct{})}
	go func() {
		defer close(s.done)
		defer conn.Close()
		buf := make([]byte, 4096)
		for _, response := range s.responses {
			if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
				return
			}
			n, from, err := conn.ReadFrom(buf)
			if err != nil {
				return
			}
			s.requests = append(s.requests, append([]byte(nil), buf[:n]...))
			if _, err := conn.WriteTo(response, from); err != nil {
				return
			}
		}
	}()

	t.Cleanup(func() {
		conn.Close()
		select {
		case <-s.done:
		case <-time.After(2 * time.Second):
		}
	})
	return s
}

// fixtureResponse returns the recorded bytes of one fixture.
func fixtureResponse(t *testing.T, id string) []byte {
	t.Helper()
	corpus, err := golden.Load()
	if err != nil {
		t.Fatalf("load the corpus: %v", err)
	}
	for _, fixture := range corpus {
		if fixture.ID == id {
			return fixture.Response
		}
	}
	t.Fatalf("no fixture named %s", id)
	return nil
}

// runAgainst puts one template against a listener and returns what came out.
func runAgainst(t *testing.T, templateID, addr string) (*Interpreter, safety.Result) {
	t.Helper()

	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("split %s: %v", addr, err)
	}

	tmpl, ok := mustLibrary(t).ByID(templateID)
	if !ok {
		t.Fatalf("no template named %s", templateID)
	}
	// The listener is on an ephemeral port, so the template's own port is
	// redirected. Nothing else about it is changed.
	tmpl.Port = atoi(t, port)

	exchange, err := tmpl.Build(host)
	if err != nil {
		t.Fatalf("build the exchange: %v", err)
	}

	interpreter := NewInterpreter()
	engine, err := safety.NewEngine(safety.DefaultPolicy(), NetDialer{},
		safety.WithInterpreter(interpreter))
	if err != nil {
		t.Fatalf("build the engine: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	result, err := engine.Run(ctx, safety.Plan{Exchanges: []safety.Exchange{exchange}})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	return interpreter, result
}

func atoi(t *testing.T, raw string) int {
	t.Helper()
	value := 0
	for _, r := range raw {
		if r < '0' || r > '9' {
			t.Fatalf("port %q is not a number", raw)
		}
		value = value*10 + int(r-'0')
	}
	return value
}

// TestProbeIdentifiesAModbusDeviceEndToEnd walks the whole active path.
//
// The template builds a request, the engine sends it, the transport frames the
// reply, the interpreter decodes it and the inventory records it. Every one of
// those has its own test; this is the only one that checks they are wired to
// each other.
func TestProbeIdentifiesAModbusDeviceEndToEnd(t *testing.T) {
	server := startReplayTCP(t, [][]byte{
		fixtureResponse(t, "conpot-default-modbus-read-device-identification"),
	})

	interpreter, result := runAgainst(t, "modbus-device-id", server.addr)

	if result.Answered != 1 {
		t.Fatalf("%d of %d packets answered, want 1", result.Answered, result.Sent)
	}

	observations := interpreter.Observations()
	if len(observations) != 1 {
		t.Fatalf("recorded %d observations, want 1", len(observations))
	}
	if got := observations[0].Identity.Vendor; !strings.EqualFold(got, "siemens") {
		t.Errorf("the device identified as vendor %q, want Siemens", got)
	}

	inventory := BuildInventory(observations, time.Now().UTC())
	if len(inventory.Assets) != 1 {
		t.Fatalf("built %d assets from one device", len(inventory.Assets))
	}
	entry := inventory.Assets[0]
	if len(entry.Services) != 1 || entry.Services[0].Protocol != "modbus" {
		t.Errorf("the asset records services %+v, want one modbus service", entry.Services)
	}
	if len(entry.Evidence) != 1 {
		t.Fatalf("the asset carries %d pieces of evidence, want 1", len(entry.Evidence))
	}

	// The evidence has to carry the bytes. A claim about a device that cannot be
	// traced back to the packet behind it is an assertion, not an observation.
	evidence := entry.Evidence[0]
	if len(evidence.Request) == 0 || len(evidence.Response) == 0 {
		t.Error("the evidence records no bytes, so the finding cannot be checked against the wire")
	}
	if evidence.TemplateID != "modbus-device-id" {
		t.Errorf("the evidence names template %q", evidence.TemplateID)
	}
}

// TestProbeWalksTheS7HandshakeEndToEnd is the case the step model exists for.
//
// The four responses come from two sources, because no single recording in the
// corpus covers the whole conversation. That is fine for what this checks: the
// question is whether the probe completes a handshake and assembles identity
// from a later step, not whether one CPU produced all four frames.
func TestProbeWalksTheS7HandshakeEndToEnd(t *testing.T) {
	server := startReplayTCP(t, [][]byte{
		fixtureResponse(t, "conpot-default-s7comm-connection-confirm"),
		fixtureResponse(t, "iti-siemens-s7-300-setup-communication"),
		fixtureResponse(t, "iti-siemens-s7-300-module-identification"),
		fixtureResponse(t, "iti-siemens-s7-300-order-number"),
	})

	interpreter, result := runAgainst(t, "s7comm-identify-rack0-slot2", server.addr)

	if result.Answered != 4 {
		t.Fatalf("%d of %d packets answered, want all 4 steps of the handshake", result.Answered, result.Sent)
	}
	if len(server.requests) != 4 {
		t.Fatalf("the device received %d requests, want 4", len(server.requests))
	}

	// Identity comes from the third and fourth steps, which is the whole reason
	// the first two are sent at all.
	var vendor, product string
	for _, obs := range interpreter.Observations() {
		if obs.Identity.Vendor != "" {
			vendor = obs.Identity.Vendor
		}
		if obs.Identity.Product != "" {
			product = obs.Identity.Product
		}
	}
	if !strings.EqualFold(vendor, "siemens") {
		t.Errorf("the CPU identified as vendor %q, want Siemens", vendor)
	}
	if !strings.Contains(product, "315") {
		t.Errorf("the CPU identified as product %q, want a 315", product)
	}
}

// TestProbeReadsABACnetDeviceOverUDP exercises the datagram path, which is a
// different route through the transport than every other template.
func TestProbeReadsABACnetDeviceOverUDP(t *testing.T) {
	server := startReplayUDP(t, [][]byte{
		fixtureResponse(t, "conpot-default-bacnet-i-am"),
		fixtureResponse(t, "conpot-default-bacnet-model-name"),
	})

	interpreter, result := runAgainst(t, "bacnet-device-identity", server.addr)

	// The template has five steps and the server scripts two answers, so the
	// rest go unanswered. That is the ordinary case in the field: a device that
	// does not publish a property simply does not reply.
	if result.Answered < 2 {
		t.Fatalf("%d packets answered, want at least the two the server scripted", result.Answered)
	}

	var sawModel bool
	for _, obs := range interpreter.Observations() {
		if obs.Identity.Product != "" {
			sawModel = true
		}
	}
	if !sawModel {
		t.Error("nothing in the run produced a model name from the recorded BACnet reply")
	}
}

// TestProbeRecordsADeviceThatRefuses keeps a refusal from looking like silence.
//
// A device answering "I do not implement that function" has proved it is there,
// that it is listening on that port and that it speaks the protocol. Dropping
// that would report an OpenPLC as an empty address.
func TestProbeRecordsADeviceThatRefuses(t *testing.T) {
	server := startReplayTCP(t, [][]byte{
		fixtureResponse(t, "openplc-v3-modbus-identification-refused"),
	})

	interpreter, result := runAgainst(t, "modbus-device-id", server.addr)

	if result.Answered != 1 {
		t.Fatalf("a protocol level refusal counted as %d answers, want 1", result.Answered)
	}
	observations := interpreter.Observations()
	if len(observations) != 1 || observations[0].Refusal == "" {
		t.Fatalf("the refusal was not recorded: %+v", observations)
	}

	inventory := BuildInventory(observations, time.Now().UTC())
	if len(inventory.Assets) != 1 {
		t.Fatalf("a refusing device produced %d assets, want 1", len(inventory.Assets))
	}
	if services := inventory.Assets[0].Services; len(services) != 1 || services[0].Protocol != "modbus" {
		t.Errorf("a device that refused a Modbus function was not recorded as speaking Modbus: %+v", services)
	}
}

// TestProbeReportsAnAddressThatIsNotThere is the common case for most of a
// scanned range, and it must not look like an error.
func TestProbeReportsAnAddressThatIsNotThere(t *testing.T) {
	// A listener opened and immediately closed leaves a port nothing is on,
	// which is what an unused address in a range behaves like.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := listener.Addr().String()
	listener.Close()

	interpreter, result := runAgainst(t, "modbus-device-id", addr)

	if result.Failed != 1 || result.Answered != 0 {
		t.Errorf("an empty address produced %d failures and %d answers, want 1 and 0",
			result.Failed, result.Answered)
	}
	if len(interpreter.Observations()) != 0 {
		t.Error("an address with nothing on it produced an observation")
	}
	if assets := BuildInventory(interpreter.Observations(), time.Now().UTC()).Assets; len(assets) != 0 {
		t.Errorf("an empty address produced %d inventory entries", len(assets))
	}
}
