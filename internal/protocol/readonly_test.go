package protocol

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// reviewedBuilders is the complete set of messages this project can put on a
// wire, and why each one is safe to send to a control device.
//
// The list is here rather than in a document because the test below fails when
// the package grows a builder that is not on it. Adding an entry is therefore not
// paperwork: it is the moment somebody decides a new kind of packet may reach
// industrial equipment, and it forces that decision into a diff where a reviewer
// will see it. Deleting an entry to make the test pass would be visible in the
// same diff.
var reviewedBuilders = map[string]string{
	"ModbusDeviceIDRequest": "function 43 with MEI type 14, Read Device Identification. " +
		"The read code is bounded by the builder, and no other function code is reachable from here.",

	"ENIPListIdentityRequest": "encapsulation command 0x0063, List Identity. It is answered " +
		"before any CIP session exists, so it cannot carry a service that changes anything.",

	"S7ConnectionRequest": "COTP connection request. It establishes the transport and " +
		"carries no S7 job.",

	"S7SetupCommunication": "the S7 job that negotiates PDU size. It is a prerequisite for " +
		"reading and writes nothing.",

	"S7ReadSZLRequest": "SZL read, the diagnostic list a CPU keeps about itself. It is a read " +
		"of system state, not of process data, and not a write.",

	"BACnetWhoIsRequest": "unconfirmed service 8, Who-Is. A device announces itself and " +
		"nothing changes.",

	"BACnetReadPropertyRequest": "confirmed service 12, ReadProperty. The write counterparts " +
		"are services 15 and 16, and neither has an encoder in this package.",

	"BuildRequest": "not an encoder. It looks up one of the builders above by name and passes " +
		"parameters to it, which is how a template reaches them. It can only return what they " +
		"return, and TestTheRegistryOffersNothingBeyondTheReviewedBuilders pins the set it " +
		"can reach.",
}

// reviewedRequests is the set of names a template may ask for.
//
// The Go functions above are what exists; this is what a YAML file can reach.
// They are checked separately because they can drift apart in both directions: a
// builder could be added to the registry under a name nobody reviewed, or a name
// could survive in the registry after the function behind it changed meaning.
var reviewedRequests = map[string]bool{
	"modbus.read-device-identification": true,
	"enip.list-identity":                true,
	"s7comm.connection-request":         true,
	"s7comm.setup-communication":        true,
	"s7comm.read-szl":                   true,
	"bacnet.who-is":                     true,
	"bacnet.read-property":              true,
}

// TestTheRegistryOffersNothingBeyondTheReviewedBuilders guards the surface a
// template can actually reach.
//
// docs/SAFETY.md says a template chooses a request by name and cannot supply
// bytes. That claim is only worth something if the list of names is fixed, so
// this fails when the registry grows or loses one.
func TestTheRegistryOffersNothingBeyondTheReviewedBuilders(t *testing.T) {
	offered := BuilderNames()
	if len(offered) == 0 {
		t.Fatal("the registry is empty, so this test would pass no matter what was added to it")
	}

	for _, name := range offered {
		if !reviewedRequests[name] {
			t.Errorf("a template can ask for %q, which is not in reviewedRequests. "+
				"Adding a name here means a new kind of packet may reach industrial equipment.", name)
		}
	}
	for name := range reviewedRequests {
		if !HasBuilder(name) {
			t.Errorf("reviewedRequests lists %q, which the registry no longer offers", name)
		}
	}
}

// TestAnUnknownRequestNameIsRefused keeps a typo in a template from silently
// sending nothing, or worse, something else.
func TestAnUnknownRequestNameIsRefused(t *testing.T) {
	_, err := BuildRequest("modbus.write-single-coil", nil)
	if err == nil {
		t.Fatal("the registry built a request for a name it does not have")
	}
	// The error lists what does exist, because the operator hitting this is
	// usually writing a template and needs to know what is available.
	if !strings.Contains(err.Error(), "modbus.read-device-identification") {
		t.Errorf("the refusal does not say what can be asked for instead:\n%v", err)
	}
}

// TestAParameterTooLargeForItsFieldIsRefused stops a template from quietly
// sending a value nobody wrote.
//
// A number that overflows its field wraps rather than failing, so a unit id of
// 300 would reach the wire as 44. That is a different device.
func TestAParameterTooLargeForItsFieldIsRefused(t *testing.T) {
	cases := []struct {
		builder string
		params  Params
	}{
		{"modbus.read-device-identification", Params{"unit_id": "300"}},
		{"modbus.read-device-identification", Params{"transaction_id": "70000"}},
		{"s7comm.read-szl", Params{"szl_id": "70000"}},
		{"bacnet.read-property", Params{"invoke_id": "256"}},
	}
	for _, tc := range cases {
		if _, err := BuildRequest(tc.builder, tc.params); err == nil {
			t.Errorf("%s accepted %v, which does not fit the field it goes in", tc.builder, tc.params)
		}
	}
}

// TestThePackageEncodesNoWrites reads this package's own source and fails when it
// exports a byte producing function that has not been reviewed.
//
// docs/SAFETY.md tells operators that no encoder for a write, a reset or a stop
// exists here. That sentence is either enforced or it is a sales pitch, and the
// only way to enforce it is to notice when the set of encoders changes.
func TestThePackageEncodesNoWrites(t *testing.T) {
	sources, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("list the protocol package: %v", err)
	}

	found := make(map[string]bool)
	for _, path := range sources {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		source, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		for _, match := range byteBuilder.FindAllStringSubmatch(string(source), -1) {
			found[match[1]] = true
		}
	}

	if len(found) == 0 {
		t.Fatal("found no request builders at all, which means this test is looking in the wrong place " +
			"and has been passing for the wrong reason")
	}

	for _, name := range sorted(found) {
		if _, reviewed := reviewedBuilders[name]; !reviewed {
			t.Errorf("%s builds bytes that could be sent to a control device and is not in reviewedBuilders. "+
				"If it is a read-only request, add it there with the function or service code it encodes and why "+
				"that is safe. If it is not, it does not belong in this project.", name)
		}
	}

	for _, name := range sorted(toSet(reviewedBuilders)) {
		if !found[name] {
			t.Errorf("reviewedBuilders lists %s, which no longer exists. Remove the entry so the list keeps "+
				"describing what this build can actually send.", name)
		}
	}
}

// byteBuilder matches an exported package level function that returns a []byte,
// which is the shape every request builder here has and the shape anything
// sendable would have.
//
// This reads the source as text rather than parsing it. A parser would be more
// precise about a signature nobody in this package writes, and the check that
// matters is the one below: if this pattern ever finds nothing, the test fails
// rather than passing on an empty set.
var byteBuilder = regexp.MustCompile(`(?m)^func ([A-Z]\w*)\([^)]*\)[^{]*\[\]byte`)

func sorted(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for name := range set {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

func toSet(m map[string]string) map[string]bool {
	out := make(map[string]bool, len(m))
	for name := range m {
		out[name] = true
	}
	return out
}
