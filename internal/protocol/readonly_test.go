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
