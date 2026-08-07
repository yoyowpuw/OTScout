package probe

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestASinglePrefixExpandsToItsHosts(t *testing.T) {
	got, err := ExpandTargets([]string{"10.0.0.0/29"})
	if err != nil {
		t.Fatalf("expand: %v", err)
	}
	// The network and broadcast addresses are dropped. Neither is a device and
	// neither answers, so including them would add two failures per subnet to
	// the error rate the run aborts on.
	want := []string{"10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4", "10.0.0.5", "10.0.0.6"}
	if !slices.Equal(got, want) {
		t.Errorf("expanded to %v, want %v", got, want)
	}
}

func TestASingleAddressAndAHostRouteAreTakenLiterally(t *testing.T) {
	for _, spec := range []string{"10.0.0.7", "10.0.0.7/32"} {
		got, err := ExpandTargets([]string{spec})
		if err != nil {
			t.Fatalf("expand %s: %v", spec, err)
		}
		if !slices.Equal(got, []string{"10.0.0.7"}) {
			t.Errorf("%s expanded to %v, want just the address", spec, got)
		}
	}
}

func TestARangeIsInclusiveAtBothEnds(t *testing.T) {
	got, err := ExpandTargets([]string{"192.168.1.10-192.168.1.13"})
	if err != nil {
		t.Fatalf("expand: %v", err)
	}
	want := []string{"192.168.1.10", "192.168.1.11", "192.168.1.12", "192.168.1.13"}
	if !slices.Equal(got, want) {
		t.Errorf("expanded to %v, want %v", got, want)
	}
}

func TestOverlappingTargetsAreContactedOnce(t *testing.T) {
	got, err := ExpandTargets([]string{"10.0.0.1", "10.0.0.0/29", "10.0.0.1-10.0.0.3"})
	if err != nil {
		t.Fatalf("expand: %v", err)
	}
	seen := make(map[string]int)
	for _, addr := range got {
		seen[addr]++
	}
	for addr, count := range seen {
		if count > 1 {
			t.Errorf("%s appears %d times, so it would be probed twice", addr, count)
		}
	}
}

// TestAHostNameIsRefused matters for the audit file rather than for the scan.
//
// A name is resolved somewhere this tool cannot see, so a run recorded against a
// name cannot later be checked against what was actually contacted.
func TestAHostNameIsRefused(t *testing.T) {
	_, err := ExpandTargets([]string{"plc-01.plant.example"})
	if err == nil {
		t.Fatal("a host name was accepted as a target")
	}
	if !strings.Contains(err.Error(), "audit") {
		t.Errorf("the refusal does not explain itself:\n%v", err)
	}
}

// TestAnEnormousRangeIsRefused is the guard against one wrong keystroke.
//
// The difference between /24 and /8 is one character, and the difference in what
// gets touched is four orders of magnitude.
func TestAnEnormousRangeIsRefused(t *testing.T) {
	for _, spec := range []string{"10.0.0.0/8", "10.0.0.0/12", "10.0.0.1-10.9.0.1"} {
		if _, err := ExpandTargets([]string{spec}); err == nil {
			t.Errorf("%s was expanded without argument", spec)
		}
	}
}

func TestAMalformedTargetIsRefused(t *testing.T) {
	for _, spec := range []string{"10.0.0.256", "10.0.0.0/33", "10.0.0.5-10.0.0.1", "", "  ", "not-an-address"} {
		if _, err := ExpandTargets([]string{spec}); err == nil {
			t.Errorf("%q was accepted as a target", spec)
		}
	}
}

func TestATargetFileIgnoresBlanksAndComments(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hosts.txt")
	contents := "# the cell 3 controllers\n\n10.0.0.1\n  10.0.0.2  \n\n# spare\n10.0.0.3\n"
	if err := os.WriteFile(path, []byte(contents), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	specs, err := ReadTargetFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	got, err := ExpandTargets(specs)
	if err != nil {
		t.Fatalf("expand: %v", err)
	}
	if !slices.Equal(got, []string{"10.0.0.1", "10.0.0.2", "10.0.0.3"}) {
		t.Errorf("read %v", got)
	}
}
