package safety

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestAnExistingAuditFileIsNeverOverwritten is the whole value of the file.
//
// A trail the next run can silently replace is not a trail. The cost of refusing
// is one changed filename, and the cost of not refusing is that the record of the
// run somebody is asking about is gone.
func TestAnExistingAuditFileIsNeverOverwritten(t *testing.T) {
	path := filepath.Join(t.TempDir(), "scan.jsonl")

	first, err := NewAuditor(path)
	if err != nil {
		t.Fatalf("open the first audit file: %v", err)
	}
	if err := first.WriteHeader(Header{Timestamp: time.Now(), Reason: "the run that must survive"}); err != nil {
		t.Fatalf("write header: %v", err)
	}
	if err := first.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	if _, err := NewAuditor(path); err == nil {
		t.Fatal("a second run was allowed to write over the first run's trail")
	}

	kept, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if !strings.Contains(string(kept), "the run that must survive") {
		t.Fatalf("the original trail was damaged:\n%s", kept)
	}
}

func TestTheAuditDirectoryIsCreated(t *testing.T) {
	path := filepath.Join(t.TempDir(), "runs", "2026-03-02", "scan.jsonl")

	auditor, err := NewAuditor(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer auditor.Close()

	if auditor.Path() != path {
		t.Errorf("the auditor reports its path as %q, want %q", auditor.Path(), path)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("the audit file was not created: %v", err)
	}
}

// TestEachRecordIsReadableAsSoonAsItIsWritten covers the run that ends badly,
// which is the one the file matters most for.
func TestEachRecordIsReadableAsSoonAsItIsWritten(t *testing.T) {
	path := filepath.Join(t.TempDir(), "scan.jsonl")
	auditor, err := NewAuditor(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer auditor.Close()

	if err := auditor.WriteHeader(Header{Timestamp: time.Now(), Reason: "why"}); err != nil {
		t.Fatalf("write header: %v", err)
	}
	if err := auditor.WriteRecord(Record{
		Timestamp:  time.Now(),
		Target:     "10.0.0.1:502",
		TemplateID: "modbus-device-id",
		Outcome:    OutcomeAnswered,
		Request:    []byte{0x2b, 0x0e},
		Response:   []byte{0x2b, 0x0e, 0x01},
	}); err != nil {
		t.Fatalf("write record: %v", err)
	}

	// Read while the auditor is still open, which is what a person watching a
	// running scan would do, and what a crash would leave behind.
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read a trail that is still being written: %v", err)
	}
	records := decodeTrail(t, raw)
	if len(records) != 2 {
		t.Fatalf("the file holds %d complete lines mid-run, want 2", len(records))
	}
	if records[1]["request"] != "2b0e" {
		t.Errorf("request bytes came back as %v, want a hex string", records[1]["request"])
	}
}

// TestAnAuditorWithNoDestinationIsHarmless lets a caller that has no trail pass
// nil rather than build a discard writer, without turning that into a panic
// halfway through a run.
func TestAnAuditorWithNoDestinationIsHarmless(t *testing.T) {
	var auditor *Auditor
	if err := auditor.WriteHeader(Header{}); err != nil {
		t.Errorf("write header: %v", err)
	}
	if err := auditor.WriteRecord(Record{}); err != nil {
		t.Errorf("write record: %v", err)
	}
	if err := auditor.WriteSummary(Summary{}); err != nil {
		t.Errorf("write summary: %v", err)
	}
	if err := auditor.Close(); err != nil {
		t.Errorf("close: %v", err)
	}
	if auditor.Path() != "" {
		t.Error("a nil auditor claims a path")
	}
}
