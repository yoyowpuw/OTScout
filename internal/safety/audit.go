package safety

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/yoyowpuw/OTScout/internal/asset"
	"github.com/yoyowpuw/OTScout/internal/version"
)

// Outcome is what happened to one exchange.
type Outcome string

const (
	// OutcomeAnswered means the device replied. Whether the reply was useful is
	// a separate question that this package does not ask.
	OutcomeAnswered Outcome = "answered"

	// OutcomeNoAnswer means the target did not reply within the read timeout.
	OutcomeNoAnswer Outcome = "no-answer"

	// OutcomeUnreachable means the connection could not be established.
	OutcomeUnreachable Outcome = "unreachable"

	// OutcomeSkippedRisk means the template outranked the allowed risk.
	OutcomeSkippedRisk Outcome = "skipped-risk"

	// OutcomeSkippedDenied means the deny list forbade it.
	OutcomeSkippedDenied Outcome = "skipped-denied"

	// OutcomeSkippedAborted means the run had already stopped when this
	// exchange came up. These are recorded rather than dropped, so the audit
	// file shows what was not done as well as what was.
	OutcomeSkippedAborted Outcome = "skipped-aborted"

	// OutcomeDryRun means the bytes were rendered and nothing was sent.
	OutcomeDryRun Outcome = "dry-run"
)

// Sent reports whether this outcome involved putting bytes on the wire, which is
// the only question the abort arithmetic and the packet counter care about.
func (o Outcome) Sent() bool {
	return o == OutcomeAnswered || o == OutcomeNoAnswer || o == OutcomeUnreachable
}

// Failed reports whether this outcome counts against the error rate.
//
// A skip is not a failure. A device answering with a protocol level refusal is
// not one either, and does not reach this package: from here that is an answer,
// because something replied and the network is fine.
func (o Outcome) Failed() bool {
	return o == OutcomeNoAnswer || o == OutcomeUnreachable
}

// Record is one line of the audit file.
type Record struct {
	Timestamp  time.Time `json:"timestamp"`
	Target     string    `json:"target"`
	Transport  string    `json:"transport"`
	TemplateID string    `json:"template_id"`
	Protocol   string    `json:"protocol"`
	Risk       Risk      `json:"risk"`

	// Step and Steps place this packet within its exchange, counting from one.
	// A reader tracing an S7 identification needs to see that the first two
	// packets set up a session and only the third asked for anything.
	Step  int `json:"step,omitempty"`
	Steps int `json:"steps,omitempty"`

	Purpose    string         `json:"purpose,omitempty"`
	Outcome    Outcome        `json:"outcome"`
	Request    asset.HexBytes `json:"request,omitempty"`
	Response   asset.HexBytes `json:"response,omitempty"`
	DurationMS int64          `json:"duration_ms,omitempty"`
	Detail     string         `json:"detail,omitempty"`
}

// Header is the first line of the audit file and describes the run rather than
// any one packet.
type Header struct {
	Timestamp time.Time `json:"timestamp"`
	Kind      string    `json:"kind"`

	// Version is the build that ran, stamped by WriteHeader rather than by the
	// caller.
	Version string `json:"version"`

	// Reason is what the operator said the scan was for. It is required, and it
	// is required because the file exists to be read by somebody who was not
	// there and who is entitled to know why their network was touched.
	Reason string `json:"reason"`

	// Invocation is the command line as given.
	Invocation []string `json:"invocation,omitempty"`

	// Policy is the effective settings, rendered so that reading the file does
	// not require knowing this tool's defaults for the version that produced it.
	Policy []string `json:"policy"`

	DryRun bool `json:"dry_run"`
}

// Summary is the last line, so that a truncated file is visibly truncated.
type Summary struct {
	Timestamp   time.Time `json:"timestamp"`
	Kind        string    `json:"kind"`
	Attempted   int       `json:"attempted"`
	Sent        int       `json:"sent"`
	Answered    int       `json:"answered"`
	Failed      int       `json:"failed"`
	Skipped     int       `json:"skipped"`
	Aborted     bool      `json:"aborted"`
	AbortReason string    `json:"abort_reason,omitempty"`
	DurationMS  int64     `json:"duration_ms"`
}

// Auditor writes the audit trail as JSON Lines.
//
// One object per line, flushed as it happens rather than buffered to the end. A
// run that is killed halfway is exactly when the file matters most, so it has to
// be readable at every instant rather than only after a clean exit.
type Auditor struct {
	w       io.Writer
	closer  io.Closer
	encoder *json.Encoder
	path    string
}

// NewAuditor opens an audit file, creating the directory if needed.
//
// The file is refused rather than overwritten if it already exists. An audit
// trail that can be silently replaced by the next run is not an audit trail, and
// the cost of the refusal is one changed filename.
func NewAuditor(path string) (*Auditor, error) {
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, fmt.Errorf("create audit directory: %w", err)
		}
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return nil, fmt.Errorf("open audit file: %w", err)
	}
	return newAuditor(file, file, path), nil
}

// NewAuditorTo writes to an already open destination, for tests and for callers
// that want the trail on standard output.
func NewAuditorTo(w io.Writer) *Auditor {
	return newAuditor(w, nil, "")
}

func newAuditor(w io.Writer, closer io.Closer, path string) *Auditor {
	encoder := json.NewEncoder(w)
	// Every record on one line, which is what makes the file greppable and what
	// lets a reader tell a complete record from a partial one.
	encoder.SetEscapeHTML(false)
	return &Auditor{w: w, closer: closer, encoder: encoder, path: path}
}

// Path is where the trail is being written, or empty when it is not a file.
func (a *Auditor) Path() string {
	if a == nil {
		return ""
	}
	return a.path
}

func (a *Auditor) write(v any) error {
	if a == nil {
		return nil
	}
	if err := a.encoder.Encode(v); err != nil {
		return fmt.Errorf("write audit record: %w", err)
	}
	if f, ok := a.w.(*os.File); ok {
		// Sync rather than trust the buffer, for the same reason the records are
		// not batched: the interesting run is the one that ends badly.
		if err := f.Sync(); err != nil {
			return fmt.Errorf("flush audit record: %w", err)
		}
	}
	return nil
}

// WriteHeader records what the run is and under what settings.
//
// The build version is stamped here rather than taken from the caller, because
// it is the one field a reader always needs and the one a caller would never
// think to pass. Whether a probe was safe is a question about a particular
// build, and a file that does not name one cannot answer it.
func (a *Auditor) WriteHeader(h Header) error {
	h.Kind = "run"
	h.Version = version.Short()
	return a.write(h)
}

// WriteRecord records one exchange.
func (a *Auditor) WriteRecord(r Record) error {
	return a.write(r)
}

// WriteSummary records the totals.
func (a *Auditor) WriteSummary(s Summary) error {
	s.Kind = "summary"
	return a.write(s)
}

// Close releases the file, if this auditor owns one.
func (a *Auditor) Close() error {
	if a == nil || a.closer == nil {
		return nil
	}
	return a.closer.Close()
}
