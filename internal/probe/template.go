// Package probe turns fingerprint templates into traffic, under the safety
// engine.
//
// The split with internal/safety is deliberate and worth stating. This package
// decides what to ask a device and how to read the answer. That package decides
// whether the question may be asked at all, how slowly, and what gets written
// down. Neither can be quietly bypassed by the other: nothing here opens a socket
// except through a safety.Engine, and nothing there knows what a Modbus frame is.
//
// A template is data. It names a request from the closed set in the protocol
// package and supplies parameters, which is why the read-only guarantee holds
// for templates nobody has written yet. There is no field in the schema that
// carries bytes, so a contributor cannot express a write even by accident.
package probe

import (
	"embed"
	"fmt"
	"io/fs"
	"path"
	"regexp"
	"sort"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"

	"github.com/yoyowpuw/OTScout/internal/protocol"
	"github.com/yoyowpuw/OTScout/internal/safety"
)

//go:embed templates/*.yaml
var templateFS embed.FS

const templateDir = "templates"

// Template is one fingerprint probe: a protocol, a port, a risk rating and the
// ordered requests that identify a device.
type Template struct {
	// ID names the template. It appears in the audit log, in the deny list and
	// in bug reports, so it has to be stable and typeable.
	ID string `yaml:"id"`

	// Summary says in one line what this template gets from a device.
	Summary string `yaml:"summary"`

	// Protocol is the decoder that reads the replies.
	Protocol string `yaml:"protocol"`

	Port      int    `yaml:"port"`
	Transport string `yaml:"transport"`

	Risk safety.Risk `yaml:"risk"`

	// RiskNote explains the rating. It is required for anything above safe,
	// because a rating without a reason cannot be argued with or revised.
	RiskNote string `yaml:"risk_note,omitempty"`

	// References are where the request is specified, so a reviewer can check
	// that it is the standard identification call it claims to be.
	References []string `yaml:"references,omitempty"`

	Steps []Step `yaml:"steps"`
}

// Step is one request within a template.
type Step struct {
	// Purpose is shown in the dry run and the audit log.
	Purpose string `yaml:"purpose"`

	// Request names a builder in the protocol package. It is a name rather than
	// bytes, which is the whole of the read-only guarantee.
	Request string `yaml:"request"`

	Params map[string]string `yaml:"params,omitempty"`
}

type templateFile struct {
	Version   int        `yaml:"version"`
	Templates []Template `yaml:"templates"`
}

// Library is the loaded set of templates.
type Library struct {
	templates []Template
	byID      map[string]*Template
}

var (
	defaultLibraryOnce sync.Once
	defaultLibrary     *Library
	defaultLibraryErr  error
)

// DefaultLibrary returns the embedded templates, parsed once.
func DefaultLibrary() (*Library, error) {
	defaultLibraryOnce.Do(func() {
		defaultLibrary, defaultLibraryErr = loadLibrary(templateFS, templateDir)
	})
	return defaultLibrary, defaultLibraryErr
}

func loadLibrary(fsys fs.FS, dir string) (*Library, error) {
	entries, err := fs.ReadDir(fsys, dir)
	if err != nil {
		return nil, fmt.Errorf("read template directory: %w", err)
	}

	var templates []Template
	definedIn := make(map[string]string)

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".yaml") {
			continue
		}
		raw, err := fs.ReadFile(fsys, path.Join(dir, entry.Name()))
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", entry.Name(), err)
		}
		parsed, err := ParseTemplates(raw)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", entry.Name(), err)
		}
		for _, tmpl := range parsed {
			if first, clash := definedIn[tmpl.ID]; clash {
				return nil, fmt.Errorf("template id %q is defined in both %s and %s",
					tmpl.ID, first, entry.Name())
			}
			definedIn[tmpl.ID] = entry.Name()
			templates = append(templates, tmpl)
		}
	}

	if len(templates) == 0 {
		return nil, fmt.Errorf("the template library is empty")
	}

	sort.Slice(templates, func(i, j int) bool { return templates[i].ID < templates[j].ID })

	lib := &Library{templates: templates, byID: make(map[string]*Template, len(templates))}
	for idx := range lib.templates {
		lib.byID[lib.templates[idx].ID] = &lib.templates[idx]
	}
	return lib, nil
}

// templateID is what an id may look like. Lowercase and hyphens only, because it
// becomes a file name, a command line argument and a deny list key.
var templateID = regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*$`)

// ParseTemplates reads and validates a template file.
//
// Everything is checked here rather than at send time. A template with a typo in
// a request name would otherwise fail partway through a scan, against equipment,
// which is the worst place to discover it.
func ParseTemplates(raw []byte) ([]Template, error) {
	var file templateFile
	if err := yaml.Unmarshal(raw, &file); err != nil {
		return nil, fmt.Errorf("parse templates: %w", err)
	}

	for idx := range file.Templates {
		if err := file.Templates[idx].Validate(); err != nil {
			return nil, err
		}
	}
	return file.Templates, nil
}

// Validate rejects a template that could not be run, attributed or reviewed.
func (t Template) Validate() error {
	if !templateID.MatchString(t.ID) {
		return fmt.Errorf("template id %q must be lowercase words joined by hyphens", t.ID)
	}
	if strings.TrimSpace(t.Summary) == "" {
		return fmt.Errorf("template %s has no summary, so nothing tells an operator what it would get", t.ID)
	}
	if !knownProtocol(t.Protocol) {
		return fmt.Errorf("template %s names protocol %q, which has no decoder; the ones that exist are %s",
			t.ID, t.Protocol, strings.Join(knownProtocols(), ", "))
	}
	if t.Port < 1 || t.Port > 65535 {
		return fmt.Errorf("template %s names port %d", t.ID, t.Port)
	}
	if t.Transport != "tcp" && t.Transport != "udp" {
		return fmt.Errorf("template %s names transport %q, want tcp or udp", t.ID, t.Transport)
	}
	if err := t.Risk.Validate(); err != nil {
		return fmt.Errorf("template %s: %w", t.ID, err)
	}
	if t.Risk != safety.RiskSafe && strings.TrimSpace(t.RiskNote) == "" {
		return fmt.Errorf("template %s is rated %s and gives no reason; a rating nobody can check "+
			"cannot be revised when somebody learns better", t.ID, t.Risk)
	}
	if len(t.Steps) == 0 {
		return fmt.Errorf("template %s has no steps", t.ID)
	}

	for idx, step := range t.Steps {
		where := fmt.Sprintf("template %s step %d", t.ID, idx+1)
		if strings.TrimSpace(step.Purpose) == "" {
			return fmt.Errorf("%s has no purpose, and it will appear in a change request without one", where)
		}
		if !protocol.HasBuilder(step.Request) {
			return fmt.Errorf("%s asks for request %q, which this build cannot send; the ones it can are %s",
				where, step.Request, strings.Join(protocol.BuilderNames(), ", "))
		}
		// Building it now proves the parameters are usable, so a scan cannot
		// fail on a bad number after it has already touched equipment.
		if _, err := protocol.BuildRequest(step.Request, protocol.Params(step.Params)); err != nil {
			return fmt.Errorf("%s: %w", where, err)
		}
	}
	return nil
}

// Packets is how many requests this template puts on the wire per target.
func (t Template) Packets() int { return len(t.Steps) }

// StepBytes renders the request one step would send, for the templates listing.
func (t Template) StepBytes(idx int) ([]byte, error) {
	if idx < 0 || idx >= len(t.Steps) {
		return nil, fmt.Errorf("template %s has no step %d", t.ID, idx+1)
	}
	step := t.Steps[idx]
	return protocol.BuildRequest(step.Request, protocol.Params(step.Params))
}

// Build produces the exchange this template represents against one target.
func (t Template) Build(host string) (safety.Exchange, error) {
	ex := safety.Exchange{
		Target:     safety.Target{Host: host, Port: t.Port, Transport: t.Transport},
		TemplateID: t.ID,
		Protocol:   t.Protocol,
		Risk:       t.Risk,
	}
	for idx, step := range t.Steps {
		request, err := protocol.BuildRequest(step.Request, protocol.Params(step.Params))
		if err != nil {
			return safety.Exchange{}, fmt.Errorf("template %s step %d: %w", t.ID, idx+1, err)
		}
		ex.Steps = append(ex.Steps, safety.Step{Purpose: step.Purpose, Request: request})
	}
	return ex, ex.Validate()
}

// All returns every template, sorted by id.
func (l *Library) All() []Template {
	out := make([]Template, len(l.templates))
	copy(out, l.templates)
	return out
}

// ByID returns one template.
func (l *Library) ByID(id string) (Template, bool) {
	tmpl, ok := l.byID[id]
	if !ok {
		return Template{}, false
	}
	return *tmpl, true
}

// Select returns the templates named, or every template when none are named.
//
// An unknown name is an error rather than a silent omission. An operator who
// misspells a template and gets a clean run with no findings has been told
// something false about their network.
func (l *Library) Select(ids []string) ([]Template, error) {
	if len(ids) == 0 {
		return l.All(), nil
	}
	out := make([]Template, 0, len(ids))
	var unknown []string
	for _, id := range ids {
		tmpl, ok := l.ByID(id)
		if !ok {
			unknown = append(unknown, id)
			continue
		}
		out = append(out, tmpl)
	}
	if len(unknown) > 0 {
		return nil, fmt.Errorf("no template named %s; run 'otscout templates' to list them",
			strings.Join(unknown, ", "))
	}
	return out, nil
}

// Ports returns the distinct ports the given templates address.
func Ports(templates []Template) []int {
	seen := make(map[int]bool, len(templates))
	var ports []int
	for _, tmpl := range templates {
		if seen[tmpl.Port] {
			continue
		}
		seen[tmpl.Port] = true
		ports = append(ports, tmpl.Port)
	}
	sort.Ints(ports)
	return ports
}

func knownProtocols() []string {
	return []string{protocol.NameModbus, protocol.NameENIP, protocol.NameS7comm, protocol.NameBACnet}
}

func knownProtocol(name string) bool {
	for _, known := range knownProtocols() {
		if known == name {
			return true
		}
	}
	return false
}
