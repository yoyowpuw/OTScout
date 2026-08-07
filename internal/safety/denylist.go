package safety

import (
	"embed"
	"fmt"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"

	"github.com/yoyowpuw/OTScout/internal/asset"
)

//go:embed data/*.yaml
var dataFS embed.FS

// DenyRule is one recorded case of a device family reacting badly to a probe.
//
// The rule is matched against what the device has already told us about itself,
// which means it can only ever apply to the second and later probes of a host.
// That is the nature of the problem: to know a device is fragile you have to know
// what it is, and to know what it is you have to have asked it something. The
// first question asked of any host is therefore the safest one available, and
// this list narrows what may follow.
type DenyRule struct {
	// ID names the rule so that a skip can be explained and argued with.
	ID string `yaml:"id"`

	// Vendor is the canonical vendor id, matched exactly. Empty matches any.
	Vendor string `yaml:"vendor,omitempty"`

	// Family and Product are matched case insensitively as substrings, because
	// the strings devices report vary in punctuation and spacing far more than
	// they vary in content.
	Family  string `yaml:"family,omitempty"`
	Product string `yaml:"product,omitempty"`

	// Templates lists the template ids this device must not be sent.
	Templates []string `yaml:"templates,omitempty"`

	// Protocols denies everything spoken over the named protocols.
	//
	// Most published reports are about a port rather than a message: the S7-300
	// advisories describe repeated traffic to 102/tcp, not one request. Naming the
	// protocol says that directly, and keeps the rule true when a template is
	// renamed or a new one for the same protocol is added later.
	Protocols []string `yaml:"protocols,omitempty"`

	// Reason is shown to the operator when a probe is skipped. It should say
	// what happens to the device, not that something happens.
	Reason string `yaml:"reason"`

	// References are where the report came from, so a rule can be re-examined
	// rather than inherited forever.
	References []string `yaml:"references,omitempty"`
}

type denyFile struct {
	Version int        `yaml:"version"`
	Rules   []DenyRule `yaml:"rules"`
}

// DenyList is the parsed set of rules.
type DenyList struct {
	rules []DenyRule
}

var (
	defaultDenyOnce sync.Once
	defaultDeny     *DenyList
	defaultDenyErr  error
)

// DefaultDenyList returns the embedded list, parsed once.
func DefaultDenyList() (*DenyList, error) {
	defaultDenyOnce.Do(func() {
		raw, err := dataFS.ReadFile("data/fragile.yaml")
		if err != nil {
			defaultDenyErr = fmt.Errorf("read embedded deny list: %w", err)
			return
		}
		defaultDeny, defaultDenyErr = ParseDenyList(raw)
	})
	return defaultDeny, defaultDenyErr
}

// ParseDenyList reads and validates a deny list.
//
// A rule that matches everything is rejected rather than accepted, because the
// failure mode of this file is silent: a rule with every field left blank would
// deny every probe to every device, and the run would simply find nothing while
// reporting that it had asked.
func ParseDenyList(raw []byte) (*DenyList, error) {
	var file denyFile
	if err := yaml.Unmarshal(raw, &file); err != nil {
		return nil, fmt.Errorf("parse deny list: %w", err)
	}

	seen := make(map[string]bool, len(file.Rules))
	for idx, rule := range file.Rules {
		switch {
		case strings.TrimSpace(rule.ID) == "":
			return nil, fmt.Errorf("deny rule %d has no id, so a skip attributed to it could not be looked up", idx)
		case seen[rule.ID]:
			return nil, fmt.Errorf("duplicate deny rule id %q", rule.ID)
		case strings.TrimSpace(rule.Reason) == "":
			return nil, fmt.Errorf("deny rule %q gives no reason, and a probe skipped without one looks like a bug", rule.ID)
		case rule.Vendor == "" && rule.Family == "" && rule.Product == "":
			return nil, fmt.Errorf("deny rule %q names no vendor, family or product, so it would deny every probe to every device", rule.ID)
		}
		seen[rule.ID] = true
	}

	return &DenyList{rules: file.Rules}, nil
}

// Rules returns the rules, for the templates command and for tests.
func (d *DenyList) Rules() []DenyRule {
	if d == nil {
		return nil
	}
	out := make([]DenyRule, len(d.rules))
	copy(out, d.rules)
	return out
}

// Check reports the rule that forbids this exchange against a device with this
// identity, or nil when nothing does.
//
// The identity is what the run has learned so far, not what the operator expects
// to find, so a rule can only ever stop the second and later probes of a host.
func (d *DenyList) Check(identity asset.Identity, ex Exchange) *DenyRule {
	if d == nil {
		return nil
	}
	for idx := range d.rules {
		rule := &d.rules[idx]
		if rule.matches(identity, ex) {
			return rule
		}
	}
	return nil
}

func (r *DenyRule) matches(identity asset.Identity, ex Exchange) bool {
	// An identity we know nothing about cannot match a rule, and must not: the
	// alternative is that a blank vendor field matches every unidentified host,
	// which would deny the first probe to everything.
	if identity.Empty() {
		return false
	}
	if r.Vendor != "" && !strings.EqualFold(r.Vendor, identity.Vendor) {
		return false
	}
	if r.Family != "" && !containsFold(identity.Family, r.Family) {
		return false
	}
	if r.Product != "" && !containsFold(identity.Product, r.Product) && !containsFold(identity.ProductRaw, r.Product) {
		return false
	}
	// A rule that narrows neither the template nor the protocol denies every
	// active probe to the device, which is the right shape for equipment that
	// should simply be left alone.
	if len(r.Templates) == 0 && len(r.Protocols) == 0 {
		return true
	}
	for _, candidate := range r.Templates {
		if candidate == ex.TemplateID {
			return true
		}
	}
	for _, candidate := range r.Protocols {
		if candidate == ex.Protocol {
			return true
		}
	}
	return false
}

func containsFold(haystack, needle string) bool {
	return strings.Contains(strings.ToLower(haystack), strings.ToLower(needle))
}
