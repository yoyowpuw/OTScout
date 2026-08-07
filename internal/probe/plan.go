package probe

import (
	"fmt"
	"sort"
	"time"

	"github.com/yoyowpuw/OTScout/internal/asset"
	"github.com/yoyowpuw/OTScout/internal/safety"
)

// PlanRequest is what the operator asked for.
type PlanRequest struct {
	Targets   []string
	Templates []Template

	// Known is a previously built inventory, usually from a passive ingest.
	//
	// It does two things, and both matter. Templates are limited to ports the
	// inventory already saw open, so a scan does not knock on doors nobody has
	// reported. And the identities are handed to the safety engine, which is
	// what lets the deny list refuse the first packet to a safety controller
	// rather than the second.
	Known *asset.Inventory

	// OnlyKnownPorts limits each target to the templates whose port the
	// inventory has already seen open on it.
	OnlyKnownPorts bool

	// Port overrides the port every selected template addresses.
	//
	// Non-standard ports are ordinary in the field. Conpot binds Modbus to 5020
	// because the process is unprivileged, and plants put protocols behind
	// gateways on whatever the gateway was configured with. Without this the
	// only way to reach such a device would be to edit a template, which is the
	// wrong place for a fact about one site.
	Port int

	Reason     string
	Invocation []string
}

// BuildPlan turns the request into the exchanges the engine will run.
//
// Targets are taken in order and every template for a target is grouped with it,
// which is the order the engine keeps. A target the inventory rules out entirely
// is dropped here rather than skipped later, so the dry run shows the scan that
// will actually happen.
func BuildPlan(req PlanRequest) (safety.Plan, error) {
	if len(req.Templates) == 0 {
		return safety.Plan{}, fmt.Errorf("no templates selected")
	}

	if req.Port != 0 && (req.Port < 1 || req.Port > 65535) {
		return safety.Plan{}, fmt.Errorf("port %d is not a port", req.Port)
	}

	plan := safety.Plan{Reason: req.Reason, Invocation: req.Invocation}

	for _, host := range req.Targets {
		for _, tmpl := range req.Templates {
			if req.Port != 0 {
				tmpl.Port = req.Port
			}
			if req.OnlyKnownPorts && !knownOpen(req.Known, host, tmpl) {
				continue
			}
			ex, err := tmpl.Build(host)
			if err != nil {
				return safety.Plan{}, err
			}
			plan.Exchanges = append(plan.Exchanges, ex)
		}
	}

	if len(plan.Exchanges) == 0 {
		if req.OnlyKnownPorts {
			return safety.Plan{}, fmt.Errorf(
				"none of the targets have any of the selected template ports open in the inventory. "+
					"Ports looked for: %v. Drop --only-known-ports to knock on them anyway", Ports(req.Templates))
		}
		return safety.Plan{}, fmt.Errorf("the plan is empty")
	}

	plan.Known = knownIdentities(req.Known)
	return plan, nil
}

// knownOpen reports whether the inventory has seen this template's port open on
// this host.
func knownOpen(inv *asset.Inventory, host string, tmpl Template) bool {
	if inv == nil {
		return false
	}
	for idx := range inv.Assets {
		entry := &inv.Assets[idx]
		if entry.Addresses.IPv4 != host && entry.Addresses.IPv6 != host {
			continue
		}
		for _, service := range entry.Services {
			if service.Port == tmpl.Port && service.Transport == tmpl.Transport {
				return true
			}
		}
	}
	return false
}

// knownIdentities extracts what passive collection already established, keyed by
// address, for the deny list to match against.
func knownIdentities(inv *asset.Inventory) map[string]asset.Identity {
	if inv == nil {
		return nil
	}
	out := make(map[string]asset.Identity)
	for idx := range inv.Assets {
		entry := &inv.Assets[idx]
		if entry.Identity.Empty() {
			continue
		}
		for _, addr := range []string{entry.Addresses.IPv4, entry.Addresses.IPv6} {
			if addr != "" {
				out[addr] = entry.Identity
			}
		}
	}
	return out
}

// EstimatePackets is how many requests the plan would put on the wire under a
// given risk ceiling.
func EstimatePackets(plan safety.Plan, allowed safety.Risk) int {
	total := 0
	for _, ex := range plan.Exchanges {
		if ex.Risk.AtMost(allowed) {
			total += ex.Packets()
		}
	}
	return total
}

// BuildInventory turns what the run observed into an asset document.
//
// Every asset carries the evidence it was built from, including the request
// bytes, because an active finding that cannot be traced back to the packet that
// produced it is a claim rather than an observation.
func BuildInventory(observations []Observation, at time.Time) *asset.Inventory {
	inv := asset.NewInventory("otscout probe")

	for idx, obs := range observations {
		addr := asset.Addresses{}
		if isIPv6(obs.Host) {
			addr.IPv6 = obs.Host
		} else {
			addr.IPv4 = obs.Host
		}

		entry := inv.ByAddress(addr)
		entry.Identity.Merge(obs.Identity)
		if entry.Role == "" || entry.Role == asset.RoleUnknown {
			entry.Role = obs.Role
		}
		if entry.FirstSeen.IsZero() {
			entry.FirstSeen = at
		}
		entry.LastSeen = at
		addSource(entry, string(asset.SourceProbe))

		// A service is recorded only when the device answered in a protocol the
		// decoder recognised. A refusal counts: a device that says "I do not
		// implement that function" has proved it speaks the protocol.
		if obs.Protocol != "" {
			mergeService(entry, asset.Service{
				Port:      obs.Port,
				Transport: obs.Transport,
				Protocol:  obs.Protocol,
				FirstSeen: at,
				LastSeen:  at,
				Source:    asset.SourceProbe,
			})
		}

		notes := obs.Notes
		if obs.Refusal != "" {
			notes = append(append([]string{}, notes...), obs.Refusal)
		}
		entry.Evidence = append(entry.Evidence, asset.Evidence{
			ID:         fmt.Sprintf("probe-%04d", idx+1),
			Source:     asset.SourceProbe,
			Protocol:   obs.Protocol,
			TemplateID: obs.TemplateID,
			Endpoint:   fmt.Sprintf("%s:%d", obs.Host, obs.Port),
			Timestamp:  at,
			Request:    obs.Request,
			Response:   obs.Response,
			Fields:     obs.Fields,
			Notes:      notes,
		})
	}

	inv.Finalize()
	return inv
}

func mergeService(entry *asset.Asset, service asset.Service) {
	for idx := range entry.Services {
		existing := &entry.Services[idx]
		if existing.Port == service.Port && existing.Transport == service.Transport {
			if existing.Protocol == "" {
				existing.Protocol = service.Protocol
			}
			existing.LastSeen = service.LastSeen
			existing.Source = asset.SourceProbe
			return
		}
	}
	entry.Services = append(entry.Services, service)
}

func addSource(entry *asset.Asset, source string) {
	for _, existing := range entry.Sources {
		if existing == source {
			return
		}
	}
	entry.Sources = append(entry.Sources, source)
	sort.Strings(entry.Sources)
}

func isIPv6(host string) bool {
	for i := 0; i < len(host); i++ {
		if host[i] == ':' {
			return true
		}
	}
	return false
}
