// Package safety decides whether a packet may be sent to industrial equipment,
// and how slowly.
//
// Every other package in this project reads. This one is the only place that can
// cause something to happen on a plant floor, which is why the rules it enforces
// are code rather than documentation and why it owns the sending loop instead of
// advising a caller who owns it.
//
// The reason for the caution is not squeamishness. A PLC on a network segment may
// be holding a valve position, a burner interlock or a turbine governor, and some
// field devices have single threaded network stacks that stall on a request they
// do not recognise. Stalling the network stack can stall the scan cycle. The ICS
// community treats active scanning as something done deliberately, in a
// maintenance window, with plant staff informed, or not at all, and a tool that
// does not respect that is a tool nobody in the field will install.
//
// The guarantees, in the order they take effect:
//
//  1. Nothing is sent that the caller did not build from a request builder in the
//     protocol package, and no builder there encodes a write, a reset or a stop.
//  2. Nothing is sent above the risk rating the operator allowed, which defaults
//     to the lowest one.
//  3. Nothing is sent to a device the deny list says reacts badly to it.
//  4. Nothing is sent concurrently. One host, one connection, one packet at a
//     time, with a delay between packets and a ceiling on the global rate.
//  5. Nothing is sent at all in dry run, which renders the same bytes for review.
//  6. Everything sent is written to an audit file as it happens.
//  7. The run stops on its own if devices start failing to answer.
//
// The seam with the rest of the project is deliberate: this package knows nothing
// about protocols. It is handed exchanges that somebody else built and decides
// when, whether and how fast. That keeps the question of what a probe says
// separate from the question of whether it should be spoken at all.
package safety

import (
	"fmt"
	"net"
	"strconv"
)

// Target is one endpoint a probe may address.
type Target struct {
	// Host is an IP address. Names are resolved before they reach this package,
	// so that the audit log records what was actually contacted rather than what
	// was typed.
	Host string

	Port int

	// Transport is "tcp" or "udp".
	Transport string
}

// Address renders the target the way a dialer wants it.
func (t Target) Address() string {
	return net.JoinHostPort(t.Host, strconv.Itoa(t.Port))
}

func (t Target) String() string {
	return t.Transport + "://" + t.Address()
}

// Validate rejects a target that could not have come from target expansion.
//
// A malformed target is not a formatting problem. The host string ends up in a
// dial call, so anything that is not already an IP address is a way of sending
// traffic somewhere the operator did not name and the audit log cannot explain.
func (t Target) Validate() error {
	if net.ParseIP(t.Host) == nil {
		return fmt.Errorf("target host %q is not an IP address", t.Host)
	}
	if t.Port < 1 || t.Port > 65535 {
		return fmt.Errorf("target port %d is not a port", t.Port)
	}
	if t.Transport != "tcp" && t.Transport != "udp" {
		return fmt.Errorf("target transport %q must be tcp or udp", t.Transport)
	}
	return nil
}

// Step is one request and the reply expected to follow it.
//
// Request holds finished bytes. This package neither builds nor parses them,
// which is what keeps the read-only guarantee provable somewhere else: the bytes
// can only have come from a builder in the protocol package, and no builder there
// encodes a state change.
type Step struct {
	// Purpose is a short phrase for the audit log and the dry run, saying what
	// this step is asking the device for.
	Purpose string

	Request []byte
}

// Exchange is one template run against one target: an ordered set of steps that
// share a connection, and everything needed to decide whether to send any of it.
//
// Several protocols cannot identify a device in one packet. An S7 CPU will not
// answer a Read SZL until a COTP connection has been established and a maximum
// PDU size negotiated, which is three round trips before anything useful comes
// back, all on the same socket. Modelling that as three unrelated exchanges would
// break it, and hiding it inside the transport would put three packets on a wire
// with no pacing between them and two of them missing from the audit file. So the
// sequence is declared here, and the engine walks it.
type Exchange struct {
	Target Target

	// TemplateID names the template that produced these steps, so that a report
	// of a device misbehaving can be traced to something a person can revise.
	TemplateID string

	Protocol string
	Risk     Risk
	Steps    []Step
}

// Packets is how many requests this exchange would put on the wire.
func (e Exchange) Packets() int { return len(e.Steps) }

// Validate rejects an exchange that cannot be audited or attributed.
func (e Exchange) Validate() error {
	if err := e.Target.Validate(); err != nil {
		return err
	}
	if e.TemplateID == "" {
		return fmt.Errorf("exchange for %s names no template, so a device that reacts badly to it could not be reported", e.Target)
	}
	if e.Protocol == "" {
		return fmt.Errorf("exchange %s names no protocol", e.TemplateID)
	}
	if err := e.Risk.Validate(); err != nil {
		return fmt.Errorf("exchange %s: %w", e.TemplateID, err)
	}
	if len(e.Steps) == 0 {
		return fmt.Errorf("exchange %s has no steps", e.TemplateID)
	}
	for idx, step := range e.Steps {
		if len(step.Request) == 0 {
			return fmt.Errorf("exchange %s step %d has no request bytes", e.TemplateID, idx+1)
		}
	}
	return nil
}
