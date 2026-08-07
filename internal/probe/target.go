package probe

import (
	"bufio"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"sort"
	"strings"
)

// MaxTargets is the largest set this tool will expand without being argued with.
//
// The number is not a performance limit. A mistyped prefix is the most likely
// way this tool ever touches equipment nobody meant to touch, and the difference
// between /24 and /8 is one keystroke. At the default pacing a /16 would take
// about four and a half hours per template, so a plan that large is far more
// often a typo than a decision.
const MaxTargets = 4096

// ExpandTargets turns what an operator typed into the addresses that will be
// contacted.
//
// Accepted forms are a single address, a CIDR prefix, and an inclusive range
// written as first-last. Host names are refused: a name is resolved somewhere
// this tool cannot see, and the audit file has to record what was contacted
// rather than what was typed.
func ExpandTargets(specs []string) ([]string, error) {
	if len(specs) == 0 {
		return nil, errors.New("no targets given")
	}

	seen := make(map[netip.Addr]bool)
	var out []netip.Addr

	for _, spec := range specs {
		spec = strings.TrimSpace(spec)
		if spec == "" {
			continue
		}
		addrs, err := expandOne(spec)
		if err != nil {
			return nil, err
		}
		for _, addr := range addrs {
			if seen[addr] {
				continue
			}
			seen[addr] = true
			out = append(out, addr)
			if len(out) > MaxTargets {
				return nil, fmt.Errorf(
					"the targets expand to more than %d addresses. That is usually a prefix with a "+
						"digit wrong rather than a decision, so this tool will not expand it. Narrow the "+
						"range, or split the run", MaxTargets)
			}
		}
	}

	if len(out) == 0 {
		return nil, errors.New("the targets expand to no addresses at all")
	}

	sort.Slice(out, func(i, j int) bool { return out[i].Less(out[j]) })
	rendered := make([]string, len(out))
	for idx, addr := range out {
		rendered[idx] = addr.String()
	}
	return rendered, nil
}

func expandOne(spec string) ([]netip.Addr, error) {
	switch {
	case strings.Contains(spec, "/"):
		return expandPrefix(spec)
	case strings.Contains(spec, "-"):
		return expandRange(spec)
	default:
		addr, err := netip.ParseAddr(spec)
		if err != nil {
			return nil, targetError(spec)
		}
		return []netip.Addr{addr.Unmap()}, nil
	}
}

func expandPrefix(spec string) ([]netip.Addr, error) {
	prefix, err := netip.ParsePrefix(spec)
	if err != nil {
		return nil, targetError(spec)
	}
	prefix = prefix.Masked()

	hostBits := prefix.Addr().BitLen() - prefix.Bits()

	// The size is checked before anything is expanded, and a prefix that is too
	// large is refused rather than truncated. Truncating would be the worst
	// available behaviour: the run would quietly probe the first few thousand
	// addresses of the network and report the rest as nothing being there, which
	// is a false statement about a plant rather than an incomplete one.
	if hostBits >= 32 || int64(1)<<hostBits > int64(MaxTargets) {
		return nil, fmt.Errorf(
			"%s covers 2^%d addresses and this tool expands at most %d. A prefix this wide is "+
				"usually a digit wrong rather than a decision, so it is refused rather than "+
				"trimmed to fit. Narrow it, or split the run",
			spec, hostBits, MaxTargets)
	}

	var out []netip.Addr
	for addr := prefix.Addr(); prefix.Contains(addr); addr = addr.Next() {
		out = append(out, addr)
	}

	// A /31 or /32 is a deliberate way to name one or two addresses, so those
	// are taken literally. Anything wider drops the network and broadcast
	// addresses, which are not devices, answer nothing, and would otherwise add
	// two failures per subnet to the rate the run aborts on.
	if prefix.Addr().Is4() && hostBits >= 2 {
		out = out[1 : len(out)-1]
	}
	return out, nil
}

func expandRange(spec string) ([]netip.Addr, error) {
	first, last, found := strings.Cut(spec, "-")
	if !found {
		return nil, targetError(spec)
	}
	from, err := netip.ParseAddr(strings.TrimSpace(first))
	if err != nil {
		return nil, targetError(spec)
	}
	to, err := netip.ParseAddr(strings.TrimSpace(last))
	if err != nil {
		return nil, targetError(spec)
	}
	from, to = from.Unmap(), to.Unmap()
	if from.BitLen() != to.BitLen() {
		return nil, fmt.Errorf("target range %s mixes IPv4 and IPv6", spec)
	}
	if to.Less(from) {
		return nil, fmt.Errorf("target range %s ends before it starts", spec)
	}

	var out []netip.Addr
	for addr := from; ; addr = addr.Next() {
		out = append(out, addr)
		if addr == to {
			break
		}
		if len(out) > MaxTargets {
			return nil, fmt.Errorf("target range %s covers more than the %d addresses this tool will expand",
				spec, MaxTargets)
		}
	}
	return out, nil
}

func targetError(spec string) error {
	return fmt.Errorf("target %q is not an address, a CIDR prefix or a first-last range. "+
		"Host names are not accepted, because the audit log has to record the address that was "+
		"contacted rather than the name that was typed", spec)
}

// ReadTargetFile reads one target specification per line, ignoring blanks and
// lines starting with a hash.
func ReadTargetFile(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("read target file: %w", err)
	}
	defer file.Close()

	var specs []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		specs = append(specs, line)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read target file: %w", err)
	}
	if len(specs) == 0 {
		return nil, fmt.Errorf("target file %s names no targets", path)
	}
	return specs, nil
}
