package asset

import (
	"fmt"
	"sort"
	"time"
)

// Flow is an observed conversation between two assets. Flows only ever come
// from the passive path, since the active prober talks to devices one at a time
// and learns nothing about how they talk to each other.
type Flow struct {
	SrcAssetID string     `json:"src_asset_id"`
	DstAssetID string     `json:"dst_asset_id"`
	SrcAddr    string     `json:"src_addr"`
	DstAddr    string     `json:"dst_addr"`
	DstPort    int        `json:"dst_port"`
	Transport  string     `json:"transport"`
	Protocol   string     `json:"protocol,omitempty"`
	Packets    uint64     `json:"packets"`
	Bytes      uint64     `json:"bytes"`
	FirstSeen  time.Time  `json:"first_seen,omitzero"`
	LastSeen   time.Time  `json:"last_seen,omitzero"`
	Source     SourceKind `json:"source,omitempty"`
}

// Key identifies a flow direction and destination service.
func (f Flow) Key() string {
	return fmt.Sprintf("%s|%s|%d|%s", f.SrcAddr, f.DstAddr, f.DstPort, f.Transport)
}

// ViolationSeverity grades how badly a flow departs from the segmentation the
// Purdue model prescribes.
type ViolationSeverity string

const (
	ViolationNone     ViolationSeverity = ""
	ViolationInfo     ViolationSeverity = "info"
	ViolationMedium   ViolationSeverity = "medium"
	ViolationHigh     ViolationSeverity = "high"
	ViolationCritical ViolationSeverity = "critical"
)

// Rank orders severities for sorting.
func (v ViolationSeverity) Rank() int {
	switch v {
	case ViolationCritical:
		return 4
	case ViolationHigh:
		return 3
	case ViolationMedium:
		return 2
	case ViolationInfo:
		return 1
	default:
		return 0
	}
}

// SegmentationIssue reports a flow that crosses Purdue levels in a way the
// reference architecture does not sanction. This is the analysis behind the
// markers on the topology view.
type SegmentationIssue struct {
	FlowKey   string            `json:"flow_key"`
	SrcAsset  string            `json:"src_asset_id"`
	DstAsset  string            `json:"dst_asset_id"`
	SrcAddr   string            `json:"src_addr"`
	DstAddr   string            `json:"dst_addr"`
	SrcLevel  PurdueLevel       `json:"src_level"`
	DstLevel  PurdueLevel       `json:"dst_level"`
	Protocol  string            `json:"protocol,omitempty"`
	DstPort   int               `json:"dst_port"`
	Severity  ViolationSeverity `json:"severity"`
	Rationale string            `json:"rationale"`
}

// controlLevels are the levels where disturbing traffic can affect a physical
// process, which is why reaching them from outside is graded hardest.
func isControlLevel(p PurdueLevel) bool {
	return p == PurdueL0 || p == PurdueL1
}

func isEnterpriseLevel(p PurdueLevel) bool {
	return p == PurdueL4 || p == PurdueL5
}

// AnalyzeSegmentation grades every flow between assets whose levels are known.
// Flows involving an unplaced asset are skipped rather than guessed at, because
// a false segmentation alarm costs an operator real time.
func AnalyzeSegmentation(assets []Asset, flows []Flow) []SegmentationIssue {
	levels := make(map[string]PurdueLevel, len(assets))
	for _, a := range assets {
		levels[a.ID] = a.Purdue
	}

	issues := make([]SegmentationIssue, 0)
	for _, f := range flows {
		srcLevel, srcOK := levels[f.SrcAssetID]
		dstLevel, dstOK := levels[f.DstAssetID]
		if !srcOK || !dstOK || !srcLevel.Known() || !dstLevel.Known() {
			continue
		}
		severity, rationale := gradeFlow(srcLevel, dstLevel, f)
		if severity == ViolationNone {
			continue
		}
		issues = append(issues, SegmentationIssue{
			FlowKey:   f.Key(),
			SrcAsset:  f.SrcAssetID,
			DstAsset:  f.DstAssetID,
			SrcAddr:   f.SrcAddr,
			DstAddr:   f.DstAddr,
			SrcLevel:  srcLevel,
			DstLevel:  dstLevel,
			Protocol:  f.Protocol,
			DstPort:   f.DstPort,
			Severity:  severity,
			Rationale: rationale,
		})
	}

	sort.SliceStable(issues, func(i, j int) bool {
		if issues[i].Severity.Rank() != issues[j].Severity.Rank() {
			return issues[i].Severity.Rank() > issues[j].Severity.Rank()
		}
		return issues[i].FlowKey < issues[j].FlowKey
	})
	return issues
}

func gradeFlow(src, dst PurdueLevel, f Flow) (ViolationSeverity, string) {
	srcRank, dstRank := src.Rank(), dst.Rank()
	if srcRank == dstRank {
		return ViolationNone, ""
	}

	// Order the pair so the rules below read in one direction only.
	lower, upper := src, dst
	if srcRank > dstRank {
		lower, upper = dst, src
	}

	isICS := ProtocolForPort(f.DstPort) != "" && isControlLevel(dst)

	switch {
	case isEnterpriseLevel(upper) && isControlLevel(lower):
		reason := fmt.Sprintf("enterprise level %s reaches control level %s without passing the industrial DMZ", upper, lower)
		if isICS {
			reason += fmt.Sprintf(", carrying control protocol traffic on port %d", f.DstPort)
			return ViolationCritical, reason
		}
		return ViolationCritical, reason

	case isEnterpriseLevel(upper) && lower == PurdueL2:
		return ViolationHigh, fmt.Sprintf("enterprise level %s reaches supervisory level %s directly", upper, lower)

	case upper == PurdueL3 && isControlLevel(lower) && isICS:
		return ViolationInfo, fmt.Sprintf("site operations %s reaches control level %s on port %d, expected for engineering access but worth confirming", upper, lower, f.DstPort)

	case isEnterpriseLevel(upper) && lower == PurdueL3:
		return ViolationMedium, fmt.Sprintf("enterprise level %s reaches site operations %s without a DMZ hop", upper, lower)

	default:
		return ViolationNone, ""
	}
}

// MergeFlows folds duplicate flow records together, summing counters.
func MergeFlows(flows []Flow) []Flow {
	byKey := make(map[string]*Flow, len(flows))
	order := make([]string, 0, len(flows))
	for idx := range flows {
		f := flows[idx]
		key := f.Key()
		existing, ok := byKey[key]
		if !ok {
			copied := f
			byKey[key] = &copied
			order = append(order, key)
			continue
		}
		existing.Packets += f.Packets
		existing.Bytes += f.Bytes
		mergeString(&existing.Protocol, f.Protocol)
		if existing.FirstSeen.IsZero() || (!f.FirstSeen.IsZero() && f.FirstSeen.Before(existing.FirstSeen)) {
			existing.FirstSeen = f.FirstSeen
		}
		if f.LastSeen.After(existing.LastSeen) {
			existing.LastSeen = f.LastSeen
		}
	}
	out := make([]Flow, 0, len(order))
	for _, key := range order {
		out = append(out, *byKey[key])
	}
	return out
}
