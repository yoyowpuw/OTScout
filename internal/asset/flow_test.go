package asset

import "testing"

func levelAsset(id string, level PurdueLevel) Asset {
	return Asset{ID: id, Addresses: Addresses{IPv4: id}, Purdue: level}
}

func TestAnalyzeSegmentationFlagsEnterpriseReachingControl(t *testing.T) {
	assets := []Asset{
		levelAsset("10.4.0.1", PurdueL4),
		levelAsset("10.1.0.1", PurdueL1),
	}
	flows := []Flow{{
		SrcAssetID: "10.4.0.1", DstAssetID: "10.1.0.1",
		SrcAddr: "10.4.0.1", DstAddr: "10.1.0.1",
		DstPort: 502, Transport: "tcp", Protocol: "modbus",
	}}

	issues := AnalyzeSegmentation(assets, flows)
	if len(issues) != 1 {
		t.Fatalf("expected one issue, got %d", len(issues))
	}
	if issues[0].Severity != ViolationCritical {
		t.Errorf("Severity = %q, want %q", issues[0].Severity, ViolationCritical)
	}
	if issues[0].Rationale == "" {
		t.Error("an issue must explain itself")
	}
}

func TestAnalyzeSegmentationIgnoresSameLevelTraffic(t *testing.T) {
	assets := []Asset{
		levelAsset("10.1.0.1", PurdueL1),
		levelAsset("10.1.0.2", PurdueL1),
	}
	flows := []Flow{{
		SrcAssetID: "10.1.0.1", DstAssetID: "10.1.0.2",
		SrcAddr: "10.1.0.1", DstAddr: "10.1.0.2",
		DstPort: 502, Transport: "tcp",
	}}
	if issues := AnalyzeSegmentation(assets, flows); len(issues) != 0 {
		t.Fatalf("traffic inside one level is normal, got %d issues", len(issues))
	}
}

func TestAnalyzeSegmentationSkipsUnplacedAssets(t *testing.T) {
	// Guessing at a level would produce false alarms, and a false segmentation
	// alarm costs an engineer real time. Unplaced assets must be skipped.
	assets := []Asset{
		levelAsset("10.4.0.1", PurdueL4),
		levelAsset("10.9.9.9", PurdueUnknown),
	}
	flows := []Flow{{
		SrcAssetID: "10.4.0.1", DstAssetID: "10.9.9.9",
		SrcAddr: "10.4.0.1", DstAddr: "10.9.9.9",
		DstPort: 502, Transport: "tcp",
	}}
	if issues := AnalyzeSegmentation(assets, flows); len(issues) != 0 {
		t.Fatalf("expected no issues when a level is unknown, got %d", len(issues))
	}
}

func TestAnalyzeSegmentationGradesEngineeringAccessAsInfo(t *testing.T) {
	// L3 to L1 on a control port is how engineers legitimately work. It should
	// be surfaced but must not be graded as an alarm.
	assets := []Asset{
		levelAsset("10.3.0.1", PurdueL3),
		levelAsset("10.1.0.1", PurdueL1),
	}
	flows := []Flow{{
		SrcAssetID: "10.3.0.1", DstAssetID: "10.1.0.1",
		SrcAddr: "10.3.0.1", DstAddr: "10.1.0.1",
		DstPort: 102, Transport: "tcp", Protocol: "s7comm",
	}}

	issues := AnalyzeSegmentation(assets, flows)
	if len(issues) != 1 {
		t.Fatalf("expected one informational issue, got %d", len(issues))
	}
	if issues[0].Severity != ViolationInfo {
		t.Errorf("Severity = %q, want %q", issues[0].Severity, ViolationInfo)
	}
}

func TestAnalyzeSegmentationSortsBySeverity(t *testing.T) {
	assets := []Asset{
		levelAsset("10.4.0.1", PurdueL4),
		levelAsset("10.3.0.1", PurdueL3),
		levelAsset("10.1.0.1", PurdueL1),
	}
	flows := []Flow{
		{SrcAssetID: "10.4.0.1", DstAssetID: "10.3.0.1", SrcAddr: "10.4.0.1", DstAddr: "10.3.0.1", DstPort: 1433, Transport: "tcp"},
		{SrcAssetID: "10.4.0.1", DstAssetID: "10.1.0.1", SrcAddr: "10.4.0.1", DstAddr: "10.1.0.1", DstPort: 502, Transport: "tcp"},
	}

	issues := AnalyzeSegmentation(assets, flows)
	if len(issues) != 2 {
		t.Fatalf("expected two issues, got %d", len(issues))
	}
	if issues[0].Severity != ViolationCritical {
		t.Errorf("the worst issue must sort first, got %q", issues[0].Severity)
	}
}

func TestMergeFlowsSumsCounters(t *testing.T) {
	flows := []Flow{
		{SrcAddr: "a", DstAddr: "b", DstPort: 502, Transport: "tcp", Packets: 3, Bytes: 300},
		{SrcAddr: "a", DstAddr: "b", DstPort: 502, Transport: "tcp", Packets: 2, Bytes: 200, Protocol: "modbus"},
		{SrcAddr: "a", DstAddr: "b", DstPort: 102, Transport: "tcp", Packets: 1, Bytes: 100},
	}
	merged := MergeFlows(flows)
	if len(merged) != 2 {
		t.Fatalf("expected two distinct flows, got %d", len(merged))
	}
	if merged[0].Packets != 5 || merged[0].Bytes != 500 {
		t.Errorf("counters did not sum: %+v", merged[0])
	}
	if merged[0].Protocol != "modbus" {
		t.Errorf("merge lost the protocol label: %q", merged[0].Protocol)
	}
}
