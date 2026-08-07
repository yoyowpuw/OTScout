package asset

import "strconv"

// PurdueLevel places an asset in the Purdue reference architecture. The DMZ is
// conventionally written as level 3.5, which is why this is a string type with
// an explicit rank rather than a plain integer.
type PurdueLevel string

const (
	PurdueUnknown PurdueLevel = ""
	PurdueL0      PurdueLevel = "L0"
	PurdueL1      PurdueLevel = "L1"
	PurdueL2      PurdueLevel = "L2"
	PurdueL3      PurdueLevel = "L3"
	PurdueDMZ     PurdueLevel = "L3.5"
	PurdueL4      PurdueLevel = "L4"
	PurdueL5      PurdueLevel = "L5"
)

// PurdueOrder lists the levels from the process outward, which is the order the
// topology view lays its swimlanes out in.
var PurdueOrder = []PurdueLevel{
	PurdueL0, PurdueL1, PurdueL2, PurdueL3, PurdueDMZ, PurdueL4, PurdueL5,
}

var purdueRank = map[PurdueLevel]int{
	PurdueL0:  0,
	PurdueL1:  10,
	PurdueL2:  20,
	PurdueL3:  30,
	PurdueDMZ: 35,
	PurdueL4:  40,
	PurdueL5:  50,
}

// Rank returns a sortable position for the level. Unknown sorts last so it does
// not masquerade as a real placement.
func (p PurdueLevel) Rank() int {
	if rank, ok := purdueRank[p]; ok {
		return rank
	}
	return 999
}

// Known reports whether the level was actually determined.
func (p PurdueLevel) Known() bool {
	_, ok := purdueRank[p]
	return ok
}

// Description gives the plain language meaning of the level for tooltips.
func (p PurdueLevel) Description() string {
	switch p {
	case PurdueL0:
		return "Process: sensors and actuators"
	case PurdueL1:
		return "Basic control: PLC, RTU, IED"
	case PurdueL2:
		return "Area supervisory: HMI and local SCADA"
	case PurdueL3:
		return "Site operations: historian, engineering workstation"
	case PurdueDMZ:
		return "Industrial DMZ: brokers and jump hosts"
	case PurdueL4:
		return "Enterprise network"
	case PurdueL5:
		return "Internet and external services"
	default:
		return "Unplaced"
	}
}

// Role is the functional job an asset performs. It drives both the icon in the
// topology view and the default Purdue placement.
type Role string

const (
	RoleUnknown    Role = ""
	RolePLC        Role = "plc"
	RoleRTU        Role = "rtu"
	RoleIED        Role = "ied"
	RoleHMI        Role = "hmi"
	RoleHistorian  Role = "historian"
	RoleEWS        Role = "engineering-workstation"
	RoleOPCServer  Role = "opc-server"
	RoleBuildingAC Role = "building-controller"
	RoleNetwork    Role = "network-device"
	RoleServer     Role = "server"
	RoleWorkstatn  Role = "workstation"
)

// DefaultPurdue gives the level a role normally sits at. Inference falls back
// to this when nothing stronger is available.
func (r Role) DefaultPurdue() PurdueLevel {
	switch r {
	case RolePLC, RoleRTU, RoleIED:
		return PurdueL1
	case RoleHMI, RoleBuildingAC:
		return PurdueL2
	case RoleHistorian, RoleEWS, RoleOPCServer:
		return PurdueL3
	case RoleNetwork:
		return PurdueL2
	case RoleServer, RoleWorkstatn:
		return PurdueL4
	default:
		return PurdueUnknown
	}
}

// portSignature maps a well known port to the role it implies and how strongly
// it implies it. Industrial control ports score highest because a device
// answering on port 502 is almost never anything but a controller, whereas a
// device answering on 443 could be nearly anything.
type portSignature struct {
	role     Role
	protocol string
	weight   int
}

var portSignatures = map[int]portSignature{
	502:   {RolePLC, "modbus", 90},
	20000: {RoleRTU, "dnp3", 90},
	2404:  {RoleIED, "iec104", 90},
	44818: {RolePLC, "enip", 90},
	9600:  {RolePLC, "fins", 85},
	5007:  {RolePLC, "melsec", 85},
	1962:  {RolePLC, "pcworx", 80},
	20547: {RolePLC, "proconos", 80},
	789:   {RolePLC, "crimson", 75},
	47808: {RoleBuildingAC, "bacnet", 80},
	4840:  {RoleOPCServer, "opcua", 60},
	102:   {RolePLC, "s7comm", 85},
	2222:  {RolePLC, "enip-io", 70},
	18245: {RolePLC, "ge-srtp", 75},
	1911:  {RoleBuildingAC, "niagara-fox", 70},
	5450:  {RoleHistorian, "osisoft-pi", 70},
	8086:  {RoleHistorian, "influxdb", 45},
	1433:  {RoleHistorian, "mssql", 35},
	3389:  {RoleEWS, "rdp", 30},
	5900:  {RoleHMI, "vnc", 35},
	161:   {RoleNetwork, "snmp", 25},
	23:    {RoleNetwork, "telnet", 15},
	80:    {RoleServer, "http", 10},
	443:   {RoleServer, "https", 10},
	445:   {RoleWorkstatn, "smb", 15},
}

// ProtocolForPort returns the conventional protocol name for a port, or an
// empty string when the port is not one we recognise.
func ProtocolForPort(port int) string {
	if sig, ok := portSignatures[port]; ok {
		return sig.protocol
	}
	return ""
}

// Inference is the outcome of classifying an asset, including why the
// classification was reached. The reason is surfaced in the UI so an operator
// can disagree with it on an informed basis.
type Inference struct {
	Role   Role
	Purdue PurdueLevel
	Reason string
}

// Classify infers role and Purdue level from the observed services. It never
// overwrites a value that is already set, because an explicit statement from a
// probe template or an operator always outranks a heuristic.
func Classify(a *Asset) Inference {
	best := portSignature{weight: -1}
	bestPort := 0
	for _, svc := range a.Services {
		sig, ok := portSignatures[svc.Port]
		if !ok {
			continue
		}
		// A port number is a convention, and what was actually seen on it is
		// evidence. Where they disagree the evidence wins: a web server on 502
		// is a web server, and filing it as a PLC would put a device in the
		// inventory at a Purdue level it has no business at, then hand it to
		// the matcher as a controller.
		if svc.Protocol != "" && svc.Protocol != sig.protocol {
			continue
		}
		if sig.weight > best.weight {
			best = sig
			bestPort = svc.Port
		}
	}

	inf := Inference{Role: a.Role, Purdue: a.Purdue}
	if best.weight < 0 {
		if inf.Reason == "" {
			inf.Reason = "no recognised service port observed"
		}
		return inf
	}

	if inf.Role == RoleUnknown {
		inf.Role = best.role
	}
	if inf.Purdue == PurdueUnknown {
		inf.Purdue = inf.Role.DefaultPurdue()
	}
	inf.Reason = "port " + strconv.Itoa(bestPort) + " indicates " + best.protocol
	return inf
}

// Apply writes an inference onto the asset without clobbering existing values.
func (inf Inference) Apply(a *Asset) {
	if a.Role == RoleUnknown {
		a.Role = inf.Role
	}
	if a.Purdue == PurdueUnknown {
		a.Purdue = inf.Purdue
	}
}
