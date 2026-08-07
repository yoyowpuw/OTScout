package ingest

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"

	"github.com/yoyowpuw/OTScout/internal/asset"
	"github.com/yoyowpuw/OTScout/internal/protocol"
)

// maxTrackedFlows bounds the flow table. A capture is untrusted input and a busy
// one can hold millions of conversations, so the table is capped and the overflow
// reported rather than allowed to consume the machine.
const maxTrackedFlows = 250000

// packetSource is the part of the pcapgo readers this file needs. Both the pcap
// and the pcapng reader satisfy it, so the rest of the code is format agnostic.
type packetSource interface {
	ReadPacketData() ([]byte, gopacket.CaptureInfo, error)
	linkTypeFor(ci gopacket.CaptureInfo) layers.LinkType
}

type pcapSource struct{ r *pcapgo.Reader }

func (s pcapSource) ReadPacketData() ([]byte, gopacket.CaptureInfo, error) {
	return s.r.ReadPacketData()
}

func (s pcapSource) linkTypeFor(gopacket.CaptureInfo) layers.LinkType { return s.r.LinkType() }

type ngSource struct{ r *pcapgo.NgReader }

func (s ngSource) ReadPacketData() ([]byte, gopacket.CaptureInfo, error) {
	return s.r.ReadPacketData()
}

// linkTypeFor reads the per packet link type a mixed pcapng exposes as ancillary
// data, so a file recorded from both an Ethernet tap and a serial line decodes
// correctly rather than being read with the wrong link layer.
func (s ngSource) linkTypeFor(ci gopacket.CaptureInfo) layers.LinkType {
	for _, extra := range ci.AncillaryData {
		if lt, ok := extra.(layers.LinkType); ok {
			return lt
		}
	}
	return s.r.LinkType()
}

// openCapture detects the file format and returns a reader for it.
//
// gzip is unwrapped here rather than relying on the pcap reader's own support,
// because the pcapng reader has none and captures arrive compressed either way.
func openCapture(file *os.File) (packetSource, error) {
	buffered := bufio.NewReaderSize(file, 1<<16)

	var reader io.Reader = buffered
	if magic, err := buffered.Peek(2); err == nil && magic[0] == 0x1f && magic[1] == 0x8b {
		gz, err := gzip.NewReader(buffered)
		if err != nil {
			return nil, fmt.Errorf("open gzip capture: %w", err)
		}
		reader = bufio.NewReaderSize(gz, 1<<16)
	}

	peeker, ok := reader.(*bufio.Reader)
	if !ok {
		peeker = bufio.NewReaderSize(reader, 1<<16)
		reader = peeker
	}
	magic, err := peeker.Peek(4)
	if err != nil {
		return nil, fmt.Errorf("read capture header: %w", err)
	}

	// A pcapng file starts with a section header block, whose type is chosen so
	// that it reads the same in either byte order.
	if magic[0] == 0x0a && magic[1] == 0x0d && magic[2] == 0x0d && magic[3] == 0x0a {
		ng, err := pcapgo.NewNgReader(reader, pcapgo.NgReaderOptions{
			WantMixedLinkType:  true,
			SkipUnknownVersion: true,
		})
		if err != nil {
			return nil, fmt.Errorf("open pcapng: %w", err)
		}
		return ngSource{r: ng}, nil
	}

	plain, err := pcapgo.NewReader(reader)
	if err != nil {
		return nil, fmt.Errorf("open pcap: %w", err)
	}
	return pcapSource{r: plain}, nil
}

// readPcapFile reads a capture in two passes.
//
// The first pass only learns which hardware address goes with which IP address.
// Doing that up front is what keeps every host behind a router from collapsing
// into one asset: the router's hardware address appears as the source for all of
// them, so a hardware address is only attached to an asset once the whole file
// shows it belongs to exactly one IP.
func readPcapFile(ctx context.Context, path string, s *sink, opts Options) error {
	bindings, err := scanBindings(ctx, path, s, opts)
	if err != nil {
		return err
	}

	pass := &capturePass{
		sink:       s,
		opts:       opts,
		source:     path,
		bindings:   bindings,
		flows:      make(map[string]*asset.Flow),
		buffers:    make(map[string][]byte),
		identified: make(map[string]map[string]bool),
		openPorts:  make(map[string]time.Time),
	}
	if err := walkCapture(ctx, path, s, opts, pass.handle); err != nil {
		return err
	}
	pass.flush()
	return nil
}

// walkCapture opens a capture and calls visit for every packet.
func walkCapture(ctx context.Context, path string, s *sink, opts Options, visit func(gopacket.Packet, gopacket.CaptureInfo)) error {
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open capture: %w", err)
	}
	defer file.Close()

	src, err := openCapture(file)
	if err != nil {
		return err
	}

	count := 0
	for {
		// Checking the context on every packet would dominate the loop, and a
		// capture is read fast enough that a check every few thousand packets
		// still cancels promptly.
		if count%4096 == 0 {
			if err := ctx.Err(); err != nil {
				return err
			}
		}
		data, ci, err := src.ReadPacketData()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			// A capture stopped mid-packet is ordinary, so what was read is kept
			// and the shortfall reported.
			s.stats.warn("capture %s ended after %d packets: %v", path, count, err)
			return nil
		}
		count++
		if opts.MaxPacketsPerFile > 0 && count > opts.MaxPacketsPerFile {
			s.stats.warn("capture %s: stopped at the %d packet limit", path, opts.MaxPacketsPerFile)
			return nil
		}

		// NoCopy is safe because ReadPacketData already returns a fresh slice.
		// Anything retained past this call is copied explicitly.
		pkt := gopacket.NewPacket(data, src.linkTypeFor(ci), gopacket.DecodeOptions{Lazy: true, NoCopy: true})
		visit(pkt, ci)
	}
}

// addressBindings records which hardware address belongs to which IP.
type addressBindings struct {
	macToIP map[string]string
	ipToMAC map[string]string
}

func (b *addressBindings) macFor(ip string) string {
	if b == nil {
		return ""
	}
	return b.ipToMAC[ip]
}

func (b *addressBindings) ipFor(mac string) string {
	if b == nil {
		return ""
	}
	return b.macToIP[mac]
}

// scanBindings runs the learning pass described on readPcapFile.
func scanBindings(ctx context.Context, path string, s *sink, opts Options) (*addressBindings, error) {
	// arp holds bindings the devices themselves announced, which is the reliable
	// source. observed holds what could merely be inferred from forwarded frames.
	arp := make(map[string]map[string]struct{})
	observed := make(map[string]map[string]struct{})

	err := walkCapture(ctx, path, s, opts, func(pkt gopacket.Packet, _ gopacket.CaptureInfo) {
		if layer := pkt.Layer(layers.LayerTypeARP); layer != nil {
			a, _ := layer.(*layers.ARP)
			mac := formatMAC(a.SourceHwAddress)
			ip := formatIP(a.SourceProtAddress)
			record(arp, mac, ip)
			return
		}
		eth, _ := pkt.Layer(layers.LayerTypeEthernet).(*layers.Ethernet)
		if eth == nil {
			return
		}
		srcMAC := formatMAC(eth.SrcMAC)
		if !usableMAC(srcMAC) {
			return
		}
		if ip4, _ := pkt.Layer(layers.LayerTypeIPv4).(*layers.IPv4); ip4 != nil {
			record(observed, srcMAC, ip4.SrcIP.String())
			return
		}
		if ip6, _ := pkt.Layer(layers.LayerTypeIPv6).(*layers.IPv6); ip6 != nil {
			record(observed, srcMAC, ip6.SrcIP.String())
		}
	})
	if err != nil {
		return nil, err
	}

	bindings := &addressBindings{
		macToIP: make(map[string]string),
		ipToMAC: make(map[string]string),
	}
	// A hardware address seen with more than one IP is a router, a proxy ARP
	// responder or a teamed interface. In every one of those cases attaching it
	// to an asset would merge devices that are not the same device, so it is
	// dropped instead.
	for _, table := range []map[string]map[string]struct{}{arp, observed} {
		for mac, ips := range table {
			if len(ips) != 1 || !usableMAC(mac) {
				continue
			}
			for ip := range ips {
				if !usableIP(ip) {
					continue
				}
				if _, taken := bindings.macToIP[mac]; taken {
					continue
				}
				bindings.macToIP[mac] = ip
				if _, taken := bindings.ipToMAC[ip]; !taken {
					bindings.ipToMAC[ip] = mac
				}
			}
		}
	}
	return bindings, nil
}

func record(table map[string]map[string]struct{}, mac, ip string) {
	if mac == "" || ip == "" {
		return
	}
	set, ok := table[mac]
	if !ok {
		set = make(map[string]struct{}, 1)
		table[mac] = set
	}
	set[ip] = struct{}{}
}

// capturePass holds the state of the second pass over a capture.
type capturePass struct {
	sink     *sink
	opts     Options
	source   string
	bindings *addressBindings

	flows   map[string]*asset.Flow
	flowCap bool

	// buffers holds partial payloads for conversations whose response has not
	// arrived complete yet, keyed by service.
	buffers map[string][]byte
	// identified records, per service, the field names already written to the
	// asset, so that a long conversation contributes each thing it has to say
	// once rather than once per packet.
	identified map[string]map[string]bool
	// openPorts records services proven to be listening, along with when.
	openPorts map[string]time.Time
	services  []observedService
}

type observedService struct {
	addr      string
	port      int
	transport string
	protocol  string
	banner    string
	seen      time.Time
}

func (p *capturePass) handle(pkt gopacket.Packet, ci gopacket.CaptureInfo) {
	p.sink.stats.PacketsRead++
	ts := ci.Timestamp.UTC()

	if layer := pkt.Layer(layers.LayerTypeARP); layer != nil {
		p.handleARP(layer.(*layers.ARP), ts)
		return
	}
	if info, _ := pkt.Layer(layers.LayerTypeLinkLayerDiscoveryInfo).(*layers.LinkLayerDiscoveryInfo); info != nil {
		p.handleLLDP(pkt, info, ts)
		return
	}

	srcIP, dstIP := packetAddresses(pkt)
	if srcIP == "" || dstIP == "" {
		return
	}

	var (
		transport string
		srcPort   int
		dstPort   int
		payload   []byte
		syn       bool
		synAck    bool
	)
	switch {
	case pkt.Layer(layers.LayerTypeTCP) != nil:
		tcp, _ := pkt.Layer(layers.LayerTypeTCP).(*layers.TCP)
		transport, srcPort, dstPort = "tcp", int(tcp.SrcPort), int(tcp.DstPort)
		payload = tcp.Payload
		syn = tcp.SYN && !tcp.ACK
		synAck = tcp.SYN && tcp.ACK
	case pkt.Layer(layers.LayerTypeUDP) != nil:
		udp, _ := pkt.Layer(layers.LayerTypeUDP).(*layers.UDP)
		transport, srcPort, dstPort = "udp", int(udp.SrcPort), int(udp.DstPort)
		payload = udp.Payload
	default:
		return
	}

	// Deciding which end is the listener is what makes the flow list and the
	// service list mean something. A SYN without an ACK settles it outright; the
	// rest is a port based judgement.
	serverIsDst := dstIsServer(srcPort, dstPort)
	switch {
	case syn:
		serverIsDst = true
	case synAck:
		serverIsDst = false
	}

	// Several UDP protocols have every device listening on the same port, so a
	// BACnet datagram from 47808 to 47808 has no client and server to tell apart.
	// Both ends are listeners in that case, and the sender's payload is as much a
	// response as anything else on the wire.
	symmetric := transport == "udp" && srcPort == dstPort && asset.ProtocolForPort(srcPort) != ""

	clientAddr, serverAddr := srcIP, dstIP
	serverPort := dstPort
	if !serverIsDst {
		clientAddr, serverAddr = dstIP, srcIP
		serverPort = srcPort
	}

	if usableIP(clientAddr) && usableIP(serverAddr) {
		p.addFlow(clientAddr, serverAddr, serverPort, transport, ts, uint64(ci.Length))
	}

	// A service is only recorded once the listening side has actually answered.
	// Recording one for a connection that was refused would put ports in the
	// inventory that are not open.
	if usableIP(serverAddr) && (synAck || (!serverIsDst && (len(payload) > 0 || transport == "udp"))) {
		p.markOpen(serverAddr, serverPort, transport, ts)
	}

	if len(payload) == 0 {
		return
	}
	// Only traffic that came from a listener is handed to the decoders. A request
	// travelling the other way would be decoded as though the client were the
	// device, which puts a PLC identity on the workstation that asked for it.
	responder, responderPort := serverAddr, serverPort
	if symmetric {
		responder, responderPort = srcIP, srcPort
		if usableIP(responder) {
			p.markOpen(responder, responderPort, transport, ts)
		}
	} else if serverIsDst {
		return
	}
	if !usableIP(responder) {
		return
	}
	p.tryDecode(responder, responderPort, transport, payload, ts)
	p.tryHTTPBanner(responder, responderPort, transport, payload, ts)
}

func (p *capturePass) handleARP(a *layers.ARP, ts time.Time) {
	mac := formatMAC(a.SourceHwAddress)
	ip := formatIP(a.SourceProtAddress)
	if !usableMAC(mac) || !usableIP(ip) {
		return
	}
	// The learning pass may have found this hardware address on several IPs, in
	// which case it belongs to a router rather than to this device.
	if p.bindings.macFor(ip) != mac {
		return
	}
	device := p.sink.device(asset.Addresses{IPv4: ip, MAC: mac})
	device.touchSeen(ts)
	device.setField("arp_announced_ip", ip)
	device.addEvidence(asset.Evidence{
		Source:    asset.SourcePcap,
		Protocol:  "arp",
		Endpoint:  ip,
		Timestamp: ts,
		Fields:    device.pendingFields(),
		Notes:     []string{"address binding taken from an ARP frame already present in the capture"},
	})
}

// handleLLDP reads the neighbour discovery frames switches and many industrial
// devices emit. They are worth reading because a device that answers no control
// protocol at all still announces its model and firmware here.
func (p *capturePass) handleLLDP(pkt gopacket.Packet, info *layers.LinkLayerDiscoveryInfo, ts time.Time) {
	eth, _ := pkt.Layer(layers.LayerTypeEthernet).(*layers.Ethernet)
	if eth == nil {
		return
	}
	mac := formatMAC(eth.SrcMAC)
	if !usableMAC(mac) {
		return
	}

	addr := asset.Addresses{MAC: mac, IPv4: p.bindings.ipFor(mac)}
	if info.SysName != "" {
		addr.Hostname = info.SysName
	}
	device := p.sink.device(addr)
	device.touchSeen(ts)
	device.setField("lldp_system_name", info.SysName)
	device.setField("lldp_system_description", collapseWhitespace(info.SysDescription))
	device.setField("lldp_port_description", info.PortDescription)

	// The system description is free text, so nothing is read out of it by
	// position. Only a vendor name the alias table knows and an order code a
	// parser recognises are taken, which is what keeps a description full of
	// marketing words from producing an invented identity.
	vendor, catalog := p.sink.sniffText(info.SysDescription)
	if vendor != "" {
		device.setVendor(vendor)
		device.addNote(fmt.Sprintf("vendor %s named in the LLDP system description", vendor))
	}
	if catalog != "" {
		device.setCatalogNumber(catalog)
		device.addNote(fmt.Sprintf("order code %s recognised in the LLDP system description", catalog))
	}
	if info.SysCapabilities.EnabledCap.Bridge || info.SysCapabilities.EnabledCap.Router {
		device.setRole(asset.RoleNetwork)
	}

	device.addEvidence(asset.Evidence{
		Source:    asset.SourcePcap,
		Protocol:  "lldp",
		Endpoint:  mac,
		Timestamp: ts,
		Fields:    device.pendingFields(),
		Notes:     append(device.pendingNotes(), "device announced itself over LLDP, nothing was sent to it"),
	})
}

func (p *capturePass) addFlow(src, dst string, dstPort int, transport string, ts time.Time, byteCount uint64) {
	flow := asset.Flow{
		SrcAddr:   src,
		DstAddr:   dst,
		DstPort:   dstPort,
		Transport: transport,
		Protocol:  asset.ProtocolForPort(dstPort),
		Source:    asset.SourcePcap,
	}
	key := flow.Key()
	existing, ok := p.flows[key]
	if !ok {
		if len(p.flows) >= maxTrackedFlows {
			if !p.flowCap {
				p.sink.stats.warn("capture %s: flow table reached %d entries, later conversations were not recorded",
					p.source, maxTrackedFlows)
				p.flowCap = true
			}
			return
		}
		flow.FirstSeen, flow.LastSeen = ts, ts
		flow.Packets, flow.Bytes = 1, byteCount
		copied := flow
		p.flows[key] = &copied
		return
	}
	existing.Packets++
	existing.Bytes += byteCount
	if !ts.IsZero() && (existing.FirstSeen.IsZero() || ts.Before(existing.FirstSeen)) {
		existing.FirstSeen = ts
	}
	if ts.After(existing.LastSeen) {
		existing.LastSeen = ts
	}
}

// addressesFor builds the address set for an IP, attaching the hardware address
// only when the learning pass proved it belongs to this one device.
func (p *capturePass) addressesFor(ip string) asset.Addresses {
	addr := addressesFor(ip)
	addr.MAC = p.bindings.macFor(ip)
	return addr
}

func (p *capturePass) markOpen(addr string, port int, transport string, ts time.Time) {
	key := serviceKey(addr, port, transport)
	if first, ok := p.openPorts[key]; ok {
		if ts.After(first) {
			return
		}
	}
	p.openPorts[key] = ts
}

func serviceKey(addr string, port int, transport string) string {
	return addr + "|" + strconv.Itoa(port) + "|" + transport
}

// tryDecode hands a server response to the decoders that suit its port.
//
// A registered port narrows the field to one decoder, which is what keeps this
// cheap and unambiguous for the ordinary case. A port nothing is registered for
// falls back to trying all of them, because industrial services turn up on
// arbitrary ports constantly: gateways remap them, honeypots bind high ports to
// avoid needing root, and vendors ship products listening wherever they please.
// Skipping those would leave exactly the odd corners of a plant uninventoried.
//
// The fallback is safe to the extent the decoders are strict, and each one
// rejects a payload that does not carry its own framing in the first few bytes.
// It is still a weaker claim than a decode on the registered port, so the
// evidence records which of the two happened.
func (p *capturePass) tryDecode(serverAddr string, port int, transport string, payload []byte, ts time.Time) {
	key := serviceKey(serverAddr, port, transport)

	decoders := protocol.PassiveDecoders(port)
	byContent := len(decoders) == 0
	if byContent {
		decoders = protocol.AllDecoders()
	}

	data := payload
	if buffered := p.buffers[key]; len(buffered) > 0 {
		data = make([]byte, 0, len(buffered)+len(payload))
		data = append(data, buffered...)
		data = append(data, payload...)
	}
	if len(data) > maxDecodeAttemptBytes {
		data = data[:maxDecodeAttemptBytes]
	}
	p.sink.stats.PayloadsTried++

	truncated := false
	for _, decode := range decoders {
		obs, err := decode(data)
		var deviceErr *protocol.ErrDeviceError
		switch {
		case err == nil || errors.As(err, &deviceErr):
			if obs.Empty() {
				continue
			}
			// A conversation is not one answer. A BACnet controller
			// announces itself and only names its model when asked, and a
			// Siemens CPU splits its identity across separate SZL reads, so
			// stopping at the first decode would keep the weakest of them.
			// Repetition is the thing to avoid, not further information, and
			// what tells the two apart is whether anything new was said.
			if !p.recordsSomethingNew(key, obs) {
				return
			}
			p.recordObservation(key, serverAddr, port, transport, obs, data, ts, err, byContent)
			return
		case errors.Is(err, protocol.ErrTruncated):
			truncated = true
		}
	}

	// A response split across segments is normal, so the bytes are held and
	// retried when more arrive. Everything else is discarded straight away.
	if truncated && len(data) < p.opts.MaxFlowBufferBytes {
		p.buffers[key] = append([]byte(nil), data...)
		return
	}
	delete(p.buffers, key)
}

// recordsSomethingNew reports whether an observation says anything this service
// has not already said, and remembers it if so.
//
// The test is on field names rather than values, which is what makes it safe to
// keep decoding a long conversation. A poll answered a thousand times reports the
// same three field names with a different transaction id each time, and treating
// those as new would put a thousand evidence entries on one asset.
func (p *capturePass) recordsSomethingNew(key string, obs protocol.Observation) bool {
	known, seen := p.identified[key]
	if !seen {
		known = make(map[string]bool, len(obs.Fields)+1)
		p.identified[key] = known
	}

	novel := false
	for field := range obs.Fields {
		if !known[field] {
			known[field] = true
			novel = true
		}
	}
	// An identity is worth recording even when it arrives under field names
	// already seen, but only the first time.
	if !obs.Identity.Empty() && !known[identityContribution] {
		known[identityContribution] = true
		novel = true
	}
	return novel || !seen
}

// identityContribution is a sentinel key in the per service set above. It cannot
// collide with a protocol field name because no decoder emits a name with a
// space in it.
const identityContribution = "identity was recorded"

func (p *capturePass) recordObservation(key, serverAddr string, port int, transport string, obs protocol.Observation, data []byte, ts time.Time, decodeErr error, byContent bool) {
	delete(p.buffers, key)
	p.markOpen(serverAddr, port, transport, ts)

	device := p.sink.device(p.addressesFor(serverAddr))
	device.touchSeen(ts)
	device.mergeIdentity(obs.Identity)
	device.setRole(obs.Role)
	for field, value := range obs.Fields {
		device.setField(field, value)
	}

	notes := append([]string(nil), obs.Notes...)
	if decodeErr != nil {
		notes = append(notes, "device answered with a protocol level error, which still proves it speaks "+obs.Protocol)
	}
	if byContent {
		notes = append(notes, fmt.Sprintf(
			"port %d is not the registered port for %s, so the protocol was identified from the shape of the response",
			port, obs.Protocol))
	}
	notes = append(notes, "decoded from a response found in "+p.source+", otscout sent nothing")

	device.addEvidence(asset.Evidence{
		Source:    asset.SourcePcap,
		Protocol:  obs.Protocol,
		Endpoint:  fmt.Sprintf("%s:%d", serverAddr, port),
		Timestamp: ts,
		// Request stays nil. That is how the evidence view proves no packet was
		// sent, so it must never be filled in on this path.
		Response: append(asset.HexBytes(nil), data...),
		Fields:   device.pendingFields(),
		Notes:    append(notes, device.pendingNotes()...),
	})

	p.services = append(p.services, observedService{
		addr:      serverAddr,
		port:      port,
		transport: transport,
		protocol:  obs.Protocol,
		seen:      ts,
	})
}

// tryHTTPBanner records the Server header of a plain HTTP response. Many OT
// devices run a small web server whose header names the product, and it costs one
// string scan to collect. Only the banner is taken: a header is too easily wrong to
// drive an identity from.
func (p *capturePass) tryHTTPBanner(serverAddr string, port int, transport string, payload []byte, ts time.Time) {
	if !bytes.HasPrefix(payload, []byte("HTTP/1.")) {
		return
	}
	limit := payload
	if len(limit) > 4096 {
		limit = limit[:4096]
	}
	server := ""
	for _, line := range strings.Split(string(limit), "\r\n") {
		if line == "" {
			break
		}
		if name, value, found := strings.Cut(line, ":"); found && strings.EqualFold(strings.TrimSpace(name), "server") {
			server = collapseWhitespace(value)
			break
		}
	}
	if server == "" {
		return
	}
	p.services = append(p.services, observedService{
		addr:      serverAddr,
		port:      port,
		transport: transport,
		protocol:  "http",
		banner:    server,
		seen:      ts,
	})
	p.markOpen(serverAddr, port, transport, ts)
}

// flush writes the flows and services gathered during the pass into the sink.
func (p *capturePass) flush() {
	// Both ends of every conversation become assets, even when nothing else was
	// learned about them. The topology and segmentation views compare the Purdue
	// level of each end, so a flow with only one end in the inventory cannot be
	// graded at all.
	for _, key := range sortedKeys(p.flows) {
		flow := p.flows[key]
		for _, addr := range []string{flow.SrcAddr, flow.DstAddr} {
			p.sink.device(p.addressesFor(addr)).touchSeen(flow.FirstSeen)
		}
	}

	banners := make(map[string]observedService, len(p.services))
	for _, svc := range p.services {
		key := serviceKey(svc.addr, svc.port, svc.transport)
		existing, ok := banners[key]
		if !ok {
			banners[key] = svc
			continue
		}
		if existing.protocol == "" {
			existing.protocol = svc.protocol
		}
		if existing.banner == "" {
			existing.banner = svc.banner
		}
		banners[key] = existing
	}

	for key, first := range p.openPorts {
		addr, port, transport, ok := parseServiceKey(key)
		if !ok {
			continue
		}
		device := p.sink.device(p.addressesFor(addr))
		device.touchSeen(first)

		svc := asset.Service{
			Port:      port,
			Transport: transport,
			Protocol:  asset.ProtocolForPort(port),
			FirstSeen: first,
			LastSeen:  first,
			Source:    asset.SourcePcap,
		}
		if extra, ok := banners[key]; ok {
			if extra.protocol != "" {
				svc.Protocol = extra.protocol
			}
			svc.Banner = extra.banner
			if extra.seen.After(svc.LastSeen) {
				svc.LastSeen = extra.seen
			}
		}
		device.addService(svc)
	}

	for _, key := range sortedKeys(p.flows) {
		p.sink.addFlow(*p.flows[key])
	}
	p.sink.stats.RecordsRead["pcap.flows"] += len(p.flows)
	p.sink.stats.RecordsRead["pcap.services"] += len(p.openPorts)
}

func parseServiceKey(key string) (string, int, string, bool) {
	parts := strings.Split(key, "|")
	if len(parts) != 3 {
		return "", 0, "", false
	}
	port, ok := parsePort(parts[1])
	if !ok {
		return "", 0, "", false
	}
	return parts[0], port, parts[2], true
}

// dstIsServer guesses which end of a conversation is the listener when no TCP
// handshake is present in the capture, which is the usual case for a capture that
// started after the connection did.
func dstIsServer(srcPort, dstPort int) bool {
	srcKnown := asset.ProtocolForPort(srcPort) != ""
	dstKnown := asset.ProtocolForPort(dstPort) != ""
	switch {
	case dstKnown && !srcKnown:
		return true
	case srcKnown && !dstKnown:
		return false
	case dstPort != srcPort:
		return dstPort < srcPort
	default:
		return true
	}
}

func packetAddresses(pkt gopacket.Packet) (string, string) {
	if ip4, _ := pkt.Layer(layers.LayerTypeIPv4).(*layers.IPv4); ip4 != nil {
		return ip4.SrcIP.String(), ip4.DstIP.String()
	}
	if ip6, _ := pkt.Layer(layers.LayerTypeIPv6).(*layers.IPv6); ip6 != nil {
		return ip6.SrcIP.String(), ip6.DstIP.String()
	}
	return "", ""
}

func formatMAC(hw []byte) string {
	if len(hw) != 6 {
		return ""
	}
	return net.HardwareAddr(hw).String()
}

func formatIP(raw []byte) string {
	switch len(raw) {
	case 4, 16:
		return net.IP(raw).String()
	default:
		return ""
	}
}

// usableMAC rejects the addresses that identify a group rather than a device.
// Creating an asset for the broadcast address or for an LLDP multicast group would
// put entries in the inventory that no operator can go and find.
func usableMAC(mac string) bool {
	hw, err := net.ParseMAC(mac)
	if err != nil || len(hw) != 6 {
		return false
	}
	if hw[0]&0x01 != 0 {
		return false
	}
	allZero := true
	for _, b := range hw {
		if b != 0 {
			allZero = false
			break
		}
	}
	return !allZero
}

// usableIP rejects addresses that cannot name a single device.
func usableIP(raw string) bool {
	ip := net.ParseIP(raw)
	if ip == nil || ip.IsUnspecified() || ip.IsMulticast() || ip.IsLinkLocalMulticast() {
		return false
	}
	if ip4 := ip.To4(); ip4 != nil && ip4[0] == 255 && ip4[1] == 255 && ip4[2] == 255 && ip4[3] == 255 {
		return false
	}
	return true
}

func collapseWhitespace(raw string) string {
	return strings.Join(strings.Fields(raw), " ")
}
