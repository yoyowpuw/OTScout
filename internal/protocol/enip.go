package protocol

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"

	"github.com/yoyowpuw/OTScout/internal/asset"
)

// EtherNet/IP encapsulation, limited to the List Identity command.
//
// List Identity asks a device to describe itself and is answered from the
// encapsulation layer without opening a CIP session or touching any object other
// than the Identity object. It is the standard discovery command on this protocol
// and is what ODVA's own tooling uses. No session registration, no service request
// and no attribute write is encoded in this file.
const (
	enipCmdListIdentity  = 0x0063
	enipHeaderLen        = 24
	enipItemCIPIdentity  = 0x000C
	enipMaxResponseSize  = 65535
	enipStatusSuccess    = 0x00000000
	enipSocketAddressLen = 16
)

// enipCommands is the set of encapsulation commands defined by the
// specification, which is what makes it possible to tell EtherNet/IP from
// anything else that happens to start with two bytes and a length.
//
// The encapsulation header carries no magic number. Its first field is a command
// code, so a payload becomes plausible EtherNet/IP the moment its first two bytes
// read as a number, and every protocol has first two bytes. Real traffic makes
// this concrete: a Niagara Fox greeting starts with the ASCII "fox", an Omron FINS
// frame starts with "FINS", and both were being reported as EtherNet/IP devices.
// Refusing every command the specification does not define costs nothing and ends
// that whole class of mistake.
// NOP is absent on purpose. It is defined, but it is a message a client sends to
// keep a TCP connection open and no device ever answers with one, so a response
// bearing command zero is not EtherNet/IP. Leaving it out is what stops an
// OSIsoft PI service on port 5450, whose frames begin with two zero bytes, from
// being inventoried as an industrial controller.
var enipCommands = map[uint16]string{
	0x0004: "List Services",
	0x0063: "List Identity",
	0x0064: "List Interfaces",
	0x0065: "Register Session",
	0x0066: "UnRegister Session",
	0x006F: "Send RR Data",
	0x0070: "Send Unit Data",
	0x0072: "Indicate Status",
	0x0073: "Cancel",
}

var enipStatusText = map[uint32]string{
	0x0001: "sender issued an invalid or unsupported encapsulation command",
	0x0002: "receiver had insufficient memory",
	0x0003: "poorly formed or incorrect data in the request",
	0x0064: "invalid session handle",
	0x0065: "invalid message length",
	0x0069: "unsupported encapsulation protocol revision",
}

// enipDeviceTypes maps the CIP device type to a name. Only entries that are well
// established are listed. A device type we cannot name is reported as a number
// rather than guessed at.
var enipDeviceTypes = map[uint16]string{
	0x0002: "AC Drive",
	0x0007: "General Purpose Discrete I/O",
	0x000C: "Communications Adapter",
	0x000E: "Programmable Logic Controller",
}

// enipVendorIDs maps ODVA vendor ids to names.
//
// This table is deliberately short. ODVA assigns these numbers and the full list
// is long, so rather than fill it in from memory and risk attributing a device to
// the wrong company, otscout relies mainly on the product name string that the
// same response carries. Extending this table from the published ODVA list is a
// welcome contribution.
var enipVendorIDs = map[uint16]string{
	1: "Rockwell Automation/Allen-Bradley",
}

// ENIPListIdentityRequest builds a List Identity request.
//
// senderContext is echoed back by the device, which lets a probe confirm that a
// reply belongs to its own request rather than to a broadcast from someone else on
// the segment.
func ENIPListIdentityRequest(senderContext [8]byte) []byte {
	frame := make([]byte, enipHeaderLen)
	binary.LittleEndian.PutUint16(frame[0:2], enipCmdListIdentity)
	// Length, session handle and status are all zero in a request.
	copy(frame[12:20], senderContext[:])
	return frame
}

// DecodeENIPResponse decodes an EtherNet/IP encapsulation response.
func DecodeENIPResponse(payload []byte) (Observation, error) {
	obs := newObservation(NameENIP)

	r := newReader(payload)
	command, ok := r.u16le()
	if !ok {
		return obs, ErrNotThisProtocol
	}
	length, ok := r.u16le()
	if !ok {
		return obs, ErrNotThisProtocol
	}
	sessionHandle, ok := r.u32le()
	if !ok {
		return obs, ErrNotThisProtocol
	}
	status, ok := r.u32le()
	if !ok {
		return obs, ErrNotThisProtocol
	}
	if !r.skip(8) { // sender context
		return obs, ErrNotThisProtocol
	}
	if !r.skip(4) { // options
		return obs, ErrNotThisProtocol
	}

	name, known := enipCommands[command]
	if !known {
		return obs, ErrNotThisProtocol
	}
	// The declared body has to actually be here, whatever the command. Checking
	// this for every command and not just for List Identity is what separates a
	// real frame from a payload whose first bytes coincide with a command code:
	// the OSIsoft PI service on port 5450 announced 24 bytes of body in 4 bytes
	// of frame, and was being inventoried as EtherNet/IP.
	if int(length) > enipMaxResponseSize || int(length) > r.remaining() {
		return obs, ErrTruncated
	}
	if command != enipCmdListIdentity {
		obs.set("encapsulation_command", fmt.Sprintf("0x%04x", command))
		obs.note("EtherNet/IP command 0x%04x (%s) carries no identity data", command, name)
		return obs, nil
	}
	if status != enipStatusSuccess {
		detail := enipStatusText[status]
		if detail == "" {
			detail = "undocumented encapsulation status"
		}
		return obs, &ErrDeviceError{Protocol: NameENIP, Code: int(status), Detail: detail}
	}
	if sessionHandle != 0 {
		obs.set("session_handle", fmt.Sprintf("0x%08x", sessionHandle))
	}

	itemCount, ok := r.u16le()
	if !ok {
		return obs, ErrTruncated
	}
	if itemCount == 0 {
		obs.note("the device answered List Identity with no items")
		return obs, nil
	}

	for idx := 0; idx < int(itemCount); idx++ {
		itemType, ok := r.u16le()
		if !ok {
			break
		}
		itemLen, ok := r.u16le()
		if !ok {
			break
		}
		body, ok := r.bytes(int(itemLen))
		if !ok {
			obs.note("item %d declared %d bytes but the frame ended", idx, itemLen)
			break
		}
		if itemType != enipItemCIPIdentity {
			obs.note("skipped item type 0x%04x, which is not a CIP identity item", itemType)
			continue
		}
		if err := decodeCIPIdentity(body, &obs); err != nil {
			obs.note("CIP identity item %d could not be read: %v", idx, err)
		}
		// The first identity item describes the device itself. Later items come
		// from devices behind a bridge and belong to their own assets, so they
		// are not folded into this one.
		break
	}

	return obs, nil
}

// decodeCIPIdentity reads the CIP Identity object body of a List Identity item.
func decodeCIPIdentity(body []byte, obs *Observation) error {
	r := newReader(body)

	protocolVersion, ok := r.u16le()
	if !ok {
		return ErrTruncated
	}
	obs.set("encapsulation_protocol_version", fmt.Sprintf("%d", protocolVersion))

	// The socket address is stored in network byte order inside a little endian
	// message, which is a quirk of this protocol rather than a mistake here.
	sockAddr, ok := r.bytes(enipSocketAddressLen)
	if !ok {
		return ErrTruncated
	}
	if port := binary.BigEndian.Uint16(sockAddr[2:4]); port != 0 {
		ip := net.IP(sockAddr[4:8])
		obs.set("reported_socket_address", fmt.Sprintf("%s:%d", ip, port))
	}

	vendorID, ok := r.u16le()
	if !ok {
		return ErrTruncated
	}
	deviceType, ok := r.u16le()
	if !ok {
		return ErrTruncated
	}
	productCode, ok := r.u16le()
	if !ok {
		return ErrTruncated
	}
	revMajor, ok := r.u8()
	if !ok {
		return ErrTruncated
	}
	revMinor, ok := r.u8()
	if !ok {
		return ErrTruncated
	}
	deviceStatus, ok := r.u16le()
	if !ok {
		return ErrTruncated
	}
	serial, ok := r.u32le()
	if !ok {
		return ErrTruncated
	}
	nameLen, ok := r.u8()
	if !ok {
		return ErrTruncated
	}
	nameBytes, ok := r.bytes(int(nameLen))
	if !ok {
		return ErrTruncated
	}
	productName := cleanASCII(nameBytes)

	state, hasState := r.u8()

	obs.set("vendor_id", fmt.Sprintf("%d", vendorID))
	obs.set("device_type", fmt.Sprintf("%d", deviceType))
	obs.set("product_code", fmt.Sprintf("%d", productCode))
	obs.set("revision", fmt.Sprintf("%d.%d", revMajor, revMinor))
	obs.set("device_status", fmt.Sprintf("0x%04x", deviceStatus))
	obs.set("serial_number", fmt.Sprintf("%08X", serial))
	obs.set("product_name", productName)
	if hasState {
		obs.set("device_state", fmt.Sprintf("0x%02x", state))
	}

	if name, known := enipDeviceTypes[deviceType]; known {
		obs.set("device_type_name", name)
		if deviceType == 0x000E {
			obs.Role = asset.RolePLC
		}
	}

	id := asset.Identity{
		ProductRaw:  productName,
		Product:     productName,
		FirmwareRaw: fmt.Sprintf("%d.%d", revMajor, revMinor),
		Firmware:    fmt.Sprintf("%d.%d", revMajor, revMinor),
		Serial:      fmt.Sprintf("%08X", serial),
	}
	if vendorName, known := enipVendorIDs[vendorID]; known {
		obs.set("vendor_name", vendorName)
		id.VendorRaw = vendorName
		id.Vendor = vendorName
	} else {
		obs.note("ODVA vendor id %d is not in the local table, so the vendor has to be read from the product name", vendorID)
	}
	// Rockwell and several other vendors put the catalog number at the start of
	// the product name, for example "1756-L71/B LOGIX5571".
	if catalog := leadingCatalogToken(productName); catalog != "" {
		id.CatalogNumber = catalog
		obs.set("catalog_number_from_product_name", catalog)
	}
	obs.Identity = id

	return nil
}

// leadingCatalogToken extracts a leading order code from a product name.
//
// An order code is a run of digits with a hyphen in it, which is a shape plain
// product names do not have. The digit count threshold matters: without it a
// model name such as "AB-12" is picked up as a catalog number and handed to the
// catalog parsers, which then have to reject it. Real order codes across the
// vendors otscout knows about carry at least three digits.
func leadingCatalogToken(productName string) string {
	if productName == "" {
		return ""
	}
	end := 0
	for end < len(productName) && productName[end] != ' ' {
		end++
	}
	token := productName[:end]
	// A trailing series letter such as the "/B" in 1756-L71/B is not part of the
	// catalog number.
	if slash := strings.IndexByte(token, '/'); slash > 0 {
		token = token[:slash]
	}
	digits, hasSeparator := 0, false
	for idx := 0; idx < len(token); idx++ {
		switch {
		case token[idx] >= '0' && token[idx] <= '9':
			digits++
		case token[idx] == '-':
			hasSeparator = true
		}
	}
	if hasSeparator && digits >= 3 && len(token) >= 6 {
		return token
	}
	return ""
}
