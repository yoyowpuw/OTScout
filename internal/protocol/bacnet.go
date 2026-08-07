package protocol

import (
	"encoding/binary"
	"fmt"

	"github.com/yoyowpuw/OTScout/internal/asset"
)

// BACnet/IP, limited to Who-Is and ReadProperty.
//
// Who-Is is a broadcast question that asks devices to announce themselves, and
// ReadProperty reads one property of one object. Both are read operations by
// definition. WriteProperty, ReinitializeDevice and DeviceCommunicationControl
// have no encoder here, and the last two are exactly the services that could take
// a building controller out of service.
const (
	bacnetBVLLType     = 0x81
	bacnetOriginalUni  = 0x0A
	bacnetOriginalBcst = 0x0B
	bacnetBVLLHeader   = 4
	bacnetNPDUVersion  = 0x01

	bacnetPDUConfirmedRequest   = 0x00
	bacnetPDUUnconfirmedRequest = 0x10
	bacnetPDUSimpleACK          = 0x20
	bacnetPDUComplexACK         = 0x30
	bacnetPDUError              = 0x50
	bacnetPDUReject             = 0x60
	bacnetPDUAbort              = 0x70

	bacnetServiceReadProperty = 0x0C
	bacnetServiceWhoIs        = 0x08
	bacnetServiceIAm          = 0x00

	bacnetObjectTypeDevice = 8
	// bacnetInstanceSelf is the wildcard device instance. The standard allows a
	// ReadProperty against the Device object with this instance to mean the
	// receiving device, which is what lets a probe ask "what are you" without
	// already knowing the answer.
	bacnetInstanceSelf = 0x3FFFFF

	bacnetMaxFrameSize = 1500
)

// Property identifiers used by the identification probe.
const (
	BACnetPropObjectName       uint32 = 77
	BACnetPropVendorName       uint32 = 121
	BACnetPropVendorIdentifier uint32 = 120
	BACnetPropModelName        uint32 = 70
	BACnetPropFirmwareRevision uint32 = 44
	BACnetPropApplicationSWVer uint32 = 12
	BACnetPropSerialNumber     uint32 = 372
	BACnetPropProtocolVersion  uint32 = 98
	BACnetPropProtocolRevision uint32 = 139
	BACnetPropSystemStatus     uint32 = 112
	BACnetPropLocation         uint32 = 58
	BACnetPropDescription      uint32 = 28
)

var bacnetPropertyNames = map[uint32]string{
	BACnetPropObjectName:       "object_name",
	BACnetPropVendorName:       "vendor_name",
	BACnetPropVendorIdentifier: "vendor_identifier",
	BACnetPropModelName:        "model_name",
	BACnetPropFirmwareRevision: "firmware_revision",
	BACnetPropApplicationSWVer: "application_software_version",
	BACnetPropSerialNumber:     "serial_number",
	BACnetPropProtocolVersion:  "protocol_version",
	BACnetPropProtocolRevision: "protocol_revision",
	BACnetPropSystemStatus:     "system_status",
	BACnetPropLocation:         "location",
	BACnetPropDescription:      "description",
}

// BACnetIdentificationProperties is the set the fingerprint probe reads, in the
// order it reads them. Vendor and model come first so that a device which stops
// answering partway through still yields something usable.
var BACnetIdentificationProperties = []uint32{
	BACnetPropVendorName,
	BACnetPropModelName,
	BACnetPropFirmwareRevision,
	BACnetPropApplicationSWVer,
	BACnetPropObjectName,
	BACnetPropVendorIdentifier,
}

// BACnetWhoIsRequest builds an unqualified Who-Is, which asks every device that
// hears it to identify itself.
func BACnetWhoIsRequest() []byte {
	apdu := []byte{bacnetPDUUnconfirmedRequest, bacnetServiceWhoIs}
	return wrapBACnet(bacnetOriginalBcst, apdu)
}

// BACnetReadPropertyRequest builds a ReadProperty request against the Device
// object of the receiving device.
func BACnetReadPropertyRequest(invokeID byte, property uint32) []byte {
	objectID := uint32(bacnetObjectTypeDevice)<<22 | bacnetInstanceSelf

	apdu := make([]byte, 0, 16)
	apdu = append(apdu,
		bacnetPDUConfirmedRequest,
		0x05, // maximum APDU length accepted: 1476 octets, no segmentation
		invokeID,
		bacnetServiceReadProperty,
	)
	// Context tag 0: object identifier, always four octets.
	apdu = append(apdu, 0x0C)
	apdu = binary.BigEndian.AppendUint32(apdu, objectID)
	// Context tag 1: property identifier, encoded in as few octets as possible.
	propBytes := encodeUnsigned(property)
	apdu = append(apdu, byte(0x18|len(propBytes)))
	apdu = append(apdu, propBytes...)

	return wrapBACnet(bacnetOriginalUni, apdu)
}

// wrapBACnet prepends the NPDU and BVLL headers to an APDU.
func wrapBACnet(bvllFunction byte, apdu []byte) []byte {
	// Control byte 0x04 marks that a reply is expected. A Who-Is expects
	// replies from many devices but is itself unconfirmed, so it clears the bit.
	control := byte(0x04)
	if bvllFunction == bacnetOriginalBcst {
		control = 0x20 // destination is a broadcast on the local network
	}
	npdu := []byte{bacnetNPDUVersion, control}
	if control == 0x20 {
		// A global broadcast carries DNET 0xFFFF, DLEN 0 and a hop count.
		npdu = append(npdu, 0xFF, 0xFF, 0x00, 0xFF)
	}

	body := append(npdu, apdu...)
	total := bacnetBVLLHeader + len(body)
	frame := make([]byte, bacnetBVLLHeader, total)
	frame[0] = bacnetBVLLType
	frame[1] = bvllFunction
	binary.BigEndian.PutUint16(frame[2:4], uint16(total))
	return append(frame, body...)
}

func encodeUnsigned(value uint32) []byte {
	switch {
	case value < 0x100:
		return []byte{byte(value)}
	case value < 0x10000:
		return []byte{byte(value >> 8), byte(value)}
	case value < 0x1000000:
		return []byte{byte(value >> 16), byte(value >> 8), byte(value)}
	default:
		return []byte{byte(value >> 24), byte(value >> 16), byte(value >> 8), byte(value)}
	}
}

// DecodeBACnetResponse decodes a BACnet/IP frame.
func DecodeBACnetResponse(payload []byte) (Observation, error) {
	obs := newObservation(NameBACnet)

	r := newReader(payload)
	bvllType, ok := r.u8()
	if !ok || bvllType != bacnetBVLLType {
		return obs, ErrNotThisProtocol
	}
	bvllFunction, ok := r.u8()
	if !ok {
		return obs, ErrNotThisProtocol
	}
	total, ok := r.u16be()
	if !ok || int(total) < bacnetBVLLHeader || int(total) > bacnetMaxFrameSize {
		return obs, ErrNotThisProtocol
	}

	version, ok := r.u8()
	if !ok || version != bacnetNPDUVersion {
		return obs, ErrNotThisProtocol
	}
	control, ok := r.u8()
	if !ok {
		return obs, ErrTruncated
	}
	if err := skipNPDUAddressing(r, control); err != nil {
		return obs, err
	}

	obs.set("bvll_function", fmt.Sprintf("0x%02x", bvllFunction))

	pduByte, ok := r.u8()
	if !ok {
		return obs, ErrTruncated
	}
	pduType := pduByte & 0xF0

	switch pduType {
	case bacnetPDUUnconfirmedRequest:
		service, ok := r.u8()
		if !ok {
			return obs, ErrTruncated
		}
		if service != bacnetServiceIAm {
			obs.note("BACnet unconfirmed service %d carries no identification data", service)
			return obs, nil
		}
		return obs, decodeIAm(r, &obs)

	case bacnetPDUComplexACK:
		if _, ok := r.u8(); !ok { // invoke id
			return obs, ErrTruncated
		}
		service, ok := r.u8()
		if !ok {
			return obs, ErrTruncated
		}
		if service != bacnetServiceReadProperty {
			obs.note("BACnet acknowledged service %d, which this build does not read", service)
			return obs, nil
		}
		return obs, decodeReadPropertyACK(r, &obs)

	case bacnetPDUError:
		// An Error PDU carries the invoke id, the service, then an error class
		// and an error code as enumerated values.
		if _, ok := r.u8(); !ok {
			return obs, ErrTruncated
		}
		if _, ok := r.u8(); !ok {
			return obs, ErrTruncated
		}
		errClass, classErr := readApplicationValue(r)
		errCode, codeErr := readApplicationValue(r)
		obs.note("device answered the BACnet request with an error, so it speaks BACnet but does not expose this property")
		if classErr != nil || codeErr != nil {
			return obs, &ErrDeviceError{Protocol: NameBACnet, Detail: "malformed error PDU"}
		}
		obs.set("error_class", errClass.String())
		obs.set("error_code", errCode.String())
		return obs, &ErrDeviceError{
			Protocol: NameBACnet,
			Code:     int(errCode.unsigned),
			Detail:   fmt.Sprintf("error class %s", errClass.String()),
		}

	case bacnetPDUReject, bacnetPDUAbort:
		// Reject and Abort carry the invoke id followed by a single reason byte.
		if _, ok := r.u8(); !ok {
			return obs, ErrTruncated
		}
		reason, ok := r.u8()
		if !ok {
			return obs, ErrTruncated
		}
		kind := "rejected"
		if pduType == bacnetPDUAbort {
			kind = "aborted"
		}
		obs.note("device %s the BACnet request but is speaking BACnet", kind)
		obs.set("reject_reason", fmt.Sprintf("%d", reason))
		return obs, &ErrDeviceError{
			Protocol: NameBACnet,
			Code:     int(reason),
			Detail:   fmt.Sprintf("request %s with reason %d", kind, reason),
		}

	default:
		obs.set("pdu_type", fmt.Sprintf("0x%02x", pduType))
		return obs, nil
	}
}

// skipNPDUAddressing steps over the optional routing fields of an NPDU.
func skipNPDUAddressing(r *reader, control byte) error {
	if control&0x20 != 0 { // destination specifier present
		if !r.skip(2) { // DNET
			return ErrTruncated
		}
		dlen, ok := r.u8()
		if !ok {
			return ErrTruncated
		}
		if !r.skip(int(dlen)) {
			return ErrTruncated
		}
	}
	if control&0x08 != 0 { // source specifier present
		if !r.skip(2) { // SNET
			return ErrTruncated
		}
		slen, ok := r.u8()
		if !ok {
			return ErrTruncated
		}
		if !r.skip(int(slen)) {
			return ErrTruncated
		}
	}
	if control&0x20 != 0 {
		if !r.skip(1) { // hop count
			return ErrTruncated
		}
	}
	return nil
}

// decodeIAm reads an I-Am response, which announces a device instance and vendor.
func decodeIAm(r *reader, obs *Observation) error {
	tag, ok := r.u8()
	if !ok {
		return ErrTruncated
	}
	// Application tag 12 is a BACnetObjectIdentifier and is always four octets.
	if tag != 0xC4 {
		return ErrNotThisProtocol
	}
	objectID, ok := r.u32be()
	if !ok {
		return ErrTruncated
	}
	objectType := objectID >> 22
	instance := objectID & 0x3FFFFF
	obs.set("device_instance", fmt.Sprintf("%d", instance))
	if objectType == bacnetObjectTypeDevice {
		obs.Role = asset.RoleBuildingAC
	}

	// Maximum APDU length, then segmentation support, then the vendor id.
	if _, err := readApplicationValue(r); err != nil {
		return nil
	}
	if _, err := readApplicationValue(r); err != nil {
		return nil
	}
	vendor, err := readApplicationValue(r)
	if err != nil {
		return nil
	}
	if vendor.kind == bacnetValueUnsigned {
		obs.set("vendor_identifier", fmt.Sprintf("%d", vendor.unsigned))
	}
	return nil
}

// decodeReadPropertyACK reads the acknowledgement of a ReadProperty request.
func decodeReadPropertyACK(r *reader, obs *Observation) error {
	tag, ok := r.u8()
	if !ok || tag != 0x0C {
		return ErrNotThisProtocol
	}
	if _, ok := r.u32be(); !ok { // object identifier
		return ErrTruncated
	}

	propTag, ok := r.u8()
	if !ok {
		return ErrTruncated
	}
	// Context tag 1 holds the property identifier, with the low nibble giving
	// its length.
	if propTag&0xF8 != 0x18 {
		return ErrNotThisProtocol
	}
	propLen := int(propTag & 0x07)
	propBytes, ok := r.bytes(propLen)
	if !ok {
		return ErrTruncated
	}
	property := decodeUnsigned(propBytes)

	// An opening context tag 3 wraps the value.
	opening, ok := r.u8()
	if !ok {
		return ErrTruncated
	}
	if opening != 0x3E {
		// Some devices include an array index before the value. Step over it.
		if opening&0xF8 == 0x28 {
			if !r.skip(int(opening & 0x07)) {
				return ErrTruncated
			}
			if opening, ok = r.u8(); !ok || opening != 0x3E {
				return ErrNotThisProtocol
			}
		} else {
			return ErrNotThisProtocol
		}
	}

	value, err := readApplicationValue(r)
	if err != nil {
		return err
	}

	name := bacnetPropertyNames[property]
	if name == "" {
		name = fmt.Sprintf("property_%d", property)
	}
	obs.set(name, value.String())
	applyBACnetProperty(obs, property, value)
	return nil
}

const (
	bacnetValueUnknown = iota
	bacnetValueUnsigned
	bacnetValueString
	bacnetValueEnumerated
)

type bacnetValue struct {
	kind     int
	unsigned uint32
	text     string
}

func (v bacnetValue) String() string {
	switch v.kind {
	case bacnetValueUnsigned, bacnetValueEnumerated:
		return fmt.Sprintf("%d", v.unsigned)
	case bacnetValueString:
		return v.text
	default:
		return ""
	}
}

// readApplicationValue decodes one application tagged value. Only the tags the
// identification properties actually use are handled, and anything else is
// reported as unknown rather than misread.
func readApplicationValue(r *reader) (bacnetValue, error) {
	tag, ok := r.u8()
	if !ok {
		return bacnetValue{}, ErrTruncated
	}
	tagNumber := tag >> 4
	lengthField := int(tag & 0x07)

	// A length field of 5 means the real length follows in an extra octet.
	length := lengthField
	if lengthField == 5 {
		extended, ok := r.u8()
		if !ok {
			return bacnetValue{}, ErrTruncated
		}
		length = int(extended)
	}

	switch tagNumber {
	case 2: // unsigned integer
		raw, ok := r.bytes(length)
		if !ok {
			return bacnetValue{}, ErrTruncated
		}
		return bacnetValue{kind: bacnetValueUnsigned, unsigned: decodeUnsigned(raw)}, nil

	case 9: // enumerated
		raw, ok := r.bytes(length)
		if !ok {
			return bacnetValue{}, ErrTruncated
		}
		return bacnetValue{kind: bacnetValueEnumerated, unsigned: decodeUnsigned(raw)}, nil

	case 7: // character string
		if length < 1 {
			return bacnetValue{kind: bacnetValueString}, nil
		}
		encoding, ok := r.u8()
		if !ok {
			return bacnetValue{}, ErrTruncated
		}
		raw, ok := r.bytes(length - 1)
		if !ok {
			return bacnetValue{}, ErrTruncated
		}
		value := bacnetValue{kind: bacnetValueString, text: cleanASCII(raw)}
		if encoding != 0 {
			// Encodings other than UTF-8 exist but are rare. The bytes are
			// still shown, cleaned of anything unprintable.
			value.text = cleanASCII(raw)
		}
		return value, nil

	default:
		if !r.skip(length) {
			return bacnetValue{}, ErrTruncated
		}
		return bacnetValue{kind: bacnetValueUnknown}, nil
	}
}

func decodeUnsigned(raw []byte) uint32 {
	var value uint32
	for _, b := range raw {
		value = value<<8 | uint32(b)
	}
	return value
}

// applyBACnetProperty maps a property value onto the canonical identity.
func applyBACnetProperty(obs *Observation, property uint32, value bacnetValue) {
	switch property {
	case BACnetPropVendorName:
		obs.Identity.VendorRaw = value.text
		obs.Identity.Vendor = value.text
	case BACnetPropModelName:
		obs.Identity.ProductRaw = value.text
		obs.Identity.Product = value.text
	case BACnetPropFirmwareRevision:
		obs.Identity.FirmwareRaw = value.text
		obs.Identity.Firmware = value.text
	case BACnetPropApplicationSWVer:
		if obs.Identity.Firmware == "" {
			obs.Identity.FirmwareRaw = value.text
			obs.Identity.Firmware = value.text
		}
	case BACnetPropSerialNumber:
		obs.Identity.Serial = value.text
	}
	if obs.Role == asset.RoleUnknown {
		obs.Role = asset.RoleBuildingAC
	}
}
