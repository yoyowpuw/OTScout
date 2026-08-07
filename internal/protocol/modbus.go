package protocol

import (
	"encoding/binary"
	"fmt"

	"github.com/yoyowpuw/OTScout/internal/asset"
)

// Modbus/TCP framing and the one function code this package can emit.
//
// Read Device Identification is function code 43 with MEI type 14. It is the
// function the specification defines for asking a device what it is, and it does
// not touch process data. No other function code has an encoder here, which is
// what makes it impossible for a fingerprint template to write to a coil or a
// register: the bytes for such a request cannot be produced by this build.
const (
	modbusFCReadDeviceID = 0x2B
	modbusMEIDeviceID    = 0x0E
	modbusExceptionFlag  = 0x80
	modbusMBAPHeaderLen  = 7
	// modbusMBAPPrefixLen is the part of the header that precedes the byte the
	// length field starts counting from.
	modbusMBAPPrefixLen   = 6
	modbusProtocolID      = 0x0000
	modbusMaxResponseSize = 260
)

// Device identification read codes from the Modbus specification.
const (
	ModbusReadBasic    byte = 0x01
	ModbusReadRegular  byte = 0x02
	ModbusReadExtended byte = 0x03
)

// Object ids defined for the basic device identification stream.
const (
	modbusObjVendorName          = 0x00
	modbusObjProductCode         = 0x01
	modbusObjMajorMinorRevision  = 0x02
	modbusObjVendorURL           = 0x03
	modbusObjProductName         = 0x04
	modbusObjModelName           = 0x05
	modbusObjUserApplicationName = 0x06
)

var modbusObjectNames = map[byte]string{
	modbusObjVendorName:          "vendor_name",
	modbusObjProductCode:         "product_code",
	modbusObjMajorMinorRevision:  "major_minor_revision",
	modbusObjVendorURL:           "vendor_url",
	modbusObjProductName:         "product_name",
	modbusObjModelName:           "model_name",
	modbusObjUserApplicationName: "user_application_name",
}

var modbusExceptions = map[byte]string{
	0x01: "illegal function",
	0x02: "illegal data address",
	0x03: "illegal data value",
	0x04: "slave device failure",
	0x05: "acknowledge",
	0x06: "slave device busy",
	0x08: "memory parity error",
	0x0A: "gateway path unavailable",
	0x0B: "gateway target device failed to respond",
}

// ModbusDeviceIDRequest builds a Read Device Identification request.
//
// The transaction id is a caller supplied value so that a probe can match a reply
// to its request, and the unit id addresses a device behind a gateway. Unit id 1
// is the usual default for a device reached directly.
func ModbusDeviceIDRequest(transactionID uint16, unitID byte, readCode byte) []byte {
	switch readCode {
	case ModbusReadBasic, ModbusReadRegular, ModbusReadExtended:
	default:
		readCode = ModbusReadBasic
	}

	pdu := []byte{modbusFCReadDeviceID, modbusMEIDeviceID, readCode, modbusObjVendorName}

	frame := make([]byte, modbusMBAPHeaderLen+len(pdu))
	binary.BigEndian.PutUint16(frame[0:2], transactionID)
	binary.BigEndian.PutUint16(frame[2:4], modbusProtocolID)
	// The length field counts the unit id plus the PDU.
	binary.BigEndian.PutUint16(frame[4:6], uint16(1+len(pdu)))
	frame[6] = unitID
	copy(frame[7:], pdu)
	return frame
}

// modbusFraming reports whether a payload divides into whole MBAP frames, and
// distinguishes a payload that is not Modbus at all from one that is a valid
// frame arriving in pieces.
//
// The MBAP header is only six bytes and two of them are a protocol id that must
// be zero, so any protocol whose third and fourth bytes happen to be zero can
// look like Modbus. HART-IP is the case that found this: its own header puts
// zeroes where Modbus expects the protocol id, and the frame was being filed as a
// Modbus response to function 13, from a device that speaks no Modbus at all. A
// tool that reports vulnerable equipment cannot afford to invent the protocol it
// found, because a wrong protocol becomes a wrong role, a wrong Purdue level, and
// an advisory search against equipment the device is not.
//
// The length field is the discriminator. It counts the unit id and the PDU, so a
// real frame accounts for every byte after the header and a coincidence rarely
// does. Several frames can share one segment because Modbus clients pipeline
// requests, which is why this walks the payload rather than comparing one length
// against the whole of it.
//
// The distinction from truncation has to be kept: the ingest path holds a
// truncated frame and waits for the rest of the stream, and collapsing the two
// would turn every response split across two segments into a device with no
// identity.
func modbusFraming(payload []byte) error {
	for len(payload) > 0 {
		if len(payload) < modbusMBAPPrefixLen {
			return ErrTruncated
		}
		if binary.BigEndian.Uint16(payload[2:4]) != modbusProtocolID {
			return ErrNotThisProtocol
		}
		length := int(binary.BigEndian.Uint16(payload[4:6]))
		// No Modbus message is a unit id and a bare function code. Every response
		// the specification defines carries at least one byte after it, an
		// exception code or a byte count or a value, and so does every request.
		// This is the check that rejects HART-IP, whose sequence number sits where
		// the Modbus length field does and is small.
		//
		// The upper bound is the frame size the specification caps a device at.
		if length < 3 || length > modbusMaxResponseSize {
			return ErrNotThisProtocol
		}
		frameLen := modbusMBAPPrefixLen + length
		if frameLen > len(payload) {
			return ErrTruncated
		}
		payload = payload[frameLen:]
	}
	return nil
}

// DecodeModbusResponse decodes a Modbus/TCP response frame.
func DecodeModbusResponse(payload []byte) (Observation, error) {
	obs := newObservation(NameModbus)

	if err := modbusFraming(payload); err != nil {
		return obs, err
	}

	r := newReader(payload)
	transactionID, ok := r.u16be()
	if !ok {
		return obs, ErrNotThisProtocol
	}
	protocolID, ok := r.u16be()
	if !ok || protocolID != modbusProtocolID {
		// A non zero protocol id means this is not Modbus/TCP.
		return obs, ErrNotThisProtocol
	}
	length, ok := r.u16be()
	if !ok || length < 2 || int(length) > modbusMaxResponseSize {
		return obs, ErrNotThisProtocol
	}
	unitID, ok := r.u8()
	if !ok {
		return obs, ErrTruncated
	}
	functionCode, ok := r.u8()
	if !ok {
		return obs, ErrTruncated
	}

	obs.set("transaction_id", fmt.Sprintf("%d", transactionID))
	obs.set("unit_id", fmt.Sprintf("%d", unitID))

	if functionCode&modbusExceptionFlag != 0 {
		code, _ := r.u8()
		detail := modbusExceptions[code]
		if detail == "" {
			detail = "undocumented exception code"
		}
		// A device that refuses the request still told us it speaks Modbus.
		obs.set("exception_code", fmt.Sprintf("%d", code))
		obs.note("device answered Modbus function %d with exception %d (%s), so it speaks Modbus but does not support device identification",
			functionCode&^modbusExceptionFlag, code, detail)
		return obs, &ErrDeviceError{Protocol: NameModbus, Code: int(code), Detail: detail}
	}

	if functionCode != modbusFCReadDeviceID {
		obs.set("function_code", fmt.Sprintf("%d", functionCode))
		obs.note("Modbus function %d carries no identification data", functionCode)
		return obs, nil
	}

	mei, ok := r.u8()
	if !ok {
		return obs, ErrTruncated
	}
	if mei != modbusMEIDeviceID {
		return obs, ErrNotThisProtocol
	}

	readCode, ok := r.u8()
	if !ok {
		return obs, ErrTruncated
	}
	conformity, ok := r.u8()
	if !ok {
		return obs, ErrTruncated
	}
	moreFollows, ok := r.u8()
	if !ok {
		return obs, ErrTruncated
	}
	nextObjectID, ok := r.u8()
	if !ok {
		return obs, ErrTruncated
	}
	objectCount, ok := r.u8()
	if !ok {
		return obs, ErrTruncated
	}

	obs.set("read_device_id_code", fmt.Sprintf("%d", readCode))
	obs.set("conformity_level", fmt.Sprintf("0x%02x", conformity))
	if moreFollows == 0xFF {
		obs.set("next_object_id", fmt.Sprintf("%d", nextObjectID))
		obs.note("the device has more identification objects, continue from object id %d", nextObjectID)
	}

	objects := make(map[byte]string, objectCount)
	for idx := 0; idx < int(objectCount); idx++ {
		objectID, ok := r.u8()
		if !ok {
			obs.note("object list ended after %d of %d declared objects", idx, objectCount)
			break
		}
		objectLen, ok := r.u8()
		if !ok {
			obs.note("object %d declared no length", objectID)
			break
		}
		value, ok := r.bytes(int(objectLen))
		if !ok {
			obs.note("object %d declared %d bytes but the frame ended", objectID, objectLen)
			break
		}
		text := cleanASCII(value)
		if text == "" {
			continue
		}
		objects[objectID] = text

		name := modbusObjectNames[objectID]
		if name == "" {
			name = fmt.Sprintf("object_0x%02x", objectID)
		}
		obs.set(name, text)
	}

	obs.Identity = modbusIdentity(objects)
	if obs.Identity.Empty() && len(objects) == 0 {
		obs.note("the device answered device identification but reported no objects")
	}
	return obs, nil
}

// modbusIdentity maps the identification objects onto the canonical model.
//
// Only the raw fields are filled in. Resolving them to a canonical vendor and
// family is the normalization layer's job, and doing it here would put vendor
// knowledge in the protocol decoder where nobody would think to look for it.
func modbusIdentity(objects map[byte]string) asset.Identity {
	id := asset.Identity{
		VendorRaw:   objects[modbusObjVendorName],
		ProductRaw:  objects[modbusObjProductName],
		Model:       objects[modbusObjModelName],
		FirmwareRaw: objects[modbusObjMajorMinorRevision],
	}
	// The product code field carries the vendor order code on most devices,
	// which is exactly what the catalog number parsers expect.
	id.CatalogNumber = objects[modbusObjProductCode]

	if id.ProductRaw == "" {
		id.ProductRaw = id.Model
	}
	id.Vendor = id.VendorRaw
	id.Product = id.ProductRaw
	id.Firmware = id.FirmwareRaw
	return id
}
