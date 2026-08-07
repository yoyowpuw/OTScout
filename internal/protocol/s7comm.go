package protocol

import (
	"encoding/binary"
	"fmt"

	"github.com/yoyowpuw/OTScout/internal/asset"
)

// S7comm over ISO-on-TCP, limited to reading the System Status List.
//
// Reaching a Siemens CPU takes three steps: a COTP connection request, an S7
// Setup Communication, then the actual read. The only read encoded here is Read
// SZL, which returns the module order number, firmware version and serial number.
// SZL is a diagnostic buffer, not process memory, and reading it does not affect
// the scan cycle.
//
// There is no encoder in this file for a variable read or write, and none for the
// PLC control functions that stop or start the CPU. That is the point: the bytes
// for those operations cannot be produced by this build.
const (
	tpktVersion   = 0x03
	tpktHeaderLen = 4

	cotpConnectionRequest = 0xE0
	cotpConnectionConfirm = 0xD0
	cotpDataTransfer      = 0xF0

	s7ProtocolID = 0x32

	s7ROSCTRJob      = 0x01
	s7ROSCTRAck      = 0x02
	s7ROSCTRAckData  = 0x03
	s7ROSCTRUserData = 0x07

	s7FunctionSetupComm = 0xF0

	s7MaxFrameSize = 4096
)

// SZL identifiers this package can request.
const (
	// SZLModuleIdentification returns the order number and firmware version.
	SZLModuleIdentification uint16 = 0x0011
	// SZLComponentIdentification returns names and serial numbers as text.
	SZLComponentIdentification uint16 = 0x001C
)

// szlComponentIndexes names the records of SZL 0x001C. These indexes are defined
// by Siemens and are stable across the S7-300, S7-400, S7-1200 and S7-1500
// families.
var szlComponentIndexes = map[uint16]string{
	0x0001: "automation_system_name",
	0x0002: "module_name",
	0x0003: "plant_designation",
	0x0004: "copyright",
	0x0005: "module_serial_number",
	0x0007: "module_type_name",
	0x0008: "memory_card_serial_number",
	0x0009: "cpu_manufacturer_profile",
	0x000A: "oem_id",
	0x000B: "location_designation",
}

// S7ConnectionRequest builds the COTP connection request.
//
// The destination TSAP encodes the rack and slot of the CPU. Rack 0 slot 2 is the
// default for the S7-300 and S7-400, while the S7-1200 and S7-1500 answer on rack
// 0 slot 1. A probe tries the documented defaults in order.
func S7ConnectionRequest(sourceTSAP, destTSAP uint16) []byte {
	cotp := []byte{
		0x11,                  // length indicator, the 17 bytes that follow
		cotpConnectionRequest, // connection request
		0x00, 0x00,            // destination reference
		0x00, 0x01, // source reference
		0x00,             // class and options
		0xC0, 0x01, 0x0A, // parameter: TPDU size 1024
		0xC1, 0x02, byte(sourceTSAP >> 8), byte(sourceTSAP), // calling TSAP
		0xC2, 0x02, byte(destTSAP >> 8), byte(destTSAP), // called TSAP
	}
	return wrapTPKT(cotp)
}

// S7SetupCommunication builds the Setup Communication job that negotiates the
// maximum PDU length. A CPU will not answer a Read SZL until this has completed.
func S7SetupCommunication(pduReference uint16) []byte {
	params := []byte{
		s7FunctionSetupComm,
		0x00,       // reserved
		0x00, 0x01, // maximum outstanding calls, calling
		0x00, 0x01, // maximum outstanding calls, called
		0x01, 0xE0, // requested PDU length, 480 bytes
	}
	header := s7Header(s7ROSCTRJob, pduReference, len(params), 0)
	return wrapTPKT(append(cotpDataHeader(), append(header, params...)...))
}

// S7ReadSZLRequest builds a Read SZL request for the given list and index.
func S7ReadSZLRequest(pduReference uint16, szlID, szlIndex uint16) []byte {
	params := []byte{
		0x00, 0x01, 0x12, // parameter head
		0x04, // parameter length
		0x11, // method: request
		0x44, // type 4 (request) in the high nibble, function group 4 (CPU functions) in the low nibble
		0x01, // subfunction: Read SZL
		0x00, // sequence number
	}
	data := make([]byte, 0, 8)
	data = append(data,
		0xFF,       // return code: success
		0x09,       // transport size: octet string
		0x00, 0x04, // payload length
	)
	data = binary.BigEndian.AppendUint16(data, szlID)
	data = binary.BigEndian.AppendUint16(data, szlIndex)

	header := s7Header(s7ROSCTRUserData, pduReference, len(params), len(data))
	body := append(cotpDataHeader(), header...)
	body = append(body, params...)
	body = append(body, data...)
	return wrapTPKT(body)
}

func s7Header(rosctr byte, pduReference uint16, paramLen, dataLen int) []byte {
	header := make([]byte, 10)
	header[0] = s7ProtocolID
	header[1] = rosctr
	// Redundancy identification, always zero in a request.
	binary.BigEndian.PutUint16(header[2:4], 0)
	binary.BigEndian.PutUint16(header[4:6], pduReference)
	binary.BigEndian.PutUint16(header[6:8], uint16(paramLen))
	binary.BigEndian.PutUint16(header[8:10], uint16(dataLen))
	return header
}

func cotpDataHeader() []byte {
	// Length indicator 2, data transfer, last data unit.
	return []byte{0x02, cotpDataTransfer, 0x80}
}

func wrapTPKT(body []byte) []byte {
	total := tpktHeaderLen + len(body)
	frame := make([]byte, tpktHeaderLen, total)
	frame[0] = tpktVersion
	frame[1] = 0x00
	binary.BigEndian.PutUint16(frame[2:4], uint16(total))
	return append(frame, body...)
}

// DecodeS7Response decodes a TPKT framed S7comm response.
func DecodeS7Response(payload []byte) (Observation, error) {
	obs := newObservation(NameS7comm)

	r := newReader(payload)
	version, ok := r.u8()
	if !ok || version != tpktVersion {
		return obs, ErrNotThisProtocol
	}
	if _, ok := r.u8(); !ok { // reserved
		return obs, ErrNotThisProtocol
	}
	total, ok := r.u16be()
	if !ok || int(total) < tpktHeaderLen || int(total) > s7MaxFrameSize {
		return obs, ErrNotThisProtocol
	}

	cotpLen, ok := r.u8()
	if !ok {
		return obs, ErrTruncated
	}
	cotpType, ok := r.u8()
	if !ok {
		return obs, ErrTruncated
	}

	switch cotpType {
	case cotpConnectionConfirm:
		// A connection confirm proves the device speaks ISO-on-TCP, which by
		// itself is a useful fingerprint even before any S7 exchange.
		obs.note("device accepted an ISO-on-TCP connection, which indicates an S7 family controller")
		obs.set("cotp_response", "connection confirm")
		return obs, nil
	case cotpDataTransfer:
		// The length indicator counts the bytes after itself, and for a data
		// transfer the remaining COTP field is the single flags byte already
		// consumed as cotpType plus one more.
		if cotpLen >= 2 {
			if !r.skip(int(cotpLen) - 1) {
				return obs, ErrTruncated
			}
		}
	default:
		obs.set("cotp_type", fmt.Sprintf("0x%02x", cotpType))
		return obs, ErrNotThisProtocol
	}

	protocolID, ok := r.u8()
	if !ok || protocolID != s7ProtocolID {
		return obs, ErrNotThisProtocol
	}
	rosctr, ok := r.u8()
	if !ok {
		return obs, ErrTruncated
	}
	if !r.skip(2) { // redundancy identification
		return obs, ErrTruncated
	}
	if _, ok := r.u16be(); !ok { // pdu reference
		return obs, ErrTruncated
	}
	paramLen, ok := r.u16be()
	if !ok {
		return obs, ErrTruncated
	}
	dataLen, ok := r.u16be()
	if !ok {
		return obs, ErrTruncated
	}

	// Acknowledgement frames carry two extra error bytes that user data frames
	// do not.
	if rosctr == s7ROSCTRAck || rosctr == s7ROSCTRAckData {
		errClass, ok := r.u8()
		if !ok {
			return obs, ErrTruncated
		}
		errCode, ok := r.u8()
		if !ok {
			return obs, ErrTruncated
		}
		if errClass != 0 || errCode != 0 {
			return obs, &ErrDeviceError{
				Protocol: NameS7comm,
				Code:     int(errClass)<<8 | int(errCode),
				Detail:   fmt.Sprintf("error class 0x%02x code 0x%02x", errClass, errCode),
			}
		}
	}

	params, ok := r.bytes(int(paramLen))
	if !ok {
		return obs, ErrTruncated
	}
	data, ok := r.bytes(int(dataLen))
	if !ok {
		return obs, ErrTruncated
	}

	if rosctr == s7ROSCTRAckData && len(params) > 0 && params[0] == s7FunctionSetupComm {
		if len(params) >= 8 {
			obs.set("negotiated_pdu_length", fmt.Sprintf("%d", binary.BigEndian.Uint16(params[6:8])))
		}
		obs.note("device completed S7 Setup Communication")
		return obs, nil
	}

	if rosctr != s7ROSCTRUserData {
		obs.set("rosctr", fmt.Sprintf("0x%02x", rosctr))
		obs.note("S7 message type 0x%02x carries no identification data", rosctr)
		return obs, nil
	}

	if err := decodeSZLPayload(data, &obs); err != nil {
		return obs, err
	}
	return obs, nil
}

// decodeSZLPayload reads the data part of a Read SZL response.
func decodeSZLPayload(data []byte, obs *Observation) error {
	r := newReader(data)

	returnCode, ok := r.u8()
	if !ok {
		return ErrTruncated
	}
	if returnCode != 0xFF {
		return &ErrDeviceError{
			Protocol: NameS7comm,
			Code:     int(returnCode),
			Detail:   fmt.Sprintf("SZL read returned code 0x%02x", returnCode),
		}
	}
	if _, ok := r.u8(); !ok { // transport size
		return ErrTruncated
	}
	if _, ok := r.u16be(); !ok { // payload length in bits or bytes
		return ErrTruncated
	}

	szlID, ok := r.u16be()
	if !ok {
		return ErrTruncated
	}
	szlIndex, ok := r.u16be()
	if !ok {
		return ErrTruncated
	}
	recordLen, ok := r.u16be()
	if !ok {
		return ErrTruncated
	}
	recordCount, ok := r.u16be()
	if !ok {
		return ErrTruncated
	}

	obs.set("szl_id", fmt.Sprintf("0x%04X", szlID))
	obs.set("szl_index", fmt.Sprintf("0x%04X", szlIndex))

	if recordLen == 0 || recordCount == 0 {
		obs.note("SZL 0x%04X returned no records", szlID)
		return nil
	}
	// A device that reports an implausible record size is either broken or
	// trying to make us allocate. Either way, stop.
	if int(recordLen) > len(data) {
		return ErrTruncated
	}

	records := make([][]byte, 0, recordCount)
	for idx := 0; idx < int(recordCount); idx++ {
		record, ok := r.bytes(int(recordLen))
		if !ok {
			obs.note("SZL record list ended after %d of %d declared records", idx, recordCount)
			break
		}
		records = append(records, record)
	}

	switch szlID {
	case SZLModuleIdentification:
		decodeSZLModuleRecords(records, obs)
	case SZLComponentIdentification:
		decodeSZLComponentRecords(records, obs)
	default:
		obs.note("SZL 0x%04X is not one this build interprets", szlID)
	}
	return nil
}

// decodeSZLModuleRecords reads SZL 0x0011 records.
//
// Each record is 28 bytes: a two byte index, a twenty byte order number, then
// three two byte version words. Record index 1 describes the module itself, and
// its last version word holds the firmware version as three separate bytes. This
// layout follows the Wireshark s7comm dissector, which is the reference other
// open source tools also follow.
func decodeSZLModuleRecords(records [][]byte, obs *Observation) {
	const (
		moduleRecordLen = 28
		mlfbOffset      = 2
		mlfbLen         = 20
		versionOffset   = 25
	)
	for _, record := range records {
		if len(record) < moduleRecordLen {
			continue
		}
		index := binary.BigEndian.Uint16(record[0:2])
		if index != 0x0001 {
			continue
		}

		orderNumber := cleanASCII(record[mlfbOffset : mlfbOffset+mlfbLen])
		if orderNumber != "" {
			obs.set("module_order_number", orderNumber)
			obs.Identity.CatalogNumber = orderNumber
		}

		major, minor, patch := record[versionOffset], record[versionOffset+1], record[versionOffset+2]
		if major != 0 || minor != 0 || patch != 0 {
			version := fmt.Sprintf("V%d.%d.%d", major, minor, patch)
			obs.set("module_firmware_version", version)
			obs.Identity.Firmware = version
			obs.Identity.FirmwareRaw = version
		}
		break
	}
	obs.Identity.VendorRaw = "Siemens"
	obs.Identity.Vendor = "Siemens"
	obs.Role = asset.RolePLC
}

// decodeSZLComponentRecords reads SZL 0x001C records, which are a two byte index
// followed by fixed width text.
func decodeSZLComponentRecords(records [][]byte, obs *Observation) {
	for _, record := range records {
		if len(record) < 3 {
			continue
		}
		index := binary.BigEndian.Uint16(record[0:2])
		text := cleanASCII(record[2:])
		if text == "" {
			continue
		}
		name := szlComponentIndexes[index]
		if name == "" {
			name = fmt.Sprintf("component_0x%04X", index)
		}
		obs.set(name, text)

		switch index {
		case 0x0005:
			obs.Identity.Serial = text
		case 0x0007:
			obs.Identity.ProductRaw = text
			obs.Identity.Product = text
		case 0x0002:
			if obs.Identity.ProductRaw == "" {
				obs.Identity.ProductRaw = text
				obs.Identity.Product = text
			}
		}
	}
	obs.Identity.VendorRaw = "Siemens"
	obs.Identity.Vendor = "Siemens"
	obs.Role = asset.RolePLC
}
