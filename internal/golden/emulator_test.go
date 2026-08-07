package golden

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// This file re-derives the bytes of every constructed fixture from the software
// the fixture cites.
//
// A constructed fixture is a claim that some named program, in some named
// configuration, emits exactly these bytes. Left as prose in a comment that claim
// would rot the first time anyone touched the file, and nobody reviewing a change
// could check it without reading Python. So the claim is written as code here,
// against the emulator's own source rather than against otscout's decoders, and
// TestConstructedFixturesMatchTheEmulatorTheyCite re-derives every fixture on
// every run.
//
// Nothing in this file may call a decoder. If it did, the corpus would only prove
// that otscout agrees with itself.

// pack writes fixed width, null padded fields the way Python's struct module
// does, which is how both emulators modelled here build their responses.
func pack(w *bytes.Buffer, value string, width int) {
	raw := []byte(value)
	if len(raw) > width {
		raw = raw[:width]
	}
	w.Write(raw)
	w.Write(make([]byte, width-len(raw)))
}

func be16(w *bytes.Buffer, value uint16) { binary.Write(w, binary.BigEndian, value) }
func le16(w *bytes.Buffer, value uint16) { binary.Write(w, binary.LittleEndian, value) }
func le32(w *bytes.Buffer, value uint32) { binary.Write(w, binary.LittleEndian, value) }

// conpotModbusDeviceInfo builds the Read Device Identification response of
// Conpot's Modbus slave.
//
// Follows MBSlave._device_info in conpot/protocols/modbus/slave.py, which emits
// the MEI type, the requested device id, a conformity level fixed at 1, no
// follow up, no next object, then the three objects of the template's
// device_info block in numerical order. handle_request prepends the function
// code, and modbus_tk's TcpQuery.build_response prepends the MBAP header with the
// transaction id and unit id of the request.
func conpotModbusDeviceInfo(transactionID uint16, unitID byte, readCode byte, vendorName, productCode, revision string) []byte {
	var pdu bytes.Buffer
	pdu.WriteByte(0x2B) // function code, prepended by handle_request
	pdu.WriteByte(0x0E) // MEI type
	pdu.WriteByte(readCode)
	pdu.WriteByte(0x01) // conformity level
	pdu.WriteByte(0x00) // no follow up data
	pdu.WriteByte(0x00) // no next object id
	pdu.WriteByte(0x03) // three objects

	for id, value := range []string{vendorName, productCode, revision} {
		pdu.WriteByte(byte(id))
		pdu.WriteByte(byte(len(value)))
		pdu.WriteString(value)
	}

	var frame bytes.Buffer
	be16(&frame, transactionID)
	be16(&frame, 0) // protocol id
	be16(&frame, uint16(pdu.Len()+1))
	frame.WriteByte(unitID)
	frame.Write(pdu.Bytes())
	return frame.Bytes()
}

// conpotS7ComponentIdentification builds the SZL 0x001C response of Conpot's S7
// server.
//
// Follows S7.request_ssl_28 in conpot/protocols/s7comm/s7.py. The list header
// declares a record length of 34 and a record count of 8, and each record is a
// two byte data index followed by 32 bytes of null padded text. The field widths
// differ per record in the Python (24s8s, 32s, 26s6s and so on) but every
// combination totals 32, so they are written here as one padded field.
//
// The result is wrapped by S7(7, ...).pack, then COTP_BASE_packet(0xF0, 0x80),
// then TPKT, as s7_server.py does.
func conpotS7ComponentIdentification(requestID uint16, szlIndex uint16, records []conpotSZLRecord) []byte {
	var body bytes.Buffer
	be16(&body, 0x001C) // SZL id
	be16(&body, szlIndex)
	be16(&body, 34) // length of one record
	be16(&body, 8)  // number of records
	for _, record := range records {
		be16(&body, record.index)
		pack(&body, record.text, 32)
	}

	var data bytes.Buffer
	data.WriteByte(0xFF) // data error code, 0xFF is success
	data.WriteByte(0x09) // data type, 0x09 is char/string
	be16(&data, uint16(body.Len()))
	data.Write(body.Bytes())

	params := []byte{0x00, 0x01, 0x12, 0x08, 0x12, 0x84, 0x01, 0x01}

	var s7 bytes.Buffer
	s7.WriteByte(0x32) // protocol id
	s7.WriteByte(0x07) // user data, which carries no result info header
	be16(&s7, 0)       // reserved
	be16(&s7, requestID)
	be16(&s7, uint16(len(params)))
	be16(&s7, uint16(data.Len()))
	s7.Write(params)
	s7.Write(data.Bytes())

	return conpotTPKT(conpotCOTPData(s7.Bytes()))
}

type conpotSZLRecord struct {
	index uint16
	text  string
}

// conpotS7ConnectionConfirm builds the COTP connection confirm of Conpot's S7
// server.
//
// Follows COTP_ConnectionConfirm.assemble in conpot/protocols/s7comm/cotp.py,
// called by s7_server.py with the references of the request swapped and its two
// TSAPs echoed. The confirm carries no TPDU size parameter even though the
// request does, which is a quirk of that implementation rather than of the
// protocol.
func conpotS7ConnectionConfirm(requestDstRef, requestSrcRef, srcTSAP, dstTSAP uint16) []byte {
	var confirm bytes.Buffer
	be16(&confirm, requestSrcRef)
	be16(&confirm, requestDstRef)
	confirm.WriteByte(0x00) // option field
	confirm.WriteByte(0xC1) // calling TSAP
	confirm.WriteByte(0x02)
	be16(&confirm, srcTSAP)
	confirm.WriteByte(0xC2) // called TSAP
	confirm.WriteByte(0x02)
	be16(&confirm, dstTSAP)

	var cotp bytes.Buffer
	cotp.WriteByte(byte(1 + confirm.Len()))
	cotp.WriteByte(0xD0) // connection confirm
	cotp.Write(confirm.Bytes())

	return conpotTPKT(cotp.Bytes())
}

// conpotCOTPData wraps a payload in a COTP data transfer TPDU, whose length
// indicator is fixed at 2 in cotp.py regardless of payload size.
func conpotCOTPData(payload []byte) []byte {
	var out bytes.Buffer
	out.WriteByte(0x02)
	out.WriteByte(0xF0)
	out.WriteByte(0x80)
	out.Write(payload)
	return out.Bytes()
}

func conpotTPKT(payload []byte) []byte {
	var out bytes.Buffer
	out.WriteByte(0x03) // version
	out.WriteByte(0x00) // reserved
	be16(&out, uint16(len(payload)+4))
	out.Write(payload)
	return out.Bytes()
}

// cipListIdentityResponse builds a List Identity reply carrying one CIP Identity
// item.
//
// Conpot's EtherNet/IP responder delegates its encapsulation layer to cpppo, so
// unlike the two above this is written from the EtherNet/IP specification rather
// than from the emulator's own code, using the field values of Conpot's default
// enip template. The template gives ProductRevision as the single number 2562,
// which occupies the two octet revision field as major 2 and minor 10.
func cipListIdentityResponse(senderContext []byte, reportedIP [4]byte, reportedPort uint16,
	vendorID, deviceType, productCode uint16, revMajor, revMinor byte,
	status uint16, serial uint32, productName string, state byte) []byte {

	var identity bytes.Buffer
	le16(&identity, 1) // encapsulation protocol version

	// The socket address is in network byte order inside an otherwise little
	// endian message, which the specification requires.
	be16(&identity, 2) // AF_INET
	be16(&identity, reportedPort)
	identity.Write(reportedIP[:])
	identity.Write(make([]byte, 8)) // sin_zero

	le16(&identity, vendorID)
	le16(&identity, deviceType)
	le16(&identity, productCode)
	identity.WriteByte(revMajor)
	identity.WriteByte(revMinor)
	le16(&identity, status)
	le32(&identity, serial)
	identity.WriteByte(byte(len(productName)))
	identity.WriteString(productName)
	identity.WriteByte(state)

	var body bytes.Buffer
	le16(&body, 1)      // one item
	le16(&body, 0x000C) // CIP identity item
	le16(&body, uint16(identity.Len()))
	body.Write(identity.Bytes())

	var frame bytes.Buffer
	le16(&frame, 0x0063) // List Identity
	le16(&frame, uint16(body.Len()))
	le32(&frame, 0) // session handle
	le32(&frame, 0) // status
	frame.Write(senderContext)
	le32(&frame, 0) // options
	frame.Write(body.Bytes())
	return frame.Bytes()
}

// bacnetIAm builds the I-Am a device broadcasts in answer to Who-Is.
//
// Written from ASHRAE 135 clause 20, using the field values of Conpot's default
// bacnet template. Conpot serves BACnet through bacpypes, whose encoder follows
// the standard, so the standard is the reference here.
func bacnetIAm(deviceInstance uint32, maxAPDU uint16, segmentation byte, vendorID uint16) []byte {
	var apdu bytes.Buffer
	apdu.WriteByte(0x10) // unconfirmed request
	apdu.WriteByte(0x00) // I-Am

	apdu.WriteByte(0xC4) // application tag 12, object identifier, four octets
	binary.Write(&apdu, binary.BigEndian, uint32(8)<<22|deviceInstance)

	apdu.WriteByte(0x22) // application tag 2, unsigned, two octets
	be16(&apdu, maxAPDU)

	apdu.WriteByte(0x91) // application tag 9, enumerated, one octet
	apdu.WriteByte(segmentation)

	apdu.WriteByte(0x21) // application tag 2, unsigned, one octet
	apdu.WriteByte(byte(vendorID))

	return bacnetBVLL(0x0B, []byte{0x01, 0x00}, apdu.Bytes())
}

// bacnetReadPropertyACK builds the acknowledgement of a ReadProperty whose value
// is a character string.
func bacnetReadPropertyACK(invokeID byte, deviceInstance, property uint32, value string) []byte {
	var apdu bytes.Buffer
	apdu.WriteByte(0x30) // complex acknowledgement
	apdu.WriteByte(invokeID)
	apdu.WriteByte(0x0C) // ReadProperty

	apdu.WriteByte(0x0C) // context tag 0, object identifier
	binary.Write(&apdu, binary.BigEndian, uint32(8)<<22|deviceInstance)

	apdu.WriteByte(0x19) // context tag 1, property identifier, one octet
	apdu.WriteByte(byte(property))

	apdu.WriteByte(0x3E)                 // opening context tag 3
	apdu.WriteByte(0x75)                 // application tag 7, character string, extended length
	apdu.WriteByte(byte(len(value) + 1)) // the length includes the encoding octet
	apdu.WriteByte(0x00)                 // encoding: UTF-8
	apdu.WriteString(value)
	apdu.WriteByte(0x3F) // closing context tag 3

	return bacnetBVLL(0x0A, []byte{0x01, 0x00}, apdu.Bytes())
}

func bacnetBVLL(function byte, npdu, apdu []byte) []byte {
	var out bytes.Buffer
	out.WriteByte(0x81)
	out.WriteByte(function)
	be16(&out, uint16(4+len(npdu)+len(apdu)))
	out.Write(npdu)
	out.Write(apdu)
	return out.Bytes()
}

// openPLCModbusException builds the refusal OpenPLC returns for a function it
// does not implement.
//
// Follows ModbusError in OpenPLC_v3/webserver/core/modbus.cpp, which edits the
// request buffer in place: it sets the length field to three, sets the high bit
// of the function code and appends the error code. Read Device Identification is
// not in the dispatch chain of processModbusMessage, so it falls through to the
// final branch and is answered with ERR_ILLEGAL_FUNCTION.
func openPLCModbusException(transactionID uint16, unitID, functionCode, errorCode byte) []byte {
	var frame bytes.Buffer
	be16(&frame, transactionID)
	be16(&frame, 0)
	be16(&frame, 3)
	frame.WriteByte(unitID)
	frame.WriteByte(functionCode | 0x80)
	frame.WriteByte(errorCode)
	return frame.Bytes()
}

// openPLCReadHoldingRegisters builds a Read Holding Registers reply.
//
// Follows ReadHoldingRegisters in the same file, which sets the length field to
// the data byte count plus three and writes the register values big endian after
// a byte count.
func openPLCReadHoldingRegisters(transactionID uint16, unitID byte, values []uint16) []byte {
	var frame bytes.Buffer
	be16(&frame, transactionID)
	be16(&frame, 0)
	be16(&frame, uint16(len(values)*2+3))
	frame.WriteByte(unitID)
	frame.WriteByte(0x03)
	frame.WriteByte(byte(len(values) * 2))
	for _, value := range values {
		be16(&frame, value)
	}
	return frame.Bytes()
}

// constructedFixtures maps a fixture id to the bytes its cited software emits.
//
// Every fixture whose provenance is "constructed" must appear here, which
// TestEveryConstructedFixtureIsDerivedSomewhere enforces. A captured fixture must
// not: there is nothing to derive, and pretending otherwise would turn a real
// recording into a copy of an assumption.
func constructedFixtures() map[string][]byte {
	// The values Conpot's default template publishes. Read from
	// conpot/templates/default/template.xml and the per protocol files beside
	// it, which the fixtures link to.
	const (
		conpotVendorName  = "Siemens"
		conpotProductCode = "SIMATIC"
		conpotRevision    = "S7-200"

		conpotSystemName        = "Technodrome"
		conpotSystemDescription = "Siemens, SIMATIC, S7-200"
		conpotFacilityName      = "Mouser Factory"
		conpotCopyright         = "Original Siemens Equipment"
		conpotSerial            = "88111222"
		conpotModuleType        = "IM151-8 PN/DP CPU"
	)

	szlRecords := []conpotSZLRecord{
		{0x0001, conpotSystemName},
		{0x0002, conpotSystemDescription},
		{0x0003, conpotFacilityName},
		{0x0004, conpotCopyright},
		{0x0005, conpotSerial},
		{0x0007, conpotModuleType},
		{0x000A, ""}, // the template maps the OEM id to an empty databus key
		{0x000B, ""}, // and the location designation likewise
	}

	modbusDeviceInfo := conpotModbusDeviceInfo(1, 1, 0x01, conpotVendorName, conpotProductCode, conpotRevision)

	return map[string][]byte{
		"conpot-default-modbus-read-device-identification": modbusDeviceInfo,
		"conpot-default-modbus-on-the-template-port":       modbusDeviceInfo,

		"conpot-default-s7comm-component-identification": conpotS7ComponentIdentification(1, 0x0000, szlRecords),
		"conpot-default-s7comm-connection-confirm":       conpotS7ConnectionConfirm(0x0000, 0x0001, 0x0100, 0x0102),

		"conpot-default-enip-list-identity": cipListIdentityResponse(
			[]byte("otscout1"),
			[4]byte{192, 168, 95, 11}, 44818,
			1,     // VendorId
			14,    // DeviceType, a programmable logic controller
			90,    // ProductCode
			2, 10, // ProductRevision 2562 as major and minor
			0x0060,  // status: owned and configured
			7079450, // SerialNumber
			"1756-L61/B LOGIX5561",
			0x03, // device state: operational
		),

		"conpot-default-bacnet-i-am": bacnetIAm(36113, 1024, 0x00, 15),
		"conpot-default-bacnet-model-name": bacnetReadPropertyACK(
			0x01, 36113, 70, "VAV-DD Controller"),

		"openplc-v3-modbus-identification-refused": openPLCModbusException(1, 1, 0x2B, 0x01),
		"openplc-v3-modbus-read-holding-registers": openPLCReadHoldingRegisters(
			0x0AC4, 1, []uint16{0x0000, 0x1F40, 0x0000, 0x0BB8}),

		"http-server-on-the-modbus-port": []byte(
			"HTTP/1.1 200 OK\r\nServer: lighttpd/1.4.35\r\nContent-Length: 0\r\n\r\n"),
	}
}

func TestConstructedFixturesMatchTheEmulatorTheyCite(t *testing.T) {
	fixtures, err := Load()
	if err != nil {
		t.Fatalf("load corpus: %v", err)
	}
	derived := constructedFixtures()

	for _, f := range fixtures {
		if f.Device.Provenance != ProvenanceConstructed {
			continue
		}
		t.Run(f.ID, func(t *testing.T) {
			want, ok := derived[f.ID]
			if !ok {
				t.Fatalf("fixture claims to be constructed but nothing in emulator_test.go derives it.\n"+
					"Add a derivation there, or record the bytes for real and set provenance to %q.",
					ProvenanceCaptured)
			}
			if !bytes.Equal(want, f.Response) {
				t.Fatalf("the fixture no longer matches the software it cites.\n got %x\nwant %x", []byte(f.Response), want)
			}
		})
	}
}

func TestEveryConstructedFixtureIsDerivedSomewhere(t *testing.T) {
	fixtures, err := Load()
	if err != nil {
		t.Fatalf("load corpus: %v", err)
	}

	known := make(map[string]bool, len(fixtures))
	for _, f := range fixtures {
		known[f.ID] = true
	}
	for id := range constructedFixtures() {
		if !known[id] {
			t.Errorf("emulator_test.go derives %q, but no fixture by that name exists", id)
		}
	}
}
