package protocol

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/yoyowpuw/OTScout/internal/asset"
)

func TestS7ConnectionRequestBytes(t *testing.T) {
	got := S7ConnectionRequest(0x0100, 0x0102)
	want := mustHex(t, ""+
		"0300 0016"+ // TPKT version 3, total length 22
		"11 e0 0000 0001 00"+ // COTP connection request
		"c0 01 0a"+ // TPDU size 1024
		"c1 02 0100"+ // calling TSAP
		"c2 02 0102") // called TSAP, rack 0 slot 2
	if hex.EncodeToString(got) != hex.EncodeToString(want) {
		t.Fatalf("request = %x, want %x", got, want)
	}
}

func TestS7SetupCommunicationBytes(t *testing.T) {
	got := S7SetupCommunication(0x0100)
	want := mustHex(t, ""+
		"0300 0019"+ // TPKT, total length 25
		"02 f0 80"+ // COTP data transfer
		"32 01 0000 0100 0008 0000"+ // S7 job header, 8 parameter bytes
		"f0 00 0001 0001 01e0") // setup communication, PDU length 480
	if hex.EncodeToString(got) != hex.EncodeToString(want) {
		t.Fatalf("request = %x, want %x", got, want)
	}
}

func TestS7ReadSZLRequestBytes(t *testing.T) {
	got := S7ReadSZLRequest(0x0200, SZLComponentIdentification, 0x0000)
	want := mustHex(t, ""+
		"0300 0021"+ // TPKT, total length 33
		"02 f0 80"+ // COTP data transfer
		"32 07 0000 0200 0008 0008"+ // S7 user data header
		"00 01 12 04 11 44 01 00"+ // Read SZL request parameters
		"ff 09 0004 001c 0000") // SZL id 0x001C, index 0
	if hex.EncodeToString(got) != hex.EncodeToString(want) {
		t.Fatalf("request = %x, want %x", got, want)
	}
}

func TestS7RequestBuildersEmitOnlyDiagnosticReads(t *testing.T) {
	// The function group and subfunction nibbles decide what the CPU does. This
	// pins them to CPU diagnostics and Read SZL, which is the guarantee that no
	// template can reach a variable write or a PLC stop through this package.
	frame := S7ReadSZLRequest(1, SZLModuleIdentification, 0)
	// Parameters start after the 4 byte TPKT, 3 byte COTP and 10 byte S7 header.
	const paramStart = 4 + 3 + 10
	params := frame[paramStart : paramStart+8]
	if params[4] != 0x11 {
		t.Errorf("method = 0x%02x, want 0x11 (request)", params[4])
	}
	if params[5] != 0x44 {
		t.Errorf("type and function group = 0x%02x, want 0x44 (request, CPU functions)", params[5])
	}
	if params[6] != 0x01 {
		t.Errorf("subfunction = 0x%02x, want 0x01 (Read SZL)", params[6])
	}
}

// szlResponse assembles a Read SZL response frame from records.
//
// The frame is built here from the protocol specification rather than by calling
// into the decoder's helpers, so that a mistake in the decoder cannot be
// cancelled out by the same mistake in the fixture.
func szlResponse(szlID uint16, recordLen int, records [][]byte) []byte {
	body := make([]byte, 0, 8+len(records)*recordLen)
	body = binary.BigEndian.AppendUint16(body, szlID)
	body = binary.BigEndian.AppendUint16(body, 0x0000) // index
	body = binary.BigEndian.AppendUint16(body, uint16(recordLen))
	body = binary.BigEndian.AppendUint16(body, uint16(len(records)))
	for _, record := range records {
		padded := make([]byte, recordLen)
		copy(padded, record)
		body = append(body, padded...)
	}

	data := make([]byte, 0, 4+len(body))
	data = append(data, 0xFF, 0x09)
	data = binary.BigEndian.AppendUint16(data, uint16(len(body)))
	data = append(data, body...)

	params := []byte{0x00, 0x01, 0x12, 0x08, 0x12, 0x84, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00}

	header := make([]byte, 10)
	header[0] = s7ProtocolID
	header[1] = s7ROSCTRUserData
	binary.BigEndian.PutUint16(header[4:6], 0x0200)
	binary.BigEndian.PutUint16(header[6:8], uint16(len(params)))
	binary.BigEndian.PutUint16(header[8:10], uint16(len(data)))

	inner := append([]byte{0x02, cotpDataTransfer, 0x80}, header...)
	inner = append(inner, params...)
	inner = append(inner, data...)

	frame := make([]byte, 4, 4+len(inner))
	frame[0] = tpktVersion
	binary.BigEndian.PutUint16(frame[2:4], uint16(4+len(inner)))
	return append(frame, inner...)
}

// componentRecord builds a 34 byte SZL 0x001C record: a two byte index followed
// by 32 bytes of text.
func componentRecord(index uint16, text string) []byte {
	record := make([]byte, 34)
	binary.BigEndian.PutUint16(record[0:2], index)
	copy(record[2:], text)
	return record
}

// moduleRecord builds a 28 byte SZL 0x0011 record: index, a twenty byte order
// number, then three version words. The firmware version sits in the last three
// bytes.
func moduleRecord(index uint16, orderNumber string, major, minor, patch byte) []byte {
	record := make([]byte, 28)
	binary.BigEndian.PutUint16(record[0:2], index)
	copy(record[2:22], orderNumber)
	record[25] = major
	record[26] = minor
	record[27] = patch
	return record
}

func TestDecodeS7ComponentIdentification(t *testing.T) {
	frame := szlResponse(SZLComponentIdentification, 34, [][]byte{
		componentRecord(0x0001, "MILL-LINE-2-PLC"),
		componentRecord(0x0005, "S C-C2UR28922012"),
		componentRecord(0x0007, "CPU 315-2 PN/DP"),
	})

	obs, err := DecodeS7Response(frame)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}

	wantFields := map[string]string{
		"automation_system_name": "MILL-LINE-2-PLC",
		"module_serial_number":   "S C-C2UR28922012",
		"module_type_name":       "CPU 315-2 PN/DP",
		"szl_id":                 "0x001C",
	}
	for key, want := range wantFields {
		if got := obs.Fields[key]; got != want {
			t.Errorf("Fields[%q] = %q, want %q", key, got, want)
		}
	}

	if obs.Identity.Serial != "S C-C2UR28922012" {
		t.Errorf("Serial = %q", obs.Identity.Serial)
	}
	if obs.Identity.ProductRaw != "CPU 315-2 PN/DP" {
		t.Errorf("ProductRaw = %q, want the module type name", obs.Identity.ProductRaw)
	}
	if obs.Identity.VendorRaw != "Siemens" {
		t.Errorf("VendorRaw = %q, want Siemens", obs.Identity.VendorRaw)
	}
	if obs.Role != asset.RolePLC {
		t.Errorf("Role = %q, want %q", obs.Role, asset.RolePLC)
	}
}

func TestDecodeS7ModuleIdentification(t *testing.T) {
	frame := szlResponse(SZLModuleIdentification, 28, [][]byte{
		moduleRecord(0x0001, "6ES7 315-2EH14-0AB0", 3, 2, 6),
		moduleRecord(0x0006, "6ES7 315-2EH14-0AB0", 0, 0, 0),
	})

	obs, err := DecodeS7Response(frame)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got := obs.Fields["module_order_number"]; got != "6ES7 315-2EH14-0AB0" {
		t.Errorf("module_order_number = %q", got)
	}
	if got := obs.Fields["module_firmware_version"]; got != "V3.2.6" {
		t.Errorf("module_firmware_version = %q, want V3.2.6", got)
	}
	// The order number is what feeds the MLFB parser, so it has to land on the
	// catalog number field.
	if obs.Identity.CatalogNumber != "6ES7 315-2EH14-0AB0" {
		t.Errorf("CatalogNumber = %q", obs.Identity.CatalogNumber)
	}
	if obs.Identity.Firmware != "V3.2.6" {
		t.Errorf("Firmware = %q", obs.Identity.Firmware)
	}
}

func TestDecodeS7ConnectionConfirmIsAFingerprintOnItsOwn(t *testing.T) {
	// Accepting an ISO-on-TCP connection on port 102 already narrows a device to
	// the S7 family, before any S7 exchange happens.
	frame := mustHex(t, "0300 0016 11 d0 0001 0002 00 c0 01 0a c1 02 0100 c2 02 0102")
	obs, err := DecodeS7Response(frame)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if obs.Fields["cotp_response"] != "connection confirm" {
		t.Errorf("Fields = %v", obs.Fields)
	}
	if len(obs.Notes) == 0 {
		t.Error("the decoder should say what a connection confirm implies")
	}
}

func TestDecodeS7ReportsErrorClassAndCode(t *testing.T) {
	// An acknowledgement with a non zero error class must surface as an error
	// rather than being read as data.
	frame := mustHex(t, ""+
		"0300 0016"+
		"02 f0 80"+
		"32 03 0000 0100 0002 0000"+ // ack data header
		"81 04"+ // error class 0x81, code 0x04
		"0000") // parameters
	_, err := DecodeS7Response(frame)

	var devErr *ErrDeviceError
	if !errors.As(err, &devErr) {
		t.Fatalf("err = %v, want an ErrDeviceError", err)
	}
	if devErr.Code != 0x8104 {
		t.Errorf("code = 0x%04x, want 0x8104", devErr.Code)
	}
}

func TestDecodeS7RejectsForeignPayloads(t *testing.T) {
	for name, payload := range map[string]string{
		"wrong tpkt version": "0400 0016 11 d0 0001 0002 00",
		"implausible length": "0300 ffff 11 d0",
		"too short":          "0300",
		"empty":              "",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeS7Response(mustHex(t, payload)); !errors.Is(err, ErrNotThisProtocol) {
				t.Errorf("err = %v, want ErrNotThisProtocol", err)
			}
		})
	}
}

func TestDecodeS7RejectsImplausibleRecordLength(t *testing.T) {
	// A device claiming a record larger than the frame is either broken or
	// trying to make the decoder allocate. Either way it must be refused.
	frame := szlResponse(SZLComponentIdentification, 34, [][]byte{
		componentRecord(0x0001, "NAME"),
	})
	// Overwrite the record length field with an absurd value. It sits after the
	// TPKT, COTP, S7 header, parameters, the four data prologue bytes, the SZL id
	// and the SZL index.
	offset := 4 + 3 + 10 + 12 + 4 + 2 + 2
	binary.BigEndian.PutUint16(frame[offset:offset+2], 0xFFFF)

	if _, err := DecodeS7Response(frame); !errors.Is(err, ErrTruncated) {
		t.Errorf("err = %v, want ErrTruncated", err)
	}
}
