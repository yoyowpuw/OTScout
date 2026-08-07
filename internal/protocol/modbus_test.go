package protocol

import (
	"encoding/hex"
	"errors"
	"strings"
	"testing"
)

// mustHex decodes a hex string written for readability, with spaces allowed
// between fields.
func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	cleaned := strings.NewReplacer(" ", "", "\n", "", "\t", "").Replace(s)
	out, err := hex.DecodeString(cleaned)
	if err != nil {
		t.Fatalf("bad hex in test fixture: %v", err)
	}
	return out
}

func TestModbusDeviceIDRequestBytes(t *testing.T) {
	got := ModbusDeviceIDRequest(1, 1, ModbusReadBasic)
	want := mustHex(t, "0001 0000 0005 01 2b 0e 01 00")
	if hex.EncodeToString(got) != hex.EncodeToString(want) {
		t.Fatalf("request = %x, want %x", got, want)
	}
	// The length field counts the unit id plus the PDU, which is the part most
	// easily got wrong.
	if got[5] != 0x05 {
		t.Errorf("length field = %d, want 5", got[5])
	}
}

func TestModbusRequestIsAlwaysTheIdentificationFunction(t *testing.T) {
	// An out of range read code must be clamped rather than passed through,
	// because the only bytes this package may emit are a device identification
	// read. There is deliberately no way to reach any other function code.
	//
	// Every value is tried rather than a handful, because the read code arrives
	// from a YAML template as a number and the property has to hold for numbers
	// nobody thought of.
	for code := 0; code <= 0xFF; code++ {
		frame := ModbusDeviceIDRequest(7, 2, byte(code))
		if frame[7] != modbusFCReadDeviceID {
			t.Fatalf("read code 0x%02x: function code = 0x%02x, want 0x2b", code, frame[7])
		}
		if frame[8] != modbusMEIDeviceID {
			t.Fatalf("read code 0x%02x: MEI type = 0x%02x, want 0x0e", code, frame[8])
		}
		switch frame[9] {
		case ModbusReadBasic, ModbusReadRegular, ModbusReadExtended:
		default:
			t.Fatalf("read code 0x%02x was not clamped to a documented value", frame[9])
		}
	}
}

// wagoDeviceIDResponse is a Read Device Identification response carrying three
// basic objects: vendor name, product code and revision.
func wagoDeviceIDResponse(t *testing.T) []byte {
	t.Helper()
	return mustHex(t, ""+
		"0001 0000 0022 01"+ // MBAP: transaction 1, protocol 0, length 34, unit 1
		"2b 0e 01 02 00 00 03"+ // FC 43, MEI 14, basic read, conformity 2, no more, next 0, three objects
		"00 04 57 41 47 4f"+ // object 0x00 vendor name "WAGO"
		"01 08 37 35 30 2d 38 32 30 32"+ // object 0x01 product code "750-8202"
		"02 08 30 31 2e 30 32 2e 30 33") // object 0x02 revision "01.02.03"
}

func TestDecodeModbusDeviceIdentification(t *testing.T) {
	obs, err := DecodeModbusResponse(wagoDeviceIDResponse(t))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if obs.Protocol != NameModbus {
		t.Errorf("Protocol = %q", obs.Protocol)
	}

	wantFields := map[string]string{
		"vendor_name":          "WAGO",
		"product_code":         "750-8202",
		"major_minor_revision": "01.02.03",
		"unit_id":              "1",
	}
	for key, want := range wantFields {
		if got := obs.Fields[key]; got != want {
			t.Errorf("Fields[%q] = %q, want %q", key, got, want)
		}
	}

	if obs.Identity.VendorRaw != "WAGO" {
		t.Errorf("VendorRaw = %q, want WAGO", obs.Identity.VendorRaw)
	}
	if obs.Identity.FirmwareRaw != "01.02.03" {
		t.Errorf("FirmwareRaw = %q, want 01.02.03", obs.Identity.FirmwareRaw)
	}
	// The product code field is where most devices put their order code, and the
	// catalog parsers expect to find it there.
	if obs.Identity.CatalogNumber != "750-8202" {
		t.Errorf("CatalogNumber = %q, want 750-8202", obs.Identity.CatalogNumber)
	}
}

func TestDecodeModbusExceptionStillIdentifiesTheProtocol(t *testing.T) {
	// A device that refuses the request has still told us it speaks Modbus, so
	// the decoder must report the error without discarding that fact.
	frame := mustHex(t, "0001 0000 0003 01 ab 01")
	obs, err := DecodeModbusResponse(frame)

	var devErr *ErrDeviceError
	if !errors.As(err, &devErr) {
		t.Fatalf("err = %v, want an ErrDeviceError", err)
	}
	if devErr.Code != 1 {
		t.Errorf("exception code = %d, want 1", devErr.Code)
	}
	if obs.Fields["exception_code"] != "1" {
		t.Errorf("the exception must be recorded as a field, got %v", obs.Fields)
	}
	if len(obs.Notes) == 0 {
		t.Error("the decoder should explain what the exception means")
	}
}

func TestDecodeModbusRejectsForeignPayloads(t *testing.T) {
	cases := map[string]string{
		"non zero protocol id": "0001 0001 0005 01 2b 0e 01 00",
		"implausible length":   "0001 0000 ffff 01 2b 0e 01 00",
		"empty":                "",

		// HART-IP, taken from a real capture. Its own header puts zeroes where
		// Modbus keeps the protocol id, so the only thing separating the two is
		// that the Modbus length field would have to account for the rest of the
		// frame and here it does not: it claims two bytes of a thirteen byte
		// payload. Before this was checked, a HART gateway was inventoried as a
		// Modbus device answering function 13.
		"hart-ip on its own port": "0101 0000 0002 00 0d 01 00 00 ea 60",
	}
	for name, payload := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeModbusResponse(mustHex(t, payload)); !errors.Is(err, ErrNotThisProtocol) {
				t.Errorf("err = %v, want ErrNotThisProtocol", err)
			}
		})
	}
}

// TestDecodeModbusTreatsAPartialFrameAsTruncated separates an incomplete frame
// from a foreign one.
//
// A response split across two TCP segments is ordinary, and the caller's answer
// to truncation is to hold the bytes and wait for the rest. Reporting such a
// payload as a different protocol would lose the identity of every device whose
// reply happened to cross a segment boundary.
func TestDecodeModbusTreatsAPartialFrameAsTruncated(t *testing.T) {
	cases := map[string]string{
		"header cut in half":      "0001 0000",
		"body has not arrived":    "0001 0000 0022 01 2b 0e",
		"second frame just began": "0001 0000 0005 01 03 02 00 7b 0002",
	}
	for name, payload := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeModbusResponse(mustHex(t, payload)); !errors.Is(err, ErrTruncated) {
				t.Errorf("err = %v, want ErrTruncated", err)
			}
		})
	}
}

func TestDecodeModbusSurvivesTruncatedObjectList(t *testing.T) {
	// A device whose object length field overruns the frame it declared. The
	// header is honest, so there is nothing more to wait for and the decoder has
	// to keep what it read rather than panic or invent the rest.
	frame := mustHex(t, ""+
		"0001 0000 0013 01"+
		"2b 0e 01 02 00 00 03"+
		"00 04 57 41 47 4f"+
		"01 08 37 35 30") // declares 8 bytes but supplies 3

	obs, err := DecodeModbusResponse(frame)
	if err != nil {
		t.Fatalf("a truncated object list should not be a hard error: %v", err)
	}
	if obs.Fields["vendor_name"] != "WAGO" {
		t.Errorf("the objects read before truncation must be kept, got %v", obs.Fields)
	}
	if len(obs.Notes) == 0 {
		t.Error("truncation must be noted")
	}
}

func TestDecodeModbusIgnoresUnprintableFieldContent(t *testing.T) {
	// Field content reaches HTML reports and terminals, so control bytes must
	// never survive decoding.
	frame := mustHex(t, ""+
		"0001 0000 000e 01"+
		"2b 0e 01 02 00 00 01"+
		"00 04 57 01 1b 4f") // "W", 0x01, 0x1b, "O"

	obs, err := DecodeModbusResponse(frame)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	value := obs.Fields["vendor_name"]
	for _, r := range value {
		if r < 0x20 || r > 0x7e {
			t.Fatalf("decoded field %q still contains a control byte", value)
		}
	}
}

func TestDecodeModbusNonIdentificationFunction(t *testing.T) {
	// A Read Holding Registers response found in a capture is not an error, it
	// simply carries no identity.
	frame := mustHex(t, "0001 0000 0005 01 03 02 00 7b")
	obs, err := DecodeModbusResponse(frame)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !obs.Identity.Empty() {
		t.Error("a register read must not produce an identity")
	}
	if obs.Fields["function_code"] != "3" {
		t.Errorf("the function code should be recorded, got %v", obs.Fields)
	}
}
