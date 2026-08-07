package protocol

import (
	"encoding/hex"
	"errors"
	"testing"

	"github.com/yoyowpuw/OTScout/internal/asset"
)

func TestENIPListIdentityRequestBytes(t *testing.T) {
	got := ENIPListIdentityRequest([8]byte{1, 2, 3, 4, 5, 6, 7, 8})
	want := mustHex(t, ""+
		"6300"+ // command 0x0063, little endian
		"0000"+ // length, zero in a request
		"00000000"+ // session handle
		"00000000"+ // status
		"0102030405060708"+ // sender context
		"00000000") // options
	if hex.EncodeToString(got) != hex.EncodeToString(want) {
		t.Fatalf("request = %x, want %x", got, want)
	}
	if len(got) != enipHeaderLen {
		t.Errorf("length = %d, want %d", len(got), enipHeaderLen)
	}
}

// controlLogixListIdentity is a List Identity reply from a ControlLogix
// controller, with a single CIP identity item.
func controlLogixListIdentity(t *testing.T) []byte {
	t.Helper()
	return mustHex(t, ""+
		// Encapsulation header. Length 0x003C is the 60 bytes of item data.
		"6300 3c00 00000000 00000000 0102030405060708 00000000"+
		"0100"+ // item count: 1
		"0c00"+ // item type: CIP identity
		"3600"+ // item length: 54
		"0100"+ // encapsulation protocol version 1
		// Socket address, in network byte order inside a little endian message.
		"0002 af12 0a0a0005 0000000000000000"+
		"0100"+ // ODVA vendor id 1
		"0e00"+ // device type 14, programmable logic controller
		"5a00"+ // product code 90
		"140b"+ // revision 20.11
		"3000"+ // device status
		"78563412"+ // serial number 0x12345678, little endian
		"14"+ // product name length 20
		"313735362 d4c37312f42204c4f47495835353731"+ // "1756-L71/B LOGIX5571"
		"03") // device state
}

func TestDecodeENIPListIdentity(t *testing.T) {
	obs, err := DecodeENIPResponse(controlLogixListIdentity(t))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}

	wantFields := map[string]string{
		"vendor_id":        "1",
		"device_type":      "14",
		"device_type_name": "Programmable Logic Controller",
		"product_code":     "90",
		"revision":         "20.11",
		"serial_number":    "12345678",
		"product_name":     "1756-L71/B LOGIX5571",
	}
	for key, want := range wantFields {
		if got := obs.Fields[key]; got != want {
			t.Errorf("Fields[%q] = %q, want %q", key, got, want)
		}
	}

	if obs.Role != asset.RolePLC {
		t.Errorf("Role = %q, want %q", obs.Role, asset.RolePLC)
	}
	if obs.Identity.Firmware != "20.11" {
		t.Errorf("Firmware = %q, want 20.11", obs.Identity.Firmware)
	}
	// The catalog number is what the Rockwell parser needs, and the device only
	// supplies it embedded in the product name.
	if obs.Identity.CatalogNumber != "1756-L71" {
		t.Errorf("CatalogNumber = %q, want 1756-L71", obs.Identity.CatalogNumber)
	}
	if obs.Identity.VendorRaw != "Rockwell Automation/Allen-Bradley" {
		t.Errorf("VendorRaw = %q", obs.Identity.VendorRaw)
	}
	if obs.Fields["reported_socket_address"] != "10.10.0.5:44818" {
		t.Errorf("reported_socket_address = %q", obs.Fields["reported_socket_address"])
	}
}

func TestDecodeENIPUnknownVendorIDFallsBackToProductName(t *testing.T) {
	// The local ODVA table is deliberately incomplete. An unmapped vendor id must
	// be noted rather than guessed, and the product name still carries the model.
	// The encapsulation length is 47: two bytes of item count, four bytes of item
	// header, and a 41 byte identity body.
	frame := mustHex(t, ""+
		"6300 2f00 00000000 00000000 0000000000000000 00000000"+
		"0100 0c00 2900"+
		"0100"+
		"0002 af12 0a0a0006 0000000000000000"+
		"e903"+ // vendor id 1001, not in the local table
		"0c00 0100 0102 0000 01000000"+
		"07"+ // product name length 7
		"4d4f5841204f4b"+ // "MOXA OK"
		"03")

	obs, err := DecodeENIPResponse(frame)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if obs.Identity.VendorRaw != "" {
		t.Errorf("VendorRaw = %q, want empty for an unmapped vendor id", obs.Identity.VendorRaw)
	}
	if obs.Fields["product_name"] != "MOXA OK" {
		t.Errorf("product_name = %q", obs.Fields["product_name"])
	}
	if len(obs.Notes) == 0 {
		t.Error("an unmapped vendor id must be noted so the gap is visible")
	}
}

func TestDecodeENIPReportsEncapsulationError(t *testing.T) {
	frame := mustHex(t, ""+
		"6300 0000 00000000 01000000 0000000000000000 00000000")
	_, err := DecodeENIPResponse(frame)

	var devErr *ErrDeviceError
	if !errors.As(err, &devErr) {
		t.Fatalf("err = %v, want an ErrDeviceError", err)
	}
	if devErr.Code != 1 {
		t.Errorf("status = %d, want 1", devErr.Code)
	}
}

func TestDecodeENIPRejectsForeignPayloads(t *testing.T) {
	for name, payload := range map[string]string{
		"too short": "6300 0000",
		"empty":     "",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeENIPResponse(mustHex(t, payload)); !errors.Is(err, ErrNotThisProtocol) {
				t.Errorf("err = %v, want ErrNotThisProtocol", err)
			}
		})
	}
}

func TestDecodeENIPOtherCommandCarriesNoIdentity(t *testing.T) {
	// A RegisterSession reply seen in a capture is valid but says nothing about
	// what the device is.
	frame := mustHex(t, ""+
		"6500 0400 01000000 00000000 0000000000000000 00000000 01000000")
	obs, err := DecodeENIPResponse(frame)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !obs.Identity.Empty() {
		t.Error("a session registration must not produce an identity")
	}
	if obs.Fields["encapsulation_command"] != "0x0065" {
		t.Errorf("the command should be recorded, got %v", obs.Fields)
	}
}

func TestLeadingCatalogToken(t *testing.T) {
	cases := map[string]string{
		"1756-L71/B LOGIX5571": "1756-L71",
		"1756-L83E/B":          "1756-L83E",
		"750-8202 PFC200":      "750-8202",
		"PowerFlex 525":        "",
		"LOGIX5571":            "",
		"":                     "",
		"AB-12":                "",
	}
	for input, want := range cases {
		if got := leadingCatalogToken(input); got != want {
			t.Errorf("leadingCatalogToken(%q) = %q, want %q", input, got, want)
		}
	}
}
