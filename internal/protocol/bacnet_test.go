package protocol

import (
	"encoding/hex"
	"errors"
	"testing"

	"github.com/yoyowpuw/OTScout/internal/asset"
)

func TestBACnetReadPropertyRequestBytes(t *testing.T) {
	got := BACnetReadPropertyRequest(1, BACnetPropVendorName)
	want := mustHex(t, ""+
		"81 0a 0011"+ // BVLL original unicast, total length 17
		"01 04"+ // NPDU version 1, expecting a reply
		"00 05 01 0c"+ // confirmed request, 1476 octet APDU, invoke 1, ReadProperty
		"0c 023fffff"+ // context tag 0: device object, wildcard instance
		"19 79") // context tag 1: property 121, vendor-name
	if hex.EncodeToString(got) != hex.EncodeToString(want) {
		t.Fatalf("request = %x, want %x", got, want)
	}
}

func TestBACnetWhoIsRequestBytes(t *testing.T) {
	got := BACnetWhoIsRequest()
	want := mustHex(t, ""+
		"81 0b 000c"+ // BVLL original broadcast, total length 12
		"01 20 ffff 00 ff"+ // NPDU with a global broadcast destination and hop count
		"10 08") // unconfirmed request, Who-Is
	if hex.EncodeToString(got) != hex.EncodeToString(want) {
		t.Fatalf("request = %x, want %x", got, want)
	}
}

func TestBACnetRequestBuildersEmitOnlyReadServices(t *testing.T) {
	// WriteProperty is service 15, ReinitializeDevice is 20 and
	// DeviceCommunicationControl is 17. None of them can be produced here, and
	// the two builders that exist must only ever emit ReadProperty and Who-Is.
	readFrame := BACnetReadPropertyRequest(9, BACnetPropModelName)
	if service := readFrame[9]; service != bacnetServiceReadProperty {
		t.Errorf("service = %d, want %d (ReadProperty)", service, bacnetServiceReadProperty)
	}
	whoIs := BACnetWhoIsRequest()
	if service := whoIs[11]; service != bacnetServiceWhoIs {
		t.Errorf("service = %d, want %d (Who-Is)", service, bacnetServiceWhoIs)
	}
}

func TestDecodeBACnetReadPropertyACKExtendedString(t *testing.T) {
	// A character string whose total length reaches five octets uses the extended
	// length form, which is the common case for real property values.
	frame := mustHex(t, ""+
		"81 0a 0027"+ // total length 39
		"01 00"+ // NPDU, no addressing
		"30 01 0c"+ // complex ack, invoke 1, ReadProperty
		"0c 023fffff"+ // object identifier
		"19 79"+ // property 121, vendor-name
		"3e"+ // opening tag 3
		"75 13 00"+ // character string, extended length 19, UTF-8 encoding
		"536368 6e6569 646572 20456c 656374 726963"+ // "Schneider Electric"
		"3f") // closing tag 3

	obs, err := DecodeBACnetResponse(frame)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got := obs.Fields["vendor_name"]; got != "Schneider Electric" {
		t.Errorf("vendor_name = %q, want Schneider Electric", got)
	}
	if obs.Identity.VendorRaw != "Schneider Electric" {
		t.Errorf("VendorRaw = %q", obs.Identity.VendorRaw)
	}
	if obs.Role != asset.RoleBuildingAC {
		t.Errorf("Role = %q, want %q", obs.Role, asset.RoleBuildingAC)
	}
}

func TestDecodeBACnetReadPropertyACKShortString(t *testing.T) {
	// A string short enough to fit the inline length field takes a different
	// decoding path and has to work equally well.
	frame := mustHex(t, ""+
		"81 0a 0017"+ // total length 23
		"01 00"+
		"30 02 0c"+
		"0c 023fffff"+
		"19 2c"+ // property 44, firmware-revision
		"3e"+
		"74 00 322e37"+ // character string, inline length 4, "2.7"
		"3f")

	obs, err := DecodeBACnetResponse(frame)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got := obs.Fields["firmware_revision"]; got != "2.7" {
		t.Errorf("firmware_revision = %q, want 2.7", got)
	}
	if obs.Identity.Firmware != "2.7" {
		t.Errorf("Firmware = %q, want 2.7", obs.Identity.Firmware)
	}
}

func TestDecodeBACnetIAm(t *testing.T) {
	frame := mustHex(t, ""+
		"81 0b 0019"+ // total length 25
		"01 20 ffff 00 ff"+ // NPDU with a global broadcast destination
		"10 00"+ // unconfirmed request, I-Am
		"c4 02000064"+ // object identifier: device, instance 100
		"22 01e0"+ // unsigned: maximum APDU 480
		"91 00"+ // enumerated: segmentation supported
		"22 0005") // unsigned: vendor identifier 5

	obs, err := DecodeBACnetResponse(frame)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got := obs.Fields["device_instance"]; got != "100" {
		t.Errorf("device_instance = %q, want 100", got)
	}
	if got := obs.Fields["vendor_identifier"]; got != "5" {
		t.Errorf("vendor_identifier = %q, want 5", got)
	}
	if obs.Role != asset.RoleBuildingAC {
		t.Errorf("Role = %q, want %q", obs.Role, asset.RoleBuildingAC)
	}
}

func TestDecodeBACnetErrorPDU(t *testing.T) {
	frame := mustHex(t, ""+
		"81 0a 000d"+ // total length 13
		"01 00"+
		"50 01 0c"+ // error PDU, invoke 1, ReadProperty
		"91 05"+ // enumerated error class 5, property
		"91 20") // enumerated error code 32, unknown property

	obs, err := DecodeBACnetResponse(frame)

	var devErr *ErrDeviceError
	if !errors.As(err, &devErr) {
		t.Fatalf("err = %v, want an ErrDeviceError", err)
	}
	if devErr.Code != 32 {
		t.Errorf("error code = %d, want 32", devErr.Code)
	}
	if obs.Fields["error_class"] != "5" {
		t.Errorf("error_class = %q, want 5", obs.Fields["error_class"])
	}
	if len(obs.Notes) == 0 {
		t.Error("an error response should still record that the device speaks BACnet")
	}
}

func TestDecodeBACnetRejectPDU(t *testing.T) {
	frame := mustHex(t, ""+
		"81 0a 0009"+ // total length 9
		"01 00"+
		"60 01 09") // reject PDU, invoke 1, reason 9

	obs, err := DecodeBACnetResponse(frame)

	var devErr *ErrDeviceError
	if !errors.As(err, &devErr) {
		t.Fatalf("err = %v, want an ErrDeviceError", err)
	}
	if devErr.Code != 9 {
		t.Errorf("reject reason = %d, want 9", devErr.Code)
	}
	if obs.Fields["reject_reason"] != "9" {
		t.Errorf("reject_reason = %q", obs.Fields["reject_reason"])
	}
}

func TestDecodeBACnetRejectsForeignPayloads(t *testing.T) {
	for name, payload := range map[string]string{
		"wrong bvll type":    "82 0a 0009 01 00 60 01 09",
		"wrong npdu version": "81 0a 0009 02 00 60 01 09",
		"implausible length": "81 0a ffff 01 00",
		"too short":          "81 0a",
		"empty":              "",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeBACnetResponse(mustHex(t, payload)); !errors.Is(err, ErrNotThisProtocol) {
				t.Errorf("err = %v, want ErrNotThisProtocol", err)
			}
		})
	}
}

func TestDecodeBACnetTruncatedValueDoesNotPanic(t *testing.T) {
	// A value that declares more bytes than the frame holds is exactly the shape
	// of input that turns an unchecked decoder into a crash.
	frame := mustHex(t, ""+
		"81 0a 0016"+
		"01 00"+
		"30 01 0c"+
		"0c 023fffff"+
		"19 79"+
		"3e"+
		"75 40 00 41 42") // declares 64 octets, supplies three

	if _, err := DecodeBACnetResponse(frame); !errors.Is(err, ErrTruncated) {
		t.Errorf("err = %v, want ErrTruncated", err)
	}
}

func TestEncodeUnsignedUsesFewestOctets(t *testing.T) {
	cases := map[uint32]int{
		0:        1,
		255:      1,
		256:      2,
		65535:    2,
		65536:    3,
		16777216: 4,
	}
	for value, wantLen := range cases {
		if got := encodeUnsigned(value); len(got) != wantLen {
			t.Errorf("encodeUnsigned(%d) used %d octets, want %d", value, len(got), wantLen)
		}
	}
}
