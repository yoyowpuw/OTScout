package asset

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
)

// HexBytes is a byte slice that serialises as a lowercase hex string rather
// than base64. Raw protocol bytes are read by humans reviewing an evidence
// trail or a dry run, and hex is the representation every protocol analyst
// already thinks in.
type HexBytes []byte

// MarshalJSON writes the bytes as a hex string.
func (h HexBytes) MarshalJSON() ([]byte, error) {
	if h == nil {
		return []byte("null"), nil
	}
	return json.Marshal(hex.EncodeToString(h))
}

// UnmarshalJSON accepts a hex string.
func (h *HexBytes) UnmarshalJSON(data []byte) error {
	if string(data) == "null" {
		*h = nil
		return nil
	}
	var encoded string
	if err := json.Unmarshal(data, &encoded); err != nil {
		return fmt.Errorf("hex bytes must be a string: %w", err)
	}
	encoded = strings.ReplaceAll(encoded, " ", "")
	decoded, err := hex.DecodeString(encoded)
	if err != nil {
		return fmt.Errorf("decode hex bytes: %w", err)
	}
	*h = decoded
	return nil
}

// String renders space separated hex octets, the form used in dry run output.
func (h HexBytes) String() string {
	if len(h) == 0 {
		return ""
	}
	parts := make([]string, len(h))
	for i, b := range h {
		parts[i] = fmt.Sprintf("%02x", b)
	}
	return strings.Join(parts, " ")
}

// HexDump renders an offset, hex and printable ASCII listing. The active probe
// dry run prints this so an engineer can inspect every byte before approving a
// scan against production equipment.
func (h HexBytes) HexDump() string {
	if len(h) == 0 {
		return ""
	}
	const width = 16
	var sb strings.Builder
	for offset := 0; offset < len(h); offset += width {
		end := offset + width
		if end > len(h) {
			end = len(h)
		}
		chunk := h[offset:end]

		fmt.Fprintf(&sb, "%04x  ", offset)
		for i := 0; i < width; i++ {
			if i < len(chunk) {
				fmt.Fprintf(&sb, "%02x ", chunk[i])
			} else {
				sb.WriteString("   ")
			}
			if i == width/2-1 {
				sb.WriteString(" ")
			}
		}
		sb.WriteString(" |")
		for _, b := range chunk {
			if b >= 0x20 && b < 0x7f {
				sb.WriteByte(b)
			} else {
				sb.WriteByte('.')
			}
		}
		sb.WriteString("|\n")
	}
	return sb.String()
}
