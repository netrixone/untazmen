package tzsp_test

import (
	"errors"
	"testing"

	"github.com/netrixone/untazmen/tzsp"
)

// buildPacket constructs a minimal TZSP datagram with the given tagged fields
// followed by a payload. tags is a raw byte slice of the tag region
// (caller is responsible for including a tagEnd byte if desired).
func buildPacket(version, typ uint8, proto uint16, tags, payload []byte) []byte {
	hdr := []byte{version, typ, byte(proto >> 8), byte(proto & 0xff)}
	pkt := append(hdr, tags...)
	return append(pkt, payload...)
}

func TestParseHeaderValid(t *testing.T) {
	data := []byte{1, 0, 0x00, 0x01, 0x01} // v1, received, Ethernet, End
	hdr, err := tzsp.ParseHeader(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if hdr.Version != 1 {
		t.Errorf("Version = %d, want 1", hdr.Version)
	}
	if hdr.Type != tzsp.TypeReceivedPacket {
		t.Errorf("Type = %d, want %d", hdr.Type, tzsp.TypeReceivedPacket)
	}
	if hdr.Protocol != tzsp.ProtoEthernet {
		t.Errorf("Protocol = 0x%04x, want 0x%04x", hdr.Protocol, tzsp.ProtoEthernet)
	}
}

func TestParseHeaderTooShort(t *testing.T) {
	for _, n := range []int{0, 1, 2, 3} {
		_, err := tzsp.ParseHeader(make([]byte, n))
		if !errors.Is(err, tzsp.ErrTooShort) {
			t.Errorf("len=%d: got %v, want ErrTooShort", n, err)
		}
	}
}

// TestParsePayloadSimple tests the minimal valid datagram:
// 4-byte header + End tag + inner payload.
func TestParsePayloadSimple(t *testing.T) {
	inner := []byte{0xde, 0xad, 0xbe, 0xef}
	// version=1, type=0, proto=0x0001, End tag (0x01), then payload
	tags := []byte{0x01} // tagEnd
	pkt := buildPacket(1, 0, tzsp.ProtoEthernet, tags, inner)

	got, err := tzsp.ParsePayload(pkt)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(got) != string(inner) {
		t.Errorf("payload = %x, want %x", got, inner)
	}
}

// TestParsePayloadWithPadding ensures padding bytes (0x00) are skipped.
func TestParsePayloadWithPadding(t *testing.T) {
	inner := []byte{0xca, 0xfe}
	// Three padding bytes, then End, then payload
	tags := []byte{0x00, 0x00, 0x00, 0x01}
	pkt := buildPacket(1, 0, tzsp.ProtoEthernet, tags, inner)

	got, err := tzsp.ParsePayload(pkt)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(got) != string(inner) {
		t.Errorf("payload = %x, want %x", got, inner)
	}
}

// TestParsePayloadWithVariableTags ensures variable-length tags are skipped correctly.
func TestParsePayloadWithVariableTags(t *testing.T) {
	inner := []byte{0x11, 0x22, 0x33}
	// tag=0x0a, length=3, value=3 bytes, then End
	tags := []byte{0x0a, 0x03, 0xaa, 0xbb, 0xcc, 0x01}
	pkt := buildPacket(1, 0, tzsp.ProtoEthernet, tags, inner)

	got, err := tzsp.ParsePayload(pkt)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(got) != string(inner) {
		t.Errorf("payload = %x, want %x", got, inner)
	}
}

func TestParsePayloadInvalidVersion(t *testing.T) {
	pkt := buildPacket(2, 0, tzsp.ProtoEthernet, []byte{0x01}, nil)
	_, err := tzsp.ParsePayload(pkt)
	if !errors.Is(err, tzsp.ErrInvalidVersion) {
		t.Errorf("got %v, want ErrInvalidVersion", err)
	}
}

func TestParsePayloadTooShort(t *testing.T) {
	for _, n := range []int{0, 1, 2, 3} {
		_, err := tzsp.ParsePayload(make([]byte, n))
		if !errors.Is(err, tzsp.ErrTooShort) {
			t.Errorf("len=%d: got %v, want ErrTooShort", n, err)
		}
	}
}

func TestParsePayloadNoEndTag(t *testing.T) {
	// Only has padding, no End tag
	pkt := buildPacket(1, 0, tzsp.ProtoEthernet, []byte{0x00, 0x00}, nil)
	_, err := tzsp.ParsePayload(pkt)
	if !errors.Is(err, tzsp.ErrNoEndTag) {
		t.Errorf("got %v, want ErrNoEndTag", err)
	}
}

func TestParsePayloadTruncatedVariableTag(t *testing.T) {
	// tag=0x0a, length=10, but only 2 value bytes follow (truncated)
	tags := []byte{0x0a, 0x0a, 0xaa, 0xbb}
	pkt := buildPacket(1, 0, tzsp.ProtoEthernet, tags, nil)
	_, err := tzsp.ParsePayload(pkt)
	if !errors.Is(err, tzsp.ErrTruncated) {
		t.Errorf("got %v, want ErrTruncated", err)
	}
}

func TestParsePayloadTruncatedLengthByte(t *testing.T) {
	// tag=0x0a with no length byte following
	tags := []byte{0x0a}
	pkt := buildPacket(1, 0, tzsp.ProtoEthernet, tags, nil)
	_, err := tzsp.ParsePayload(pkt)
	if !errors.Is(err, tzsp.ErrTruncated) {
		t.Errorf("got %v, want ErrTruncated", err)
	}
}

func TestLooksLikeTZSP(t *testing.T) {
	validPacket := func() []byte {
		// version=1, type=0 (RX), proto=0x0001 (Ethernet), End tag, payload
		return []byte{0x01, 0x00, 0x00, 0x01, 0x01, 0xde, 0xad}
	}

	tests := []struct {
		name string
		data []byte
		want bool
	}{
		{"valid RX packet", validPacket(), true},
		{"valid TX packet", func() []byte { p := validPacket(); p[1] = 0x01; return p }(), true},
		{"valid Config packet", func() []byte { p := validPacket(); p[1] = 0x03; return p }(), true},
		{"valid Keepalive", func() []byte { p := validPacket(); p[1] = 0x04; return p }(), true},
		{"valid PortCloser", func() []byte { p := validPacket(); p[1] = 0x05; return p }(), true},
		{"valid 802.11 protocol", func() []byte {
			p := validPacket()
			p[2] = 0x00
			p[3] = 0x12
			return p
		}(), true},
		{"valid Prism protocol", func() []byte {
			p := validPacket()
			p[2] = 0x00
			p[3] = 0x77
			return p
		}(), true},
		{"valid WLAN AVS protocol", func() []byte {
			p := validPacket()
			p[2] = 0x7F
			p[3] = 0x20
			return p
		}(), true},
		{"with padding tags", func() []byte {
			return []byte{0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x01, 0xde}
		}(), true},
		{"with variable tag", func() []byte {
			return []byte{0x01, 0x00, 0x00, 0x01, 0x0a, 0x02, 0xaa, 0xbb, 0x01, 0xde}
		}(), true},
		{"too short (4 bytes)", make([]byte, 4), false},
		{"too short (0 bytes)", []byte{}, false},
		{"wrong version", func() []byte { p := validPacket(); p[0] = 0x02; return p }(), false},
		{"unknown type (2)", func() []byte { p := validPacket(); p[1] = 0x02; return p }(), false},
		{"unknown type (6)", func() []byte { p := validPacket(); p[1] = 0x06; return p }(), false},
		{"unknown protocol", func() []byte { p := validPacket(); p[2] = 0xff; p[3] = 0xff; return p }(), false},
		{"no end tag", []byte{0x01, 0x00, 0x00, 0x01, 0x00, 0x00}, false},
		{"truncated variable tag length byte", []byte{0x01, 0x00, 0x00, 0x01, 0x0a}, false},
		{"truncated variable tag value", []byte{0x01, 0x00, 0x00, 0x01, 0x0a, 0x05, 0xaa}, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := tzsp.LooksLikeTZSP(tc.data)
			if got != tc.want {
				t.Errorf("LooksLikeTZSP(%x) = %v, want %v", tc.data, got, tc.want)
			}
		})
	}
}

// TestParsePayloadEmptyInner verifies that an empty inner payload is returned as-is.
func TestParsePayloadEmptyInner(t *testing.T) {
	pkt := buildPacket(1, 0, tzsp.ProtoEthernet, []byte{0x01}, nil)
	got, err := tzsp.ParsePayload(pkt)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("expected empty payload, got %x", got)
	}
}
