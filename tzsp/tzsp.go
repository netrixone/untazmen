// Package tzsp implements parsing of the Tazmen Sniffer Protocol (TZSP),
// a lightweight encapsulation protocol commonly used by MikroTik devices to
// mirror traffic to a remote host over UDP.
//
// Reference: https://web.archive.org/web/20190322161547/http://wiki.mikrotik.com/wiki/TZSP
package tzsp

import (
	"encoding/binary"
	"errors"
)

// Port is the well-known UDP port for TZSP.
const Port = 37008

// Packet types carried in the Type header field.
const (
	TypeReceivedPacket uint8 = 0
	TypeTransmitPacket uint8 = 1
	TypeReserved       uint8 = 2
	TypeConfig         uint8 = 3
	TypeKeepalive      uint8 = 4
	TypePortCloser     uint8 = 5
)

// Encapsulated protocol identifiers carried in the Protocol header field.
const (
	ProtoEthernet uint16 = 0x0001
	Proto80211    uint16 = 0x0012
	ProtoPrism    uint16 = 0x0077
	ProtoWLANAVS  uint16 = 0x7F20
)

// Tagged-field tag values. Tags 0x00 and 0x01 have no length or value fields;
// all other tags carry an explicit one-byte length followed by that many bytes.
const (
	tagPadding uint8 = 0x00 // zero-length filler, no length byte
	tagEnd     uint8 = 0x01 // terminates the tag list; payload follows immediately
)

// Sentinel errors returned by ParsePayload.
var (
	// ErrTooShort is returned when the data is shorter than the minimum 4-byte header.
	ErrTooShort = errors.New("tzsp: packet too short")

	// ErrInvalidVersion is returned when the TZSP version field is not 1.
	ErrInvalidVersion = errors.New("tzsp: unsupported version (expected 1)")

	// ErrTruncated is returned when a tagged field's length byte or value extends
	// beyond the end of the data slice.
	ErrTruncated = errors.New("tzsp: tagged fields are truncated")

	// ErrNoEndTag is returned when no End tag (0x01) is found before the data ends.
	ErrNoEndTag = errors.New("tzsp: End tag not found")
)

// Header holds the decoded values of the fixed 4-byte TZSP header.
type Header struct {
	Version  uint8  // must be 1
	Type     uint8  // see Type* constants
	Protocol uint16 // see Proto* constants
}

// ParseHeader decodes the 4-byte fixed TZSP header from data.
// It does NOT validate the version; callers that require validation should
// check Header.Version themselves or use ParsePayload.
func ParseHeader(data []byte) (Header, error) {
	if len(data) < 4 {
		return Header{}, ErrTooShort
	}
	return Header{
		Version:  data[0],
		Type:     data[1],
		Protocol: binary.BigEndian.Uint16(data[2:4]),
	}, nil
}

// LooksLikeTZSP performs a heuristic check on a raw UDP payload to determine
// whether it is likely a TZSP datagram, without relying on port numbers.
//
// The check validates:
//   - minimum length (4-byte header + at least 1 tag byte)
//   - version field equals 1
//   - type field is a known TZSP packet type
//   - protocol field is a known encapsulated-protocol value
//   - the tagged-field region is well-formed (End tag is reachable)
//
// Returns true when all checks pass.
func LooksLikeTZSP(data []byte) bool {
	// Need at least the 4-byte fixed header plus one tag byte.
	if len(data) < 5 {
		return false
	}

	// Version must be 1.
	if data[0] != 1 {
		return false
	}

	// Type must be a known value.
	switch data[1] {
	case TypeReceivedPacket, TypeTransmitPacket, TypeConfig, TypeKeepalive, TypePortCloser:
		// OK
	default:
		return false
	}

	// Protocol must be a known encapsulated-protocol value.
	proto := binary.BigEndian.Uint16(data[2:4])
	switch proto {
	case ProtoEthernet, Proto80211, ProtoPrism, ProtoWLANAVS:
		// OK
	default:
		return false
	}

	// Walk tagged fields: End tag must be reachable without truncation.
	offset := 4
	for offset < len(data) {
		tag := data[offset]
		offset++
		switch tag {
		case tagEnd:
			return true
		case tagPadding:
			// single-byte, no length
		default:
			if offset >= len(data) {
				return false
			}
			length := int(data[offset])
			offset++ // consume length byte
			offset += length
			if offset > len(data) {
				return false
			}
		}
	}

	return false
}

// ParsePayload decodes a complete TZSP datagram and returns a slice of data
// that begins immediately after the End tagged field — i.e., the encapsulated
// inner packet bytes. The returned slice shares the backing array with data.
//
// The function validates the Version field and walks all tagged fields to
// locate the payload boundary. It returns an error if data is malformed.
func ParsePayload(data []byte) ([]byte, error) {
	hdr, err := ParseHeader(data)
	if err != nil {
		return nil, err
	}
	if hdr.Version != 1 {
		return nil, ErrInvalidVersion
	}

	// Walk tagged fields starting right after the fixed 4-byte header.
	offset := 4
	for offset < len(data) {
		tag := data[offset]
		offset++

		switch tag {
		case tagEnd:
			// Payload begins at the current offset.
			return data[offset:], nil

		case tagPadding:
			// Single-byte tag, no length, no value; continue to next tag.

		default:
			// Variable-length tag: next byte is the value length.
			if offset >= len(data) {
				return nil, ErrTruncated
			}
			length := int(data[offset])
			offset++ // consume length byte
			offset += length
			if offset > len(data) {
				return nil, ErrTruncated
			}
		}
	}

	return nil, ErrNoEndTag
}
