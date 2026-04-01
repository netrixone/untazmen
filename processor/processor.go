// Package processor implements the pcap packet-processing pipeline.
// It reads packets from a pcap or pcapng source, strips the outer
// Ethernet/IP/UDP/TZSP encapsulation from any packet that carries TZSP,
// and writes the result to a pcap output file.
//
// Packets that do not contain TZSP are passed through unchanged.
package processor

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"os"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"

	"github.com/netrixone/untazmen/tzsp"
)

// Stats holds counters accumulated during a single Process call.
type Stats struct {
	// Total is the number of packets read from the input.
	Total int

	// Stripped is the number of packets from which TZSP was removed.
	Stripped int

	// Passed is the number of packets written without modification.
	Passed int
}

// Processor reads packets from an input file, optionally strips TZSP
// encapsulation, and writes the result to an output file.
type Processor struct {
	inputPath  string
	outputPath string
}

// New creates a new Processor that reads from inputPath and writes to outputPath.
func New(inputPath, outputPath string) *Processor {
	return &Processor{
		inputPath:  inputPath,
		outputPath: outputPath,
	}
}

// Process runs the full strip pipeline. It returns statistics about how many
// packets were processed and an error if the operation could not complete.
// When outputPath is "-", the pcap stream is written to os.Stdout for piping
// (e.g. to tshark).
func (p *Processor) Process() (Stats, error) {
	src, linkType, closeInput, err := openInput(p.inputPath)
	if err != nil {
		return Stats{}, fmt.Errorf("open input %q: %w", p.inputPath, err)
	}
	defer closeInput()

	var outFile *os.File
	if p.outputPath == "-" {
		outFile = os.Stdout
	} else {
		var err error
		outFile, err = os.Create(p.outputPath)
		if err != nil {
			return Stats{}, fmt.Errorf("create output %q: %w", p.outputPath, err)
		}
		defer outFile.Close()
	}

	// The output is always written as a plain pcap with Ethernet link type.
	// TZSP always encapsulates Ethernet, so stripped packets are Ethernet frames.
	// Non-TZSP packets from an Ethernet capture are already Ethernet frames.
	w := pcapgo.NewWriter(outFile)
	if err := w.WriteFileHeader(65535, layers.LinkTypeEthernet); err != nil {
		return Stats{}, fmt.Errorf("write pcap file header: %w", err)
	}

	dec := newDecoder(linkType)
	var stats Stats

	for {
		data, capInfo, err := src.ReadPacketData()
		if err == io.EOF {
			break
		}
		if err != nil {
			return stats, fmt.Errorf("read packet %d: %w", stats.Total+1, err)
		}
		stats.Total++

		innerData, ok := dec.stripTZSP(data)
		if ok {
			stats.Stripped++
			innerCapInfo := capInfo
			innerCapInfo.CaptureLength = len(innerData)
			innerCapInfo.Length = len(innerData)
			if err := w.WritePacket(innerCapInfo, innerData); err != nil {
				return stats, fmt.Errorf("write packet %d: %w", stats.Total, err)
			}
		} else {
			stats.Passed++
			if err := w.WritePacket(capInfo, data); err != nil {
				return stats, fmt.Errorf("write packet %d: %w", stats.Total, err)
			}
		}
	}

	return stats, nil
}

// maxCachedStreams is the upper bound on the number of UDP streams stored in
// the TZSP stream cache. It prevents unbounded memory growth for captures that
// contain an unusually large number of distinct flows.
const maxCachedStreams = 1 << 16

// streamKey identifies a UDP flow by its 4-tuple. Each IP address is stored as
// 16 bytes in IPv4-mapped IPv6 form; each port occupies 2 big-endian bytes.
type streamKey [36]byte

// decoder wraps a reusable gopacket DecodingLayerParser and layer objects
// to avoid per-packet allocations.
type decoder struct {
	parser      *gopacket.DecodingLayerParser
	decoded     []gopacket.LayerType
	eth         layers.Ethernet
	ip4         layers.IPv4
	ip6         layers.IPv6
	udp         layers.UDP
	tcp         layers.TCP
	tzspStreams map[streamKey]struct{} // streams confirmed to carry TZSP
}

// newDecoder creates a decoder suitable for the given link type.
// It registers all layer types reachable from the link-layer type.
func newDecoder(linkType layers.LinkType) *decoder {
	d := &decoder{
		decoded:     make([]gopacket.LayerType, 0, 8),
		tzspStreams: make(map[streamKey]struct{}),
	}
	d.parser = gopacket.NewDecodingLayerParser(
		linkTypeToLayerType(linkType),
		&d.eth, &d.ip4, &d.ip6, &d.udp, &d.tcp,
	)

	// Do not return an error for unsupported layer types (e.g. application data).
	d.parser.IgnoreUnsupported = true
	return d
}

// newStreamKey packs (srcIP, srcPort, dstIP, dstPort) into a fixed-size key.
// IPv4 addresses are stored in IPv4-mapped IPv6 form; IPv6 addresses verbatim.
func newStreamKey(srcIP []byte, srcPort uint16, dstIP []byte, dstPort uint16) streamKey {
	var k streamKey
	src16 := ipTo16(srcIP)
	dst16 := ipTo16(dstIP)
	copy(k[0:16], src16[:])
	k[16] = byte(srcPort >> 8)
	k[17] = byte(srcPort)
	copy(k[18:34], dst16[:])
	k[34] = byte(dstPort >> 8)
	k[35] = byte(dstPort)
	return k
}

// ipTo16 returns a 16-byte IPv4-mapped IPv6 representation for a 4-byte IPv4
// address, or copies a 16-byte IPv6 address verbatim. Any other length yields
// a zero array.
func ipTo16(ip []byte) [16]byte {
	var b [16]byte
	switch len(ip) {
	case 4:
		b[10] = 0xff
		b[11] = 0xff
		copy(b[12:], ip)
	case 16:
		copy(b[:], ip)
	}
	return b
}

// currentIPs returns the source and destination IP byte slices from whichever
// IP layer (v4 or v6) was decoded for the current packet.
func (d *decoder) currentIPs() (src, dst []byte) {
	for _, lt := range d.decoded {
		switch lt {
		case layers.LayerTypeIPv4:
			return d.ip4.SrcIP, d.ip4.DstIP
		case layers.LayerTypeIPv6:
			return d.ip6.SrcIP, d.ip6.DstIP
		}
	}
	return nil, nil
}

// isTZSPStream reports whether the current UDP payload belongs to (or should
// be added to) the set of known TZSP streams. It caches positive results so
// that the heuristic is only run once per stream.
func (d *decoder) isTZSPStream() bool {
	srcIP, dstIP := d.currentIPs()
	if srcIP != nil {
		key := newStreamKey(srcIP, uint16(d.udp.SrcPort), dstIP, uint16(d.udp.DstPort))
		if _, ok := d.tzspStreams[key]; ok {
			return true // fast path: stream already confirmed
		}
		if !tzsp.LooksLikeTZSP(d.udp.Payload) {
			return false
		}
		if len(d.tzspStreams) < maxCachedStreams {
			d.tzspStreams[key] = struct{}{}
		}
		return true
	}
	// No IP layer present: fall back to per-packet heuristic without caching.
	return tzsp.LooksLikeTZSP(d.udp.Payload)
}

// linkTypeToLayerType converts a pcap link type to the corresponding gopacket
// layer type. gopacket v1.1.19's LinkType.LayerType() does not populate the
// LayerType field in LinkTypeMetadata, so we do the mapping explicitly for the
// link types we care about.
func linkTypeToLayerType(lt layers.LinkType) gopacket.LayerType {
	switch lt {
	case layers.LinkTypeEthernet:
		return layers.LayerTypeEthernet
	case layers.LinkTypeIPv4:
		return layers.LayerTypeIPv4
	case layers.LinkTypeIPv6:
		return layers.LayerTypeIPv6
	default:
		// Fall back to the library's mapping for any other link type.
		return lt.LayerType()
	}
}

// stripTZSP tries to decode data and locate a TZSP payload inside a UDP datagram.
// On success it returns (innerPayload, true). If the packet does not carry TZSP,
// it returns (nil, false).
//
// Detection strategy: port-less heuristic inspection of the UDP payload. The
// payload is accepted as TZSP only when its version, type, protocol, and
// tagged-field region all match the TZSP specification. This allows detection
// on non-standard ports while rejecting unrelated UDP traffic.
func (d *decoder) stripTZSP(data []byte) ([]byte, bool) {
	d.decoded = d.decoded[:0]

	// DecodeLayers may return an error when it hits an unknown layer (e.g. TLS),
	// but decoded will still contain all layers successfully identified so far.
	_ = d.parser.DecodeLayers(data, &d.decoded)

	// Check whether a UDP layer was found.
	udpFound := false
	for _, lt := range d.decoded {
		if lt == layers.LayerTypeUDP {
			udpFound = true
			break
		}
	}
	if !udpFound {
		return nil, false
	}

	// Determine whether this UDP payload is TZSP, using the stream cache to
	// avoid re-running the heuristic for already-confirmed flows.
	if !d.isTZSPStream() {
		return nil, false
	}

	inner, err := tzsp.ParsePayload(d.udp.Payload)
	if err != nil || len(inner) == 0 {
		return nil, false
	}
	return inner, true
}

// packetSource abstracts the ReadPacketData method shared by pcapgo.Reader
// and pcapgo.NgReader.
type packetSource interface {
	ReadPacketData() ([]byte, gopacket.CaptureInfo, error)
}

// openInput opens a pcap or pcapng source. When path is "-", it reads from
// os.Stdin (which need not be seekable). Otherwise it opens the named file.
// It detects the format by inspecting the 4-byte magic number.
func openInput(path string) (packetSource, layers.LinkType, func(), error) {
	if path == "-" {
		return openInputReader(os.Stdin, func() {})
	}

	f, err := os.Open(path)
	if err != nil {
		return nil, 0, nil, err
	}
	src, lt, _, err := openInputReader(f, func() { f.Close() })
	if err != nil {
		f.Close()
		return nil, 0, nil, err
	}
	return src, lt, func() { f.Close() }, nil
}

// openInputReader detects the pcap/pcapng format of r by reading its first
// 4 bytes, prepends them back with an io.MultiReader, and returns a packet
// source. close is called on error or when the caller is done with the source.
//
// pcapng uses a fixed block type of 0x0a0d0d0a (Section Header Block).
// pcap files start with either 0xa1b2c3d4 (little-endian) or 0xd4c3b2a1
// (big-endian) magic; both are handled by pcapgo.NewReader.
func openInputReader(r io.Reader, close func()) (packetSource, layers.LinkType, func(), error) {
	var magic [4]byte
	if _, err := io.ReadFull(r, magic[:]); err != nil {
		return nil, 0, nil, fmt.Errorf("read magic: %w", err)
	}

	combined := io.MultiReader(bytes.NewReader(magic[:]), r)

	m := binary.LittleEndian.Uint32(magic[:])
	if m == 0x0a0d0d0a {
		nr, err := pcapgo.NewNgReader(combined, pcapgo.DefaultNgReaderOptions)
		if err != nil {
			return nil, 0, nil, fmt.Errorf("pcapng reader: %w", err)
		}
		return nr, nr.LinkType(), close, nil
	}

	nr, err := pcapgo.NewReader(combined)
	if err != nil {
		return nil, 0, nil, fmt.Errorf("pcap reader: %w", err)
	}

	return nr, nr.LinkType(), close, nil
}
