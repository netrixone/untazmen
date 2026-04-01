package processor_test

import (
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"

	"github.com/netrixone/untazmen/processor"
)

const sampleFile = "../_data/linphone_call_iphone_android_G729.pcapng"

// TestProcessSampleFile runs the processor on the bundled sample capture and
// verifies that:
//   - at least one packet was stripped (TZSP was present)
//   - the output file is a valid pcap with Ethernet link type
//   - the output packet count equals the input packet count
func TestProcessSampleFile(t *testing.T) {
	if _, err := os.Stat(sampleFile); err != nil {
		t.Skipf("sample file not found: %v", err)
	}

	outPath := filepath.Join(t.TempDir(), "out.pcap")
	p := processor.New(sampleFile, outPath)
	stats, err := p.Process()
	if err != nil {
		t.Fatalf("Process() error: %v", err)
	}

	if stats.Total == 0 {
		t.Fatal("no packets were read from the sample file")
	}
	if stats.Stripped == 0 {
		t.Fatal("expected at least one TZSP packet to be stripped")
	}
	if stats.Total != stats.Stripped+stats.Passed {
		t.Errorf("total (%d) != stripped (%d) + passed (%d)", stats.Total, stats.Stripped, stats.Passed)
	}
	t.Logf("stats: total=%d stripped=%d passed=%d", stats.Total, stats.Stripped, stats.Passed)

	// Verify the output is a valid pcap with Ethernet link type.
	f, err := os.Open(outPath)
	if err != nil {
		t.Fatalf("open output: %v", err)
	}
	defer f.Close()

	r, err := pcapgo.NewReader(f)
	if err != nil {
		t.Fatalf("pcapgo.NewReader on output: %v", err)
	}
	if r.LinkType() != layers.LinkTypeEthernet {
		t.Errorf("output link type = %v, want Ethernet", r.LinkType())
	}

	// Count packets in output and verify all decode as Ethernet.
	var outCount int
	for {
		data, _, err := r.ReadPacketData()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("read output packet %d: %v", outCount+1, err)
		}
		outCount++

		// Each packet should parse as a valid Ethernet frame.
		pkt := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.Default)
		if pkt.Layer(layers.LayerTypeEthernet) == nil {
			t.Errorf("output packet %d does not decode as Ethernet", outCount)
		}
	}

	if outCount != stats.Total {
		t.Errorf("output packet count = %d, want %d (= input count)", outCount, stats.Total)
	}
}

// TestProcessHeuristicNonStandardPort verifies that TZSP traffic on a non-standard
// UDP port is still detected and stripped by the heuristic detector.
func TestProcessHeuristicNonStandardPort(t *testing.T) {
	frame := buildEthernetUDPTZSPFrame(9999)
	inputPath := writeTempPcap(t, layers.LinkTypeEthernet, [][]byte{frame})
	outPath := filepath.Join(t.TempDir(), "out.pcap")

	p := processor.New(inputPath, outPath)
	stats, err := p.Process()
	if err != nil {
		t.Fatalf("Process() error: %v", err)
	}

	if stats.Total != 1 {
		t.Fatalf("Total = %d, want 1", stats.Total)
	}
	if stats.Stripped != 1 {
		t.Errorf("Stripped = %d, want 1 (TZSP on non-standard port must be stripped)", stats.Stripped)
	}
}

// TestProcessHeuristicStandardPortNonTZSP verifies that a UDP datagram on the
// well-known TZSP port but with a non-TZSP payload is NOT stripped.
func TestProcessHeuristicStandardPortNonTZSP(t *testing.T) {
	// Build a UDP datagram on port 37008 carrying a payload that starts with
	// version=0xff, which is not a valid TZSP version.
	frame := buildEthernetUDPRandomPayload(37008, []byte{0xff, 0x00, 0x00, 0x01, 0x01, 0xde, 0xad})
	inputPath := writeTempPcap(t, layers.LinkTypeEthernet, [][]byte{frame})
	outPath := filepath.Join(t.TempDir(), "out.pcap")

	p := processor.New(inputPath, outPath)
	stats, err := p.Process()
	if err != nil {
		t.Fatalf("Process() error: %v", err)
	}

	if stats.Total != 1 {
		t.Fatalf("Total = %d, want 1", stats.Total)
	}
	if stats.Passed != 1 {
		t.Errorf("Passed = %d, want 1 (non-TZSP payload on TZSP port must pass through)", stats.Passed)
	}
}

// buildEthernetUDPTZSPFrame builds a minimal Ethernet+IPv4+UDP frame whose UDP
// payload is a valid TZSP datagram (version=1, RX, Ethernet, End tag, 6-byte
// inner Ethernet header stub). dstPort is the UDP destination port.
func buildEthernetUDPTZSPFrame(dstPort uint16) []byte {
	// Minimal inner Ethernet frame (14 bytes): dst+src MAC + EtherType 0x0800.
	innerEth := make([]byte, 14)
	innerEth[12] = 0x08
	innerEth[13] = 0x00

	// TZSP datagram: version=1, type=0 (RX), proto=0x0001 (Ethernet), End tag, inner.
	tzspPayload := append([]byte{0x01, 0x00, 0x00, 0x01, 0x01}, innerEth...)

	return buildEthernetUDPRandomPayload(dstPort, tzspPayload)
}

// buildEthernetUDPRandomPayload builds a minimal Ethernet+IPv4+UDP frame with
// the given dstPort and UDP payload.
func buildEthernetUDPRandomPayload(dstPort uint16, udpPayload []byte) []byte {
	udpLen := 8 + len(udpPayload)
	ipTotalLen := 20 + udpLen

	frame := make([]byte, 14+ipTotalLen)

	// Ethernet header (14 bytes): dst=ff:ff:ff:ff:ff:ff, src=aa:bb:cc:dd:ee:ff, EtherType=0x0800
	copy(frame[0:6], []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
	copy(frame[6:12], []byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff})
	frame[12] = 0x08
	frame[13] = 0x00

	// IPv4 header (20 bytes)
	ip := frame[14:]
	ip[0] = 0x45 // version=4, IHL=5
	ip[6] = 0x40 // TTL (using offset 8 below, but set flags here)
	ip[8] = 0x40 // TTL=64
	ip[9] = 0x11 // protocol=17 (UDP)
	ip[2] = byte(ipTotalLen >> 8)
	ip[3] = byte(ipTotalLen)
	ip[12] = 0xc0
	ip[13] = 0xa8
	ip[14] = 0x01
	ip[15] = 0x01 // src 192.168.1.1
	ip[16] = 0xc0
	ip[17] = 0xa8
	ip[18] = 0x01
	ip[19] = 0x02 // dst 192.168.1.2

	// UDP header (8 bytes)
	udp := frame[34:]
	udp[0] = 0x04
	udp[1] = 0x00 // src port 1024
	udp[2] = byte(dstPort >> 8)
	udp[3] = byte(dstPort)
	udp[4] = byte(udpLen >> 8)
	udp[5] = byte(udpLen)

	// UDP payload
	copy(frame[42:], udpPayload)

	return frame
}

// TestProcessStdin verifies that "-" as the input path reads from os.Stdin.
func TestProcessStdin(t *testing.T) {
	frame := buildEthernetUDPTZSPFrame(9999)

	// Build a pcap in memory and feed it through an os.Pipe as fake stdin.
	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	go func() {
		w := pcapgo.NewWriter(pw)
		_ = w.WriteFileHeader(65535, layers.LinkTypeEthernet)
		ci := gopacket.CaptureInfo{CaptureLength: len(frame), Length: len(frame)}
		_ = w.WritePacket(ci, frame)
		pw.Close()
	}()

	old := os.Stdin
	os.Stdin = pr
	defer func() {
		os.Stdin = old
		pr.Close()
	}()

	outPath := filepath.Join(t.TempDir(), "out.pcap")
	p := processor.New("-", outPath)
	stats, err := p.Process()
	if err != nil {
		t.Fatalf("Process() error: %v", err)
	}
	if stats.Total != 1 {
		t.Fatalf("Total = %d, want 1", stats.Total)
	}
	if stats.Stripped != 1 {
		t.Errorf("Stripped = %d, want 1", stats.Stripped)
	}
}

// TestProcessStreamCacheAllStripped verifies that multiple TZSP packets from
// the same UDP flow are all stripped correctly (exercises the cache fast-path).
func TestProcessStreamCacheAllStripped(t *testing.T) {
	frame := buildEthernetUDPTZSPFrame(9999)
	// Repeat the same frame 5 times to exercise the cache.
	frames := [][]byte{frame, frame, frame, frame, frame}
	inputPath := writeTempPcap(t, layers.LinkTypeEthernet, frames)
	outPath := filepath.Join(t.TempDir(), "out.pcap")

	p := processor.New(inputPath, outPath)
	stats, err := p.Process()
	if err != nil {
		t.Fatalf("Process() error: %v", err)
	}

	if stats.Total != 5 {
		t.Fatalf("Total = %d, want 5", stats.Total)
	}
	if stats.Stripped != 5 {
		t.Errorf("Stripped = %d, want 5 (all packets in confirmed stream must be stripped)", stats.Stripped)
	}
}

// TestProcessNonTZSPPacketsPassThrough verifies that packets without TZSP are
// copied verbatim to the output. We build a minimal synthetic pcap that contains
// a single raw Ethernet frame with no UDP/TZSP layers.
func TestProcessNonTZSPPacketsPassThrough(t *testing.T) {
	// Build a synthetic Ethernet frame carrying an ICMPv4 payload (no UDP at all).
	// Structure: Ethernet(dst=ff:ff:ff:ff:ff:ff, src=aa:bb:cc:dd:ee:ff, type=0x0800)
	// + IPv4(proto=1 ICMP) + 8 zero bytes of ICMP payload.
	frame := buildEthernetICMPFrame()

	inputPath := writeTempPcap(t, layers.LinkTypeEthernet, [][]byte{frame})
	outPath := filepath.Join(t.TempDir(), "out.pcap")

	p := processor.New(inputPath, outPath)
	stats, err := p.Process()
	if err != nil {
		t.Fatalf("Process() error: %v", err)
	}

	if stats.Total != 1 {
		t.Fatalf("Total = %d, want 1", stats.Total)
	}
	if stats.Passed != 1 {
		t.Errorf("Passed = %d, want 1 (non-TZSP packet should pass through)", stats.Passed)
	}
	if stats.Stripped != 0 {
		t.Errorf("Stripped = %d, want 0", stats.Stripped)
	}

	// Output packet must match input verbatim.
	outFrames := readAllPackets(t, outPath)
	if len(outFrames) != 1 {
		t.Fatalf("output packet count = %d, want 1", len(outFrames))
	}
	if string(outFrames[0]) != string(frame) {
		t.Errorf("output frame differs from input frame\ngot  %x\nwant %x", outFrames[0], frame)
	}
}

// buildEthernetICMPFrame constructs a minimal 42-byte Ethernet+IPv4+ICMP frame.
func buildEthernetICMPFrame() []byte {
	frame := make([]byte, 42)
	// Ethernet header (14 bytes)
	copy(frame[0:6], []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff})  // dst
	copy(frame[6:12], []byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}) // src
	frame[12] = 0x08                                              // EtherType IPv4
	frame[13] = 0x00
	// IPv4 header (20 bytes), proto=1 (ICMP)
	frame[14] = 0x45 // version=4, IHL=5
	frame[15] = 0x00 // DSCP
	frame[16] = 0x00 // total length high
	frame[17] = 0x1c // total length low = 28
	frame[22] = 0x40 // TTL=64
	frame[23] = 0x01 // protocol = ICMP
	frame[26] = 0x7f // src 127.0.0.1
	frame[27] = 0x00
	frame[28] = 0x00
	frame[29] = 0x01
	frame[30] = 0x7f // dst 127.0.0.1
	frame[31] = 0x00
	frame[32] = 0x00
	frame[33] = 0x01
	// 8 bytes ICMP (echo request, all zeros except type=8)
	frame[34] = 0x08
	return frame
}

// writeTempPcap writes frames to a temporary pcap file and returns its path.
func writeTempPcap(t *testing.T, lt layers.LinkType, frames [][]byte) string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "input-*.pcap")
	if err != nil {
		t.Fatalf("create temp pcap: %v", err)
	}
	defer f.Close()

	w := pcapgo.NewWriter(f)
	if err := w.WriteFileHeader(65535, lt); err != nil {
		t.Fatalf("write pcap header: %v", err)
	}
	for i, frame := range frames {
		ci := gopacket.CaptureInfo{
			CaptureLength: len(frame),
			Length:        len(frame),
		}
		if err := w.WritePacket(ci, frame); err != nil {
			t.Fatalf("write frame %d: %v", i, err)
		}
	}
	return f.Name()
}

// readAllPackets opens a pcap file and returns all packet payloads.
func readAllPackets(t *testing.T, path string) [][]byte {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer f.Close()

	r, err := pcapgo.NewReader(f)
	if err != nil {
		t.Fatalf("pcapgo.NewReader: %v", err)
	}
	var out [][]byte
	for {
		data, _, err := r.ReadPacketData()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("read packet: %v", err)
		}
		cp := make([]byte, len(data))
		copy(cp, data)
		out = append(out, cp)
	}
	return out
}
