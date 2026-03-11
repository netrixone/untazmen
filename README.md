# untazmen

`untazmen` strips the outer **Ethernet / IP / UDP / TZSP** encapsulation layers
from every packet in a pcap or pcapng capture file, leaving only the inner
payload that TZSP was carrying.  Packets that do not contain TZSP are copied
to the output unchanged.

## Background

[TZSP (Tazmen Sniffer Protocol)](https://en.wikipedia.org/wiki/TZSP) is a
lightweight encapsulation protocol used primarily by MikroTik RouterOS to mirror
traffic to a remote sniffer host.  The mirrored frame is wrapped inside a UDP
datagram (well-known port **37008**) with a small fixed header and a list of
tagged fields, after which the original Ethernet frame follows verbatim.

A typical layer stack in a TZSP capture looks like this:

```
Ethernet_outer → IP_outer → UDP_outer → TZSP → Ethernet_inner → IP_inner → …
```

After processing with `untazmen`:

```
Ethernet_inner → IP_inner → …
```

The output is always a standard pcap file with Ethernet link type, which can be
opened directly in Wireshark, tshark, or any other packet analyser.

## Build

Requires Go 1.21 or later.

```sh
go build -o untazmen .
```

## Usage

```
untazmen -i <input> -o <output>

Options:
  -i  --input   Path to the input PCAP or PCAPng file (omit to read from stdin)
  -o  --output  Path to the output pcap file (omit to write to stdout for piping, e.g. to tshark)
```

### Examples

```sh
untazmen -i capture.pcapng -o stripped.pcap
# done: 3905 packets total, 3862 stripped, 43 passed through

tshark -r stripped.pcap

# Pipe directly from tcpdump or a remote host
tcpdump -w - | untazmen -i - -o stripped.pcap
ssh router 'tcpdump -w -' | untazmen -i - | tshark -r -
```

## Dependencies

| Module | Purpose |
|--------|---------|
| [`github.com/google/gopacket`](https://github.com/google/gopacket) | Fast layer-by-layer decoding of Ethernet / IP / UDP; pcap and pcapng I/O |
| [`github.com/akamensky/argparse`](https://github.com/akamensky/argparse) | CLI argument parsing |
