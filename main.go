package main

import (
	"fmt"
	"os"

	"github.com/akamensky/argparse"

	"github.com/netrixone/untazmen/processor"
)

var version = "dev"

func main() {
	p := argparse.NewParser(
		"untazmen",
		"Strip outer Ethernet/IP/UDP/TZSP layers from a PCAP or PCAPng capture file.\n"+
			"Packets that do not carry TZSP are passed through unchanged.\n"+
			"The output is always written as a pcap file with Ethernet link type.",
	)

	input := p.String("i", "input", &argparse.Options{
		Help:    "Path to the input PCAP or PCAPng file (use - to read from stdin)",
		Default: "-",
	})
	output := p.String("o", "output", &argparse.Options{
		Help:    "Path to the output pcap file (use - to write to stdout for piping, e.g. to tshark)",
		Default: "-",
	})
	showVersion := p.Flag("", "version", &argparse.Options{
		Help: "Print version and exit",
	})

	if err := p.Parse(os.Args); err != nil {
		fmt.Fprintln(os.Stderr, p.Usage(err))
		os.Exit(1)
	}

	if *showVersion {
		fmt.Println(version)
		os.Exit(0)
	}

	if *input == "" || *output == "" {
		fmt.Fprintln(os.Stderr, p.Usage(nil))
		os.Exit(1)
	}

	proc := processor.New(*input, *output)
	stats, err := proc.Process()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	fmt.Fprintf(os.Stderr,
		"done: %d packets total, %d stripped, %d passed through\n",
		stats.Total, stats.Stripped, stats.Passed,
	)
}
