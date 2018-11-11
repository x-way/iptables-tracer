package main

import (
	"testing"

	"github.com/google/gopacket/layers"
)

func TestFormatPacketICMPv4(t *testing.T) {
	tables := []struct {
		icmp     *layers.ICMPv4
		src      string
		dst      string
		length   int
		expected string
	}{
		{&layers.ICMPv4{}, "test-src", "test-dst", 1234, "test-src > test-dst: ICMP echo reply, id 0, seq 0, length 1234"},
		{&layers.ICMPv4{Id: 999, Seq: 10}, "test-src", "test-dst", 1234, "test-src > test-dst: ICMP echo reply, id 999, seq 10, length 1234"},
		{&layers.ICMPv4{TypeCode: 0x0800}, "test-src", "test-dst", 1234, "test-src > test-dst: ICMP echo request, id 0, seq 0, length 1234"},
		{&layers.ICMPv4{TypeCode: 0xff00}, "test-src", "test-dst", 1234, "test-src > test-dst: ICMP, length 1234"},
	}

	for _, table := range tables {
		got := formatPacketICMPv4(table.icmp, table.src, table.dst, table.length)
		if got != table.expected {
			t.Errorf("formatPacketICMPv4 was incorrect, got: '%s', expected: '%s'.", got, table.expected)
		}
	}
}

func TestFormatPacketTCP(t *testing.T) {
	tables := []struct {
		tcp      *layers.TCP
		src      string
		dst      string
		length   int
		expected string
	}{
		{&layers.TCP{}, "test-src", "test-dst", 1234, "test-src.0 > test-dst.0: Flags [none], seq 0, win 0, length 1234"},
		{&layers.TCP{Seq: 999, Window: 95}, "test-src", "test-dst", 1234, "test-src.0 > test-dst.0: Flags [none], seq 999, win 95, length 1234"},
		{&layers.TCP{DataOffset: 4}, "test-src", "test-dst", 1234, "test-src.0 > test-dst.0: Flags [none], seq 0, win 0, length 1218"},
		{&layers.TCP{SYN: true}, "test-src", "test-dst", 1234, "test-src.0 > test-dst.0: Flags [S], seq 0, win 0, length 1234"},
		{&layers.TCP{SYN: true, ACK: true}, "test-src", "test-dst", 1234, "test-src.0 > test-dst.0: Flags [S.], seq 0, win 0, length 1234"},
		{&layers.TCP{ACK: true}, "test-src", "test-dst", 1234, "test-src.0 > test-dst.0: Flags [.], seq 0, win 0, length 1234"},
		{&layers.TCP{PSH: true, ACK: true}, "test-src", "test-dst", 1234, "test-src.0 > test-dst.0: Flags [P.], seq 0, win 0, length 1234"},
		{&layers.TCP{FIN: true}, "test-src", "test-dst", 1234, "test-src.0 > test-dst.0: Flags [F], seq 0, win 0, length 1234"},
		{&layers.TCP{FIN: true, ACK: true}, "test-src", "test-dst", 1234, "test-src.0 > test-dst.0: Flags [F.], seq 0, win 0, length 1234"},
		{&layers.TCP{FIN: true, SYN: true, RST: true, PSH: true, ACK: true, URG: true, ECE: true, CWR: true, NS: true}, "test-src", "test-dst", 1234, "test-src.0 > test-dst.0: Flags [FSRP.UEWN], seq 0, win 0, length 1234"},
	}

	for _, table := range tables {
		got := formatPacketTCP(table.tcp, table.src, table.dst, table.length)
		if got != table.expected {
			t.Errorf("formatPacketTCP was incorrect, got: '%s', expected: '%s'.", got, table.expected)
		}
	}
}
