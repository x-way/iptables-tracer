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
