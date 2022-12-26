package ctprint_test

import (
	"io"
	"os"
	"strings"
	"testing"

	"github.com/x-way/iptables-tracer/pkg/ctprint"
)

var ctbytesTestCases = []struct {
	Bytes []byte
	Mark  uint32
	Print string
	Name  string
}{
	{
		Bytes: []byte{},
		Print: "Error extracting CT attributes: incorrect length of provided data",
		Mark:  0,
		Name:  "Empty bytes",
	},
	{
		Bytes: []byte{0x4c, 0x0, 0x1, 0x80, 0x2c, 0x0, 0x1, 0x80, 0x14, 0x0, 0x3, 0x0, 0x20, 0x1, 0x4, 0x70, 0xb7, 0x50, 0x0, 0x1, 0x24, 0x23, 0x12, 0x75, 0x31, 0x4c, 0x6e, 0x67, 0x14, 0x0, 0x4, 0x0, 0x2a, 0x7, 0x57, 0x41, 0x0, 0x0, 0x11, 0x78, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0x1c, 0x0, 0x2, 0x80, 0x5, 0x0, 0x1, 0x0, 0x6, 0x0, 0x0, 0x0, 0x6, 0x0, 0x2, 0x0, 0xc4, 0x11, 0x0, 0x0, 0x6, 0x0, 0x3, 0x0, 0x0, 0x16, 0x0, 0x0, 0x4c, 0x0, 0x2, 0x80, 0x2c, 0x0, 0x1, 0x80, 0x14, 0x0, 0x3, 0x0, 0x2a, 0x7, 0x57, 0x41, 0x0, 0x0, 0x11, 0x78, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0x14, 0x0, 0x4, 0x0, 0x20, 0x1, 0x4, 0x70, 0xb7, 0x50, 0x0, 0x1, 0x24, 0x23, 0x12, 0x75, 0x31, 0x4c, 0x6e, 0x67, 0x1c, 0x0, 0x2, 0x80, 0x5, 0x0, 0x1, 0x0, 0x6, 0x0, 0x0, 0x0, 0x6, 0x0, 0x2, 0x0, 0x0, 0x16, 0x0, 0x0, 0x6, 0x0, 0x3, 0x0, 0xc4, 0x11, 0x0, 0x0, 0x8, 0x0, 0xc, 0x0, 0xe2, 0x32, 0xec, 0xc9, 0x8, 0x0, 0x3, 0x0, 0x0, 0x0, 0x0, 0xe, 0x8, 0x0, 0x7, 0x0, 0x0, 0x0, 0x1, 0x2c, 0x30, 0x0, 0x4, 0x80, 0x2c, 0x0, 0x1, 0x80, 0x5, 0x0, 0x1, 0x0, 0x3, 0x0, 0x0, 0x0, 0x5, 0x0, 0x2, 0x0, 0x6, 0x0, 0x0, 0x0, 0x5, 0x0, 0x3, 0x0, 0x7, 0x0, 0x0, 0x0, 0x6, 0x0, 0x4, 0x0, 0x23, 0x0, 0x0, 0x0, 0x6, 0x0, 0x5, 0x0, 0x33, 0x0, 0x0, 0x0},
		Print: " CT: orig=tcp:2001:470:b750:1:2423:1275:314c:6e67:50193->2a07:5741:0:1178::1:22, reply=tcp:2a07:5741:0:1178::1:22->2001:470:b750:1:2423:1275:314c:6e67:50193, tcpstate=ESTABLISHED, wscaleorig=6, wscalereply=7, flagsorig=WINDOW_SCALE,SACK_PERM,MAXACK_SET, flagsreply=WINDOW_SCALE,SACK_PERM,DATA_UNACKNOWLEDGED,MAXACK_SET, timeout=300s, id=0xe232ecc9, status=SEEN_REPLY,ASSURED,CONFIRMED",
		Mark:  0,
		Name:  "IPv6 TCP mid-session",
	},
	{
		Bytes: []byte{0x34, 0x0, 0x1, 0x80, 0x14, 0x0, 0x1, 0x80, 0x8, 0x0, 0x1, 0x0, 0xb2, 0x52, 0x91, 0x9, 0x8, 0x0, 0x2, 0x0, 0xb9, 0xcd, 0xd1, 0xa0, 0x1c, 0x0, 0x2, 0x80, 0x5, 0x0, 0x1, 0x0, 0x11, 0x0, 0x0, 0x0, 0x6, 0x0, 0x2, 0x0, 0x4, 0x27, 0x0, 0x0, 0x6, 0x0, 0x3, 0x0, 0x4, 0x27, 0x0, 0x0, 0x34, 0x0, 0x2, 0x80, 0x14, 0x0, 0x1, 0x80, 0x8, 0x0, 0x1, 0x0, 0xb9, 0xcd, 0xd1, 0xa0, 0x8, 0x0, 0x2, 0x0, 0xb2, 0x52, 0x91, 0x9, 0x1c, 0x0, 0x2, 0x80, 0x5, 0x0, 0x1, 0x0, 0x11, 0x0, 0x0, 0x0, 0x6, 0x0, 0x2, 0x0, 0x4, 0x27, 0x0, 0x0, 0x6, 0x0, 0x3, 0x0, 0x4, 0x27, 0x0, 0x0, 0x8, 0x0, 0xc, 0x0, 0x6d, 0x59, 0x7a, 0x13, 0x8, 0x0, 0x3, 0x0, 0x0, 0x0, 0x1, 0x8e, 0x8, 0x0, 0x7, 0x0, 0x0, 0x0, 0x0, 0xb4},
		Print: " CT: orig=udp:178.82.145.9:1063->185.205.209.160:1063, reply=udp:185.205.209.160:1063->178.82.145.9:1063, timeout=180s, id=0x6d597a13, status=SEEN_REPLY,ASSURED,CONFIRMED,SRC_NAT_DONE,DST_NAT_DONE",
		Mark:  0,
		Name:  "IPv4 UDP mid-session",
	},
	{
		Bytes: []byte{0x34, 0x0, 0x1, 0x80, 0x14, 0x0, 0x1, 0x80, 0x8, 0x0, 0x1, 0x0, 0xa, 0xca, 0x65, 0x3f, 0x8, 0x0, 0x2, 0x0, 0xa, 0x6f, 0xa, 0x8a, 0x1c, 0x0, 0x2, 0x80, 0x5, 0x0, 0x1, 0x0, 0x6, 0x0, 0x0, 0x0, 0x6, 0x0, 0x2, 0x0, 0xd8, 0xf8, 0x0, 0x0, 0x6, 0x0, 0x3, 0x0, 0x69, 0x89, 0x0, 0x0, 0x34, 0x0, 0x2, 0x80, 0x14, 0x0, 0x1, 0x80, 0x8, 0x0, 0x1, 0x0, 0xa, 0x6f, 0xa, 0x8a, 0x8, 0x0, 0x2, 0x0, 0xa, 0xca, 0x65, 0x3f, 0x1c, 0x0, 0x2, 0x80, 0x5, 0x0, 0x1, 0x0, 0x6, 0x0, 0x0, 0x0, 0x6, 0x0, 0x2, 0x0, 0x69, 0x89, 0x0, 0x0, 0x6, 0x0, 0x3, 0x0, 0xd8, 0xf8, 0x0, 0x0, 0x8, 0x0, 0xc, 0x0, 0xc9, 0x3d, 0xfa, 0xcf, 0x8, 0x0, 0x3, 0x0, 0x0, 0x0, 0x1, 0x88, 0x8, 0x0, 0x7, 0x0, 0x0, 0x0, 0x0, 0x78, 0x30, 0x0, 0x4, 0x80, 0x2c, 0x0, 0x1, 0x80, 0x5, 0x0, 0x1, 0x0, 0x1, 0x0, 0x0, 0x0, 0x5, 0x0, 0x2, 0x0, 0x7, 0x0, 0x0, 0x0, 0x5, 0x0, 0x3, 0x0, 0x0, 0x0, 0x0, 0x0, 0x6, 0x0, 0x4, 0x0, 0x3, 0x0, 0x0, 0x0, 0x6, 0x0, 0x5, 0x0, 0x0, 0x0, 0x0, 0x0},
		Print: " CT: orig=tcp:10.202.101.63:55544->10.111.10.138:27017, reply=tcp:10.111.10.138:27017->10.202.101.63:55544, tcpstate=SYN_SENT, wscaleorig=7, wscalereply=0, flagsorig=WINDOW_SCALE,SACK_PERM, flagsreply=, timeout=120s, id=0xc93dfacf, status=CONFIRMED,SRC_NAT_DONE,DST_NAT_DONE",
		Mark:  0,
		Name:  "IPv4 TCP first SYN",
	},
	{
		Bytes: []byte{0x34, 0x0, 0x1, 0x80, 0x14, 0x0, 0x1, 0x80, 0x8, 0x0, 0x1, 0x0, 0xa, 0x6f, 0x3f, 0x1, 0x8, 0x0, 0x2, 0x0, 0xa, 0x6f, 0x3f, 0x2, 0x1c, 0x0, 0x2, 0x80, 0x5, 0x0, 0x1, 0x0, 0x6, 0x0, 0x0, 0x0, 0x6, 0x0, 0x2, 0x0, 0xec, 0xb4, 0x0, 0x0, 0x6, 0x0, 0x3, 0x0, 0x69, 0x89, 0x0, 0x0, 0x34, 0x0, 0x2, 0x80, 0x14, 0x0, 0x1, 0x80, 0x8, 0x0, 0x1, 0x0, 0xa, 0x6f, 0x3f, 0x2, 0x8, 0x0, 0x2, 0x0, 0xa, 0x6f, 0x3f, 0x1, 0x1c, 0x0, 0x2, 0x80, 0x5, 0x0, 0x1, 0x0, 0x6, 0x0, 0x0, 0x0, 0x6, 0x0, 0x2, 0x0, 0x69, 0x89, 0x0, 0x0, 0x6, 0x0, 0x3, 0x0, 0xec, 0xb4, 0x0, 0x0, 0x8, 0x0, 0xc, 0x0, 0xfc, 0x98, 0xb9, 0x22, 0x8, 0x0, 0x3, 0x0, 0x0, 0x0, 0x1, 0x8e, 0x8, 0x0, 0x7, 0x0, 0x0, 0x0, 0x1, 0x2c, 0x30, 0x0, 0x4, 0x80, 0x2c, 0x0, 0x1, 0x80, 0x5, 0x0, 0x1, 0x0, 0x3, 0x0, 0x0, 0x0, 0x5, 0x0, 0x2, 0x0, 0x7, 0x0, 0x0, 0x0, 0x5, 0x0, 0x3, 0x0, 0x7, 0x0, 0x0, 0x0, 0x6, 0x0, 0x4, 0x0, 0x33, 0x0, 0x0, 0x0, 0x6, 0x0, 0x5, 0x0, 0x23, 0x0, 0x0, 0x0},
		Print: " CT: orig=tcp:10.111.63.1:60596->10.111.63.2:27017, reply=tcp:10.111.63.2:27017->10.111.63.1:60596, tcpstate=ESTABLISHED, wscaleorig=7, wscalereply=7, flagsorig=WINDOW_SCALE,SACK_PERM,DATA_UNACKNOWLEDGED,MAXACK_SET, flagsreply=WINDOW_SCALE,SACK_PERM,MAXACK_SET, timeout=300s, id=0xfc98b922, status=SEEN_REPLY,ASSURED,CONFIRMED,SRC_NAT_DONE,DST_NAT_DONE",
		Mark:  0,
		Name:  "IPv4 TCP mid-session reply",
	},
	{
		Bytes: []byte{0x3c, 0x0, 0x1, 0x80, 0x14, 0x0, 0x1, 0x80, 0x8, 0x0, 0x1, 0x0, 0xb9, 0xcd, 0xd1, 0xa0, 0x8, 0x0, 0x2, 0x0, 0x1, 0x1, 0x1, 0x1, 0x24, 0x0, 0x2, 0x80, 0x5, 0x0, 0x1, 0x0, 0x1, 0x0, 0x0, 0x0, 0x6, 0x0, 0x4, 0x0, 0xac, 0x21, 0x0, 0x0, 0x5, 0x0, 0x5, 0x0, 0x8, 0x0, 0x0, 0x0, 0x5, 0x0, 0x6, 0x0, 0x0, 0x0, 0x0, 0x0, 0x3c, 0x0, 0x2, 0x80, 0x14, 0x0, 0x1, 0x80, 0x8, 0x0, 0x1, 0x0, 0x1, 0x1, 0x1, 0x1, 0x8, 0x0, 0x2, 0x0, 0xb9, 0xcd, 0xd1, 0xa0, 0x24, 0x0, 0x2, 0x80, 0x5, 0x0, 0x1, 0x0, 0x1, 0x0, 0x0, 0x0, 0x6, 0x0, 0x4, 0x0, 0xac, 0x21, 0x0, 0x0, 0x5, 0x0, 0x5, 0x0, 0x0, 0x0, 0x0, 0x0, 0x5, 0x0, 0x6, 0x0, 0x0, 0x0, 0x0, 0x0, 0x8, 0x0, 0xc, 0x0, 0xc6, 0x6a, 0x68, 0xb1, 0x8, 0x0, 0x3, 0x0, 0x0, 0x0, 0x1, 0x8a, 0x8, 0x0, 0x7, 0x0, 0x0, 0x0, 0x0, 0x1e},
		Print: " CT: orig=icmp:0/8/44065:185.205.209.160->1.1.1.1, reply=icmp:0/0/44065:1.1.1.1->185.205.209.160, timeout=30s, id=0xc66a68b1, status=SEEN_REPLY,CONFIRMED,SRC_NAT_DONE,DST_NAT_DONE",
		Mark:  0,
		Name:  "IPv4 ICMP echo request",
	},
	{
		Bytes: []byte{0x54, 0x0, 0x1, 0x80, 0x2c, 0x0, 0x1, 0x80, 0x14, 0x0, 0x3, 0x0, 0x2a, 0x7, 0x57, 0x41, 0x0, 0x0, 0x11, 0x78, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0x14, 0x0, 0x4, 0x0, 0x26, 0x6, 0x47, 0x0, 0x47, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x11, 0x11, 0x24, 0x0, 0x2, 0x80, 0x5, 0x0, 0x1, 0x0, 0x3a, 0x0, 0x0, 0x0, 0x6, 0x0, 0x7, 0x0, 0x6e, 0x64, 0x0, 0x0, 0x5, 0x0, 0x8, 0x0, 0x80, 0x0, 0x0, 0x0, 0x5, 0x0, 0x9, 0x0, 0x0, 0x0, 0x0, 0x0, 0x54, 0x0, 0x2, 0x80, 0x2c, 0x0, 0x1, 0x80, 0x14, 0x0, 0x3, 0x0, 0x26, 0x6, 0x47, 0x0, 0x47, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x11, 0x11, 0x14, 0x0, 0x4, 0x0, 0x2a, 0x7, 0x57, 0x41, 0x0, 0x0, 0x11, 0x78, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0x24, 0x0, 0x2, 0x80, 0x5, 0x0, 0x1, 0x0, 0x3a, 0x0, 0x0, 0x0, 0x6, 0x0, 0x7, 0x0, 0x6e, 0x64, 0x0, 0x0, 0x5, 0x0, 0x8, 0x0, 0x81, 0x0, 0x0, 0x0, 0x5, 0x0, 0x9, 0x0, 0x0, 0x0, 0x0, 0x0, 0x8, 0x0, 0xc, 0x0, 0xd0, 0x9b, 0x5a, 0xf4, 0x8, 0x0, 0x3, 0x0, 0x0, 0x0, 0x0, 0xa, 0x8, 0x0, 0x7, 0x0, 0x0, 0x0, 0x0, 0x1e},
		Print: " CT: orig=icmpv6:0/128/28260:2a07:5741:0:1178::1->2606:4700:4700::1111, reply=icmpv6:0/129/28260:2606:4700:4700::1111->2a07:5741:0:1178::1, timeout=30s, id=0xd09b5af4, status=SEEN_REPLY,CONFIRMED",
		Mark:  0,
		Name:  "IPv6 ICMP echo request",
	},
	{
		Bytes: []byte{0x24, 0x0, 0x1, 0x80, 0x14, 0x0, 0x1, 0x80, 0x8, 0x0, 0x1, 0x0, 0xa, 0xca, 0x65, 0x21, 0x8, 0x0, 0x2, 0x0, 0xa, 0xca, 0x65, 0x3f, 0xc, 0x0, 0x2, 0x80, 0x5, 0x0, 0x1, 0x0, 0x29, 0x0, 0x0, 0x0, 0x24, 0x0, 0x2, 0x80, 0x14, 0x0, 0x1, 0x80, 0x8, 0x0, 0x1, 0x0, 0xa, 0xca, 0x65, 0x3f, 0x8, 0x0, 0x2, 0x0, 0xa, 0xca, 0x65, 0x21, 0xc, 0x0, 0x2, 0x80, 0x5, 0x0, 0x1, 0x0, 0x29, 0x0, 0x0, 0x0, 0x8, 0x0, 0xc, 0x0, 0xe7, 0xd7, 0x3, 0x45, 0x8, 0x0, 0x3, 0x0, 0x0, 0x0, 0x1, 0x8a, 0x8, 0x0, 0x7, 0x0, 0x0, 0x0, 0x2, 0x58},
		Print: " CT: orig=UNSUPPORTEDL4:0x29:10.202.101.33->10.202.101.63, reply=UNSUPPORTEDL4:0x29:10.202.101.63->10.202.101.33, timeout=600s, id=0xe7d70345, status=SEEN_REPLY,CONFIRMED,SRC_NAT_DONE,DST_NAT_DONE",

		Mark: 0,
		Name: "GRE mid-session",
	},
	{
		Bytes: []byte{0x24, 0x0, 0x1, 0x80, 0x14, 0x0, 0x1, 0x80, 0x8, 0x0, 0x1, 0x0, 0xa, 0xca, 0x65, 0x3f, 0x8, 0x0, 0x2, 0x0, 0xa, 0xca, 0x65, 0x13, 0xc, 0x0, 0x2, 0x80, 0x5, 0x0, 0x1, 0x0, 0x29, 0x0, 0x0, 0x0, 0x24, 0x0, 0x2, 0x80, 0x14, 0x0, 0x1, 0x80, 0x8, 0x0, 0x1, 0x0, 0xa, 0xca, 0x65, 0x13, 0x8, 0x0, 0x2, 0x0, 0xa, 0xca, 0x65, 0x3f, 0xc, 0x0, 0x2, 0x80, 0x5, 0x0, 0x1, 0x0, 0x29, 0x0, 0x0, 0x0, 0x8, 0x0, 0xc, 0x0, 0x5f, 0x7a, 0xbf, 0x1c, 0x8, 0x0, 0x3, 0x0, 0x0, 0x0, 0x1, 0x88, 0x8, 0x0, 0x7, 0x0, 0x0, 0x0, 0x2, 0x58},
		Print: " CT: orig=UNSUPPORTEDL4:0x29:10.202.101.63->10.202.101.19, reply=UNSUPPORTEDL4:0x29:10.202.101.19->10.202.101.63, timeout=600s, id=0x5f7abf1c, status=CONFIRMED,SRC_NAT_DONE,DST_NAT_DONE",

		Mark: 0,
		Name: "GRE unreplied",
	},
	{
		Bytes: []byte{0x24, 0x0, 0x1, 0x80, 0x14, 0x0, 0x1, 0x80, 0x8, 0x0, 0x1, 0x0, 0xa, 0xca, 0x65, 0x3f, 0x8, 0x0, 0x2, 0x0, 0xa, 0xca, 0x65, 0x49, 0xc, 0x0, 0x2, 0x80, 0x5, 0x0, 0x1, 0x0, 0x29, 0x0, 0x0, 0x0, 0x24, 0x0, 0x2, 0x80, 0x14, 0x0, 0x1, 0x80, 0x8, 0x0, 0x1, 0x0, 0xa, 0xca, 0x65, 0x49, 0x8, 0x0, 0x2, 0x0, 0xa, 0xca, 0x65, 0x3f, 0xc, 0x0, 0x2, 0x80, 0x5, 0x0, 0x1, 0x0, 0x29, 0x0, 0x0, 0x0, 0x8, 0x0, 0xc, 0x0, 0xc, 0xf6, 0x28, 0xe3, 0x8, 0x0, 0x3, 0x0, 0x0, 0x0, 0x1, 0x0, 0x8, 0x0, 0x7, 0x0, 0x0, 0x0, 0x0, 0x0},
		Print: " CT: orig=UNSUPPORTEDL4:0x29:10.202.101.63->10.202.101.73, reply=UNSUPPORTEDL4:0x29:10.202.101.73->10.202.101.63, timeout=0s, id=0x0cf628e3, status=DST_NAT_DONE",

		Mark: 0,
		Name: "GRE initial packet",
	},
}

func Test_GetCtMark(t *testing.T) {
	for _, tt := range ctbytesTestCases {
		t.Run(tt.Name, func(t *testing.T) {
			got := ctprint.GetCtMark(tt.Bytes)
			if got != tt.Mark {
				t.Errorf("expected %d, got %d\n", tt.Mark, got)
			}
		})
	}
}

func Test_Print(t *testing.T) {
	for _, tt := range ctbytesTestCases {
		t.Run(tt.Name, func(t *testing.T) {
			realStdout := os.Stdout
			r, w, _ := os.Pipe()
			os.Stdout = w

			ctprint.Print(tt.Bytes)

			w.Close()
			obuf, _ := io.ReadAll(r)
			os.Stdout = realStdout
			got := string(obuf)
			got = strings.TrimSuffix(got, "\n")

			if got != tt.Print {
				t.Errorf("expected '%s', got '%s'\n", tt.Print, got)
			}
		})
	}
}
