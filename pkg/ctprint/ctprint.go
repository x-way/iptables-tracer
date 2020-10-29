// Package ctprint provides functions to print NFLOG conntrack entries
package ctprint

import (
	"fmt"
	"log"
	"os"
	"strings"

	conntrack "github.com/florianl/go-conntrack"
)

var stdOutLogger = log.New(os.Stdout, "", log.LstdFlags)

// Print parses the conntrack info from NFLOG and prints a textual representation of the contained conntrack attributes
func Print(ctbytes []byte) {
	if str, err := Format(ctbytes); err != nil {
		fmt.Printf("Error extracting CT attributes: %s\n", err)
	} else {
		fmt.Printf(" CT: %s\n", str)
	}
}

func Format(ctbytes []byte) (string, error) {
	if connection, err := conntrack.ParseAttributes(stdOutLogger, ctbytes); err != nil {
		return "", err
	} else {
		return formatConnection(connection), nil
	}
}

func formatConnection(c conntrack.Con) string {
	var attrs []string
	if c.Origin != nil {
		attrs = append(attrs, fmt.Sprintf("orig=%s", formatEndpoints(*c.Origin)))
	}
	if c.Reply != nil {
		attrs = append(attrs, fmt.Sprintf("reply=%s", formatEndpoints(*c.Reply)))
	}

	if c.ProtoInfo != nil {
		if c.ProtoInfo.TCP != nil {
			if c.ProtoInfo.TCP.State != nil {
				attrs = append(attrs, fmt.Sprintf("tcpstate=%s", getTCPState(*c.ProtoInfo.TCP.State)))
			}
			if c.ProtoInfo.TCP.WScaleOrig != nil {
				attrs = append(attrs, fmt.Sprintf("wscaleorig=%d", *c.ProtoInfo.TCP.WScaleOrig))
			}
			if c.ProtoInfo.TCP.WScaleRepl != nil {
				attrs = append(attrs, fmt.Sprintf("wscalereply=%d", *c.ProtoInfo.TCP.WScaleRepl))
			}
			if c.ProtoInfo.TCP.FlagsOrig != nil && c.ProtoInfo.TCP.FlagsOrig.Flags != nil {
				attrs = append(attrs, fmt.Sprintf("flagsorig=%s", getTCPFlags(*c.ProtoInfo.TCP.FlagsOrig.Flags)))
			}
			if c.ProtoInfo.TCP.FlagsReply != nil && c.ProtoInfo.TCP.FlagsReply.Flags != nil {
				attrs = append(attrs, fmt.Sprintf("flagsreply=%s", getTCPFlags(*c.ProtoInfo.TCP.FlagsReply.Flags)))
			}
		}
	}

	if c.Helper != nil {
		attrs = append(attrs, fmt.Sprintf("helper=%s", *c.Helper.Name))
	}
	if c.Mark != nil {
		attrs = append(attrs, fmt.Sprintf("mark=0x%x", *c.Mark))
	}
	if c.Timeout != nil {
		attrs = append(attrs, fmt.Sprintf("timeout=%ds", *c.Timeout))
	}
	if c.ID != nil {
		attrs = append(attrs, fmt.Sprintf("id=0x%08x", *c.ID))
	}
	if c.Status != nil {
		attrs = append(attrs, fmt.Sprintf("status=%s", getCtStatus(*c.Status)))
	}

	return strings.Join(attrs, ", ")
}

func formatEndpoints(t conntrack.IPTuple) string {
	var proto, src, dst string
	if t.Src != nil {
		src = t.Src.String()
	}
	if t.Dst != nil {
		dst = t.Dst.String()
	}
	if t.Proto != nil {
		if t.Proto.Number != nil {
			switch *t.Proto.Number {
			case 6, 17:
				if *t.Proto.Number == 6 {
					proto = "tcp"
				} else {
					proto = "udp"
				}
				if t.Proto.SrcPort != nil {
					src = fmt.Sprintf("%s:%d", src, *t.Proto.SrcPort)
				}
				if t.Proto.DstPort != nil {
					dst = fmt.Sprintf("%s:%d", dst, *t.Proto.DstPort)
				}
			case 1:
				proto = "icmp"

				if t.Proto.IcmpCode != nil {
					proto = fmt.Sprintf("%s:%d", proto, *t.Proto.IcmpCode)
				}
				if t.Proto.IcmpType != nil {
					proto = fmt.Sprintf("%s/%d", proto, *t.Proto.IcmpType)
				}
				if t.Proto.IcmpID != nil {
					proto = fmt.Sprintf("%s/%d", proto, *t.Proto.IcmpID)
				}
			case 58:
				proto = "icmpv6"

				if t.Proto.Icmpv6Code != nil {
					proto = fmt.Sprintf("%s:%d", proto, *t.Proto.Icmpv6Code)
				}
				if t.Proto.Icmpv6Type != nil {
					proto = fmt.Sprintf("%s/%d", proto, *t.Proto.Icmpv6Type)
				}
				if t.Proto.Icmpv6ID != nil {
					proto = fmt.Sprintf("%s/%d", proto, *t.Proto.Icmpv6ID)
				}
			default:
				proto = fmt.Sprintf("UNSUPPORTEDL4:0x%x", *t.Proto.Number)
			}
		}
	}
	return fmt.Sprintf("%s:%s->%s", proto, src, dst)
}

var tcpflags = map[uint8]string{
	0x01: "WINDOW_SCALE",
	0x02: "SACK_PERM",
	0x04: "CLOSE_INIT",
	0x08: "BE_LIBERAL",
	0x10: "DATA_UNACKNOWLEDGED",
	0x20: "MAXACK_SET",
	0x40: "EXP_CHALLENGE_ACK",
	0x80: "SIMULTANEOUS_OPEN",
}

func getTCPFlags(flags uint8) string {
	var stati []string
	var bit uint8
	for i := 0; i < 8; i++ {
		bit = 0x01 << i
		if flags&bit == bit {
			if str, found := tcpflags[bit]; found {
				stati = append(stati, str)
			}
		}
	}
	return strings.Join(stati, ",")
}

var tcpstates = map[uint8]string{
	0:  "NONE",
	1:  "SYN_SENT",
	2:  "SYN_RECV",
	3:  "ESTABLISHED",
	4:  "FIN_WAIT",
	5:  "CLOSE_WAIT",
	6:  "LAST_ACK",
	7:  "TIME_WAIT",
	8:  "CLOSE",
	9:  "LISTEN",
	10: "MAX",
	11: "IGNORE",
	12: "RETRANS",
	13: "UNACK",
	14: "TIMEOUT_MAX",
}

func getTCPState(state uint8) string {
	if str, found := tcpstates[state]; found {
		return str
	}
	return fmt.Sprintf("UNKNOWN:0x%x", state)
}

var ctstates = map[uint32]string{
	0x0001: "EXPECTED",
	0x0002: "SEEN_REPLY",
	0x0004: "ASSURED",
	0x0008: "CONFIRMED",
	0x0010: "SRC_NAT",
	0x0020: "DST_NAT",
	0x0040: "SEQ_ADJUST",
	0x0080: "SRC_NAT_DONE",
	0x0100: "DST_NAT_DONE",
	0x0200: "DYING",
	0x0400: "FIXED_TIMEOUT",
	0x0800: "TEMPLATE",
	0x1000: "UNTRACKED",
	0x2000: "HELPER",
	0x4000: "OFFLOAD",
	0x8000: "EXPECTED",
}

func getCtStatus(ctstatus uint32) string {
	var stati []string
	var bit uint32
	for i := 0; i < 16; i++ {
		bit = 0x01 << i
		if ctstatus&bit == bit {
			if str, found := ctstates[bit]; found {
				stati = append(stati, str)
			}
		}
	}
	return strings.Join(stati, ",")
}

// InfoString takes the conntrack info value and returns a short textual representation
func InfoString(ctinfo uint32) string {
	switch ctinfo {
	case 0:
		return "EST O"
	case 1:
		return "REL O"
	case 2:
		return "NEW O"
	case 3:
		return "EST R"
	case 4:
		return "REL R"
	case 5:
		return "NEW R"
	case 7:
		return "UNTRA"
	case ^uint32(0):
		return "     "
	default:
		return fmt.Sprintf("%5d", ctinfo)
	}
}

// GetCtMark parses the conntrack info from NFLOG and extracts the connmark
func GetCtMark(data []byte) uint32 {
	if connection, err := conntrack.ParseAttributes(stdOutLogger, data); err == nil {
		if connection.Mark != nil {
			return *connection.Mark
		}
	}
	return 0
}
