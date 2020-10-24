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
	if connection, err := conntrack.ParseAttributes(stdOutLogger, ctbytes); err != nil {
		fmt.Printf("Error extracting CT attributes: %s\n", err)
	} else {
		printConnection(connection)
	}
}

func printConnection(c conntrack.Con) {
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
			if c.ProtoInfo.TCP.FlagsOrig != nil {
				attrs = append(attrs, fmt.Sprintf("flagsorig=%s", getTCPFlags(*c.ProtoInfo.TCP.FlagsOrig)))
			}
			if c.ProtoInfo.TCP.FlagsReply != nil {
				attrs = append(attrs, fmt.Sprintf("flagsreply=%s", getTCPFlags(*c.ProtoInfo.TCP.FlagsReply)))
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

	fmt.Printf(" CT: %s\n", strings.Join(attrs, ", "))
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

func getTCPFlags(data []byte) string {
	var stati []string
	flags := data[0]
	if flags&0x01 == 0x01 {
		stati = append(stati, "WINDOW_SCALE")
	}
	if flags&0x02 == 0x02 {
		stati = append(stati, "SACK_PERM")
	}
	if flags&0x04 == 0x04 {
		stati = append(stati, "CLOSE_INIT")
	}
	if flags&0x08 == 0x08 {
		stati = append(stati, "BE_LIBERAL")
	}
	if flags&0x10 == 0x10 {
		stati = append(stati, "DATA_UNACKNOWLEDGED")
	}
	if flags&0x20 == 0x20 {
		stati = append(stati, "MAXACK_SET")
	}
	if flags&0x40 == 0x40 {
		stati = append(stati, "EXP_CHALLENGE_ACK")
	}
	if flags&0x80 == 0x80 {
		stati = append(stati, "SIMULTANEOUS_OPEN")
	}
	return strings.Join(stati, ",")
}

func getTCPState(state uint8) string {
	switch state {
	case 0:
		return "NONE"
	case 1:
		return "SYN_SENT"
	case 2:
		return "SYN_RECV"
	case 3:
		return "ESTABLISHED"
	case 4:
		return "FIN_WAIT"
	case 5:
		return "CLOSE_WAIT"
	case 6:
		return "LAST_ACK"
	case 7:
		return "TIME_WAIT"
	case 8:
		return "CLOSE"
	case 9:
		return "LISTEN"
	case 10:
		return "MAX"
	case 11:
		return "IGNORE"
	case 12:
		return "RETRANS"
	case 13:
		return "UNACK"
	case 14:
		return "TIMEOUT_MAX"
	default:
		return fmt.Sprintf("UNKNOWN:0x%x", state)
	}
}

func getCtStatus(ctstatus uint32) string {
	var stati []string
	if ctstatus&(1<<0) == (1 << 0) {
		stati = append(stati, "EXPECTED")
	}
	if ctstatus&(1<<1) == (1 << 1) {
		stati = append(stati, "SEEN_REPLY")
	}
	if ctstatus&(1<<2) == (1 << 2) {
		stati = append(stati, "ASSURED")
	}
	if ctstatus&(1<<3) == (1 << 3) {
		stati = append(stati, "CONFIRMED")
	}
	if ctstatus&(1<<4) == (1 << 4) {
		stati = append(stati, "SRC_NAT")
	}
	if ctstatus&(1<<5) == (1 << 5) {
		stati = append(stati, "DST_NAT")
	}
	if ctstatus&(1<<6) == (1 << 6) {
		stati = append(stati, "SEQ_ADJUST")
	}
	if ctstatus&(1<<7) == (1 << 7) {
		stati = append(stati, "SRC_NAT_DONE")
	}
	if ctstatus&(1<<8) == (1 << 8) {
		stati = append(stati, "DST_NAT_DONE")
	}
	if ctstatus&(1<<9) == (1 << 9) {
		stati = append(stati, "DYING")
	}
	if ctstatus&(1<<10) == (1 << 10) {
		stati = append(stati, "FIXED_TIMEOUT")
	}
	if ctstatus&(1<<11) == (1 << 11) {
		stati = append(stati, "TEMPLATE")
	}
	if ctstatus&(1<<12) == (1 << 12) {
		stati = append(stati, "UNTRACKED")
	}
	if ctstatus&(1<<13) == (1 << 13) {
		stati = append(stati, "HELPER")
	}
	if ctstatus&(1<<14) == (1 << 14) {
		stati = append(stati, "OFFLOAD")
	}
	if ctstatus&(1<<15) == (1 << 15) {
		stati = append(stati, "EXPECTED")
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
