package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"sort"
	"strings"

	conntrack "github.com/florianl/go-conntrack"
	"golang.org/x/sys/unix"
)

func printCt(ctbytes []byte) {
	var conn conntrack.Conn
	var err error

	if conn, err = conntrack.ParseAttributes(ctbytes); err != nil {
		fmt.Printf("Error extracting CT attributes: %s\n", err)
		return
	}
	printConn(conn)
}

func printConn(c conntrack.Conn) {

	attrMap := make(map[conntrack.ConnAttrType]string)

	attrMap[conntrack.AttrTCPState] = "AttrTCPState"
	attrMap[conntrack.AttrSNatIPv4] = "AttrSNatIPv4"
	attrMap[conntrack.AttrDNatIPv4] = "AttrDNatIPv4"
	attrMap[conntrack.AttrSNatPort] = "AttrSNatPort"
	attrMap[conntrack.AttrDNatPort] = "AttrDNatPort"
	attrMap[conntrack.AttrMarkMask] = "AttrMarkMask"
	attrMap[conntrack.AttrOrigCounterPackets] = "AttrOrigCounterPackets"
	attrMap[conntrack.AttrReplCounterPackets] = "AttrReplCounterPackets"
	attrMap[conntrack.AttrOrigCounterBytes] = "AttrOrigCounterBytes"
	attrMap[conntrack.AttrReplCounterBytes] = "AttrReplCounterBytes"
	attrMap[conntrack.AttrUse] = "AttrUse"
	attrMap[conntrack.AttrTCPFlagsOrig] = "AttrTCPFlagsOrig"
	attrMap[conntrack.AttrTCPFlagsRepl] = "AttrTCPFlagsRepl"
	attrMap[conntrack.AttrTCPMaskOrig] = "AttrTCPMaskOrig"
	attrMap[conntrack.AttrTCPMaskRepl] = "AttrTCPMaskRepl"
	attrMap[conntrack.AttrMasterIPv4Src] = "AttrMasterIPv4Src"
	attrMap[conntrack.AttrMasterIPv4Dst] = "AttrMasterIPv4Dst"
	attrMap[conntrack.AttrMasterIPv6Src] = "AttrMasterIPv6Src"
	attrMap[conntrack.AttrMasterIPv6Dst] = "AttrMasterIPv6Dst"
	attrMap[conntrack.AttrMasterPortSrc] = "AttrMasterPortSrc"
	attrMap[conntrack.AttrMasterPortDst] = "AttrMasterPortDst"
	attrMap[conntrack.AttrMasterL3Proto] = "AttrMasterL3Proto"
	attrMap[conntrack.AttrMasterL4Proto] = "AttrMasterL4Proto"
	attrMap[conntrack.AttrSecmark] = "AttrSecmark"
	attrMap[conntrack.AttrOrigNatSeqCorrectionPos] = "AttrOrigNatSeqCorrectionPos"
	attrMap[conntrack.AttrOrigNatSeqOffsetBefore] = "AttrOrigNatSeqOffsetBefore"
	attrMap[conntrack.AttrOrigNatSeqOffsetAfter] = "AttrOrigNatSeqOffsetAfter"
	attrMap[conntrack.AttrReplNatSeqCorrectionPos] = "AttrReplNatSeqCorrectionPos"
	attrMap[conntrack.AttrReplNatSeqOffsetBefore] = "AttrReplNatSeqOffsetBefore"
	attrMap[conntrack.AttrReplNatSeqOffsetAfter] = "AttrReplNatSeqOffsetAfter"
	attrMap[conntrack.AttrSctpState] = "AttrSctpState"
	attrMap[conntrack.AttrSctpVtagOrig] = "AttrSctpVtagOrig"
	attrMap[conntrack.AttrSctpVtagRepl] = "AttrSctpVtagRepl"
	attrMap[conntrack.AttrDccpState] = "AttrDccpState"
	attrMap[conntrack.AttrDccpRole] = "AttrDccpRole"
	attrMap[conntrack.AttrDccpHandshakeSeq] = "AttrDccpHandshakeSeq"
	attrMap[conntrack.AttrTCPWScaleOrig] = "AttrTCPWScaleOrig"
	attrMap[conntrack.AttrTCPWScaleRepl] = "AttrTCPWScaleRepl"
	attrMap[conntrack.AttrZone] = "AttrZone"
	attrMap[conntrack.AttrSecCtx] = "AttrSecCtx"
	attrMap[conntrack.AttrTimestampStart] = "AttrTimestampStart"
	attrMap[conntrack.AttrTimestampStop] = "AttrTimestampStop"
	attrMap[conntrack.AttrHelperInfo] = "AttrHelperInfo"
	attrMap[conntrack.AttrConnlabels] = "AttrConnlabels"
	attrMap[conntrack.AttrConnlabelsMask] = "AttrConnlabelsMask"
	attrMap[conntrack.AttrOrigzone] = "AttrOrigzone"
	attrMap[conntrack.AttrReplzone] = "AttrReplzone"
	attrMap[conntrack.AttrSNatIPv6] = "AttrSNatIPv6"
	attrMap[conntrack.AttrDNatIPv6] = "AttrDNatIPv6"

	var origDone, replyDone bool
	var attrs []string
	keys := make([]int, 0, len(c))
	for k := range c {
		keys = append(keys, int(k))
	}
	sort.Ints(keys)
	for _, uk := range keys {
		k := conntrack.ConnAttrType(uk)
		switch k {
		case conntrack.AttrStatus:
			attrs = append(attrs, fmt.Sprintf("status=%s", getCtStatus(c[k])))
		case conntrack.AttrHelperName:
			attrs = append(attrs, fmt.Sprintf("helper=%s", c[k]))
		case conntrack.AttrID:
			attrs = append(attrs, fmt.Sprintf("id=0x%x", c[k]))
		case conntrack.AttrMark:
			attrs = append(attrs, fmt.Sprintf("mark=0x%x", c[k]))
		case conntrack.AttrTimeout:
			attrs = append(attrs, fmt.Sprintf("timeout=%ds", binary.BigEndian.Uint32(c[k])))
		case conntrack.AttrOrigIPv4Src, conntrack.AttrOrigIPv4Dst, conntrack.AttrOrigIPv6Src, conntrack.AttrOrigIPv6Dst, conntrack.AttrOrigPortSrc, conntrack.AttrOrigPortDst, conntrack.AttrOrigL3Proto, conntrack.AttrOrigL4Proto, conntrack.AttrIcmpType, conntrack.AttrIcmpCode, conntrack.AttrIcmpID:
			if !origDone {
				attrs = append(attrs, formatEndpoints(c, true))
				origDone = true
			}
		case conntrack.AttrReplIPv4Src, conntrack.AttrReplIPv4Dst, conntrack.AttrReplIPv6Src, conntrack.AttrReplIPv6Dst, conntrack.AttrReplPortSrc, conntrack.AttrReplPortDst, conntrack.AttrReplL3Proto, conntrack.AttrReplL4Proto:
			if !replyDone {
				attrs = append(attrs, formatEndpoints(c, false))
				replyDone = true
			}
		default:
			if label, ok := attrMap[k]; ok {
				attrs = append(attrs, fmt.Sprintf("%s=%v", label, c[k]))
			} else {
				attrs = append(attrs, fmt.Sprintf("UNKNOWN:0x%x=%v", k, c[k]))
			}
		}

	}
	fmt.Printf(" CT: %s\n", strings.Join(attrs, ", "))

}

func formatEndpoints(c conntrack.Conn, orig bool) string {
	var ok bool
	var data []byte
	var prefix, proto, src, dst string
	var L3Proto, IPv4Src, IPv4Dst, IPv6Src, IPv6Dst, L4Proto, PortSrc, PortDst, IcmpCode, IcmpType, IcmpID conntrack.ConnAttrType
	if orig {
		prefix = "orig"
		L3Proto = conntrack.AttrOrigL3Proto
		IPv4Src = conntrack.AttrOrigIPv4Src
		IPv4Dst = conntrack.AttrOrigIPv4Dst
		IPv6Src = conntrack.AttrOrigIPv6Src
		IPv6Dst = conntrack.AttrOrigIPv6Dst
		L4Proto = conntrack.AttrOrigL4Proto
		PortSrc = conntrack.AttrOrigPortSrc
		PortDst = conntrack.AttrOrigPortDst
	} else {
		prefix = "reply"
		L3Proto = conntrack.AttrReplL3Proto
		IPv4Src = conntrack.AttrReplIPv4Src
		IPv4Dst = conntrack.AttrReplIPv4Dst
		IPv6Src = conntrack.AttrReplIPv6Src
		IPv6Dst = conntrack.AttrReplIPv6Dst
		L4Proto = conntrack.AttrReplL4Proto
		PortSrc = conntrack.AttrReplPortSrc
		PortDst = conntrack.AttrReplPortDst
	}
	IcmpCode = conntrack.AttrIcmpCode
	IcmpType = conntrack.AttrIcmpType
	IcmpID = conntrack.AttrIcmpID
	if data, ok = c[L3Proto]; ok {
		switch data[0] {
		case unix.AF_INET, unix.AF_INET6:
			if data[0] == unix.AF_INET {
				if data, ok = c[IPv4Src]; ok {
					src = fmt.Sprintf("%d.%d.%d.%d", data[0], data[1], data[2], data[3])
				}
				if data, ok = c[IPv4Dst]; ok {
					dst = fmt.Sprintf("%d.%d.%d.%d", data[0], data[1], data[2], data[3])
				}
			} else {
				if data, ok = c[IPv6Src]; ok {
					src = net.IP(data).String()
				}
				if data, ok = c[IPv6Dst]; ok {
					dst = net.IP(data).String()
				}
			}
			if data, ok = c[L4Proto]; ok {
				switch data[0] {
				case 6, 17:
					if data[0] == 6 {
						proto = "tcp"
					} else {
						proto = "udp"
					}
					if data, ok = c[PortSrc]; ok {
						src = fmt.Sprintf("%s:%d", src, binary.BigEndian.Uint16(data))
					}
					if data, ok = c[PortDst]; ok {
						dst = fmt.Sprintf("%s:%d", dst, binary.BigEndian.Uint16(data))
					}
				case 1, 58:
					if data[0] == 1 {
						proto = "icmp"
					} else {
						proto = "icmpv6"
					}
					if data, ok = c[IcmpCode]; ok {
						proto = fmt.Sprintf("%s:%d", proto, data[0])
					}
					if data, ok = c[IcmpType]; ok {
						proto = fmt.Sprintf("%s/%d", proto, data[0])
					}
					if data, ok = c[IcmpID]; ok {
						proto = fmt.Sprintf("%s/%d", proto, binary.BigEndian.Uint16(data))
					}
				default:
					proto = fmt.Sprintf("UNSUPPORTEDL4:0x%x", data)
				}
			}
		default:
			proto = fmt.Sprintf("UNSUPPORTED L3:0x%x", data)
		}
	}
	return fmt.Sprintf("%s=%s:%s->%s", prefix, proto, src, dst)
}

func getCtStatus(data []byte) string {
	var stati []string
	bitfield := binary.BigEndian.Uint32(data)
	if bitfield&(1<<0) == (1 << 0) {
		stati = append(stati, "EXPECTED")
	}
	if bitfield&(1<<1) == (1 << 1) {
		stati = append(stati, "SEEN_REPLY")
	}
	if bitfield&(1<<2) == (1 << 2) {
		stati = append(stati, "ASSURED")
	}
	if bitfield&(1<<3) == (1 << 3) {
		stati = append(stati, "CONFIRMED")
	}
	if bitfield&(1<<4) == (1 << 4) {
		stati = append(stati, "SRC_NAT")
	}
	if bitfield&(1<<5) == (1 << 5) {
		stati = append(stati, "DST_NAT")
	}
	if bitfield&(1<<6) == (1 << 6) {
		stati = append(stati, "SEQ_ADJUST")
	}
	if bitfield&(1<<7) == (1 << 7) {
		stati = append(stati, "SRC_NAT_DONE")
	}
	if bitfield&(1<<8) == (1 << 8) {
		stati = append(stati, "DST_NAT_DONE")
	}
	if bitfield&(1<<9) == (1 << 9) {
		stati = append(stati, "DYING")
	}
	if bitfield&(1<<10) == (1 << 10) {
		stati = append(stati, "FIXED_TIMEOUT")
	}
	if bitfield&(1<<11) == (1 << 11) {
		stati = append(stati, "TEMPLATE")
	}
	if bitfield&(1<<12) == (1 << 12) {
		stati = append(stati, "UNTRACKED")
	}
	if bitfield&(1<<13) == (1 << 13) {
		stati = append(stati, "HELPER")
	}
	if bitfield&(1<<14) == (1 << 14) {
		stati = append(stati, "OFFLOAD")
	}
	if bitfield&(1<<15) == (1 << 15) {
		stati = append(stati, "EXPECTED")
	}
	return strings.Join(stati, ",")
}
