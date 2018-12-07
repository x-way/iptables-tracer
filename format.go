package main

import (
	"fmt"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func formatPacketTCP(tcp *layers.TCP, src, dst string, length int) string {
	length = length - int(tcp.DataOffset)*4
	flags := ""
	if tcp.FIN {
		flags = flags + "F"
	}
	if tcp.SYN {
		flags = flags + "S"
	}
	if tcp.RST {
		flags = flags + "R"
	}
	if tcp.PSH {
		flags = flags + "P"
	}
	if tcp.ACK {
		flags = flags + "."
	}
	if tcp.URG {
		flags = flags + "U"
	}
	if tcp.ECE {
		flags = flags + "E"
	}
	if tcp.CWR {
		flags = flags + "W"
	}
	if tcp.NS {
		flags = flags + "N"
	}
	if flags == "" {
		flags = "none"
	}
	out := fmt.Sprintf("%s.%d > %s.%d: Flags [%s]", src, tcp.SrcPort, dst, tcp.DstPort, flags)
	if length > 0 || tcp.SYN || tcp.FIN || tcp.RST {
		if length > 0 {
			out += fmt.Sprintf(", seq %d:%d", tcp.Seq, int(tcp.Seq)+length)
		} else {
			out += fmt.Sprintf(", seq %d", tcp.Seq)
		}
	}
	if tcp.ACK {
		out += fmt.Sprintf(", ack %d", tcp.Ack)
	}
	out += fmt.Sprintf(", win %d", tcp.Window)
	if tcp.URG {
		out += fmt.Sprintf(", urg %d", tcp.Urgent)
	}
	out += fmt.Sprintf(", length %d", length)
	return out
}

func formatPacketICMPv6(packet *gopacket.Packet, icmp *layers.ICMPv6, src, dst string, length int) string {
	switch icmpType := icmp.TypeCode.Type(); icmpType {
	case layers.ICMPv6TypeEchoRequest:
		if echoLayer := (*packet).Layer(layers.LayerTypeICMPv6Echo); echoLayer != nil {
			echo, _ := echoLayer.(*layers.ICMPv6Echo)
			return fmt.Sprintf("%s > %s: ICMP6, echo request, id %d, seq %d, length %d", src, dst, echo.Identifier, echo.SeqNumber, length)
		}
		return fmt.Sprintf("%s > %s: ICMP6, echo request, length %d", src, dst, length)
	case layers.ICMPv6TypeEchoReply:
		if echoLayer := (*packet).Layer(layers.LayerTypeICMPv6Echo); echoLayer != nil {
			echo, _ := echoLayer.(*layers.ICMPv6Echo)
			return fmt.Sprintf("%s > %s: ICMP6, echo reply, id %d, seq %d, length %d", src, dst, echo.Identifier, echo.SeqNumber, length)
		}
		return fmt.Sprintf("%s > %s: ICMP6, echo reply, length %d", src, dst, length)
	default:
		return fmt.Sprintf("%s > %s: ICMP6, length %d", src, dst, length)
	}
}

func formatPacketICMPv4(icmp *layers.ICMPv4, src, dst string, length int) string {
	switch icmpType := icmp.TypeCode.Type(); icmpType {
	case layers.ICMPv4TypeEchoRequest:
		return fmt.Sprintf("%s > %s: ICMP echo request, id %d, seq %d, length %d", src, dst, icmp.Id, icmp.Seq, length)
	case layers.ICMPv4TypeEchoReply:
		return fmt.Sprintf("%s > %s: ICMP echo reply, id %d, seq %d, length %d", src, dst, icmp.Id, icmp.Seq, length)
	default:
		return fmt.Sprintf("%s > %s: ICMP, length %d", src, dst, length)
	}
}

func formatPacketDNS(dns *layers.DNS, src, dst string, srcPort, dstPort, length int) string {
	dnsStr := ""
	if dns.QR {
		dnsStr = fmt.Sprintf("%d", dns.ID)
		switch dns.OpCode {
		case layers.DNSOpCodeQuery:
			// nothing
		case layers.DNSOpCodeIQuery:
			dnsStr = dnsStr + " inv_q"
		case layers.DNSOpCodeStatus:
			dnsStr = dnsStr + " stat"
		case 3:
			dnsStr = dnsStr + " op3"
		case layers.DNSOpCodeNotify:
			dnsStr = dnsStr + " notify"
		case layers.DNSOpCodeUpdate:
			dnsStr = dnsStr + " update"
		case 6:
			dnsStr = dnsStr + " op6"
		case 7:
			dnsStr = dnsStr + " op7"
		case 8:
			dnsStr = dnsStr + " op8"
		case 9:
			dnsStr = dnsStr + " updateA"
		case 10:
			dnsStr = dnsStr + " updateD"
		case 11:
			dnsStr = dnsStr + " updateDA"
		case 12:
			dnsStr = dnsStr + " updateM"
		case 13:
			dnsStr = dnsStr + " updateMA"
		case 14:
			dnsStr = dnsStr + " zoneInit"
		case 15:
			dnsStr = dnsStr + " zoneRef"
		}
		switch dns.ResponseCode {
		case layers.DNSResponseCodeNoErr:
			// nothing
		case layers.DNSResponseCodeFormErr:
			dnsStr = dnsStr + " FormErr"
		case layers.DNSResponseCodeServFail:
			dnsStr = dnsStr + " ServFail"
		case layers.DNSResponseCodeNXDomain:
			dnsStr = dnsStr + " NXDomain"
		case layers.DNSResponseCodeNotImp:
			dnsStr = dnsStr + " NotImp"
		case layers.DNSResponseCodeRefused:
			dnsStr = dnsStr + " Refused"
		case layers.DNSResponseCodeYXDomain:
			dnsStr = dnsStr + " YXDomain"
		case layers.DNSResponseCodeYXRRSet:
			dnsStr = dnsStr + " YXRRSet"
		case layers.DNSResponseCodeNXRRSet:
			dnsStr = dnsStr + " NXRRSet"
		case layers.DNSResponseCodeNotAuth:
			dnsStr = dnsStr + " NotAuth"
		case layers.DNSResponseCodeNotZone:
			dnsStr = dnsStr + " NotZone"
		case 11:
			dnsStr = dnsStr + " Resp11"
		case 12:
			dnsStr = dnsStr + " Resp12"
		case 13:
			dnsStr = dnsStr + " Resp13"
		case 14:
			dnsStr = dnsStr + " Resp14"
		case 15:
			dnsStr = dnsStr + " NoChange"
		}
		if dns.AA {
			dnsStr = dnsStr + "*"
		}
		if !dns.RA {
			dnsStr = dnsStr + "-"
		}
		if dns.TC {
			dnsStr = dnsStr + "|"
		}
		if (dns.Z & 0x2) == 0x2 {
			dnsStr = dnsStr + "$"
		}

		if dns.QDCount != 1 {
			dnsStr = fmt.Sprintf("%s [%dq]", dnsStr, dns.QDCount)
		}
		dnsStr = fmt.Sprintf("%s %d/%d/%d", dnsStr, dns.ANCount, dns.NSCount, dns.ARCount)
		if dns.ANCount > 0 {
			for i, r := range dns.Answers {
				if i > 0 {
					dnsStr = dnsStr + ","
				}
				if r.Class != layers.DNSClassIN && r.Type != 41 {
					dnsStr = dnsStr + " " + r.Class.String()
				}
				dnsStr = dnsStr + " " + r.Type.String()

				switch r.Type {
				case layers.DNSTypeA, layers.DNSTypeAAAA:
					dnsStr = dnsStr + " " + r.IP.String()
				case layers.DNSTypeCNAME:
					dnsStr = dnsStr + " " + string(r.CNAME) + "."
				case layers.DNSTypeNS:
					dnsStr = dnsStr + " " + string(r.NS) + "."
				case layers.DNSTypeMX:
					dnsStr = fmt.Sprintf("%s %s. %d", dnsStr, string(r.MX.Name), r.MX.Preference)
				case layers.DNSTypeTXT:
					for _, s := range r.TXTs {
						dnsStr = fmt.Sprintf("%s \"%s\"", dnsStr, string(s))
					}
				case layers.DNSTypeSRV:
					dnsStr = fmt.Sprintf("%s %s.:%d %d %d", dnsStr, string(r.SRV.Name), r.SRV.Port, r.SRV.Priority, r.SRV.Weight)
				case layers.DNSTypeSOA:
					// nothing
				default:
					// nothing
				}
			}
		}
	} else {
		dnsStr = fmt.Sprintf("%d", dns.ID)
		if dns.RD {
			dnsStr = dnsStr + "+"
		}
		if (dns.Z & 0x1) == 0x1 {
			dnsStr = dnsStr + "%"
		}
		if dns.OpCode == layers.DNSOpCodeIQuery {
			if dns.QDCount > 0 {
				dnsStr = fmt.Sprintf("%s [%dq]", dnsStr, dns.QDCount)
			}
			if dns.ANCount != 1 {
				dnsStr = fmt.Sprintf("%s [%da]", dnsStr, dns.ANCount)
			}
		} else {
			if dns.ANCount > 0 {
				dnsStr = fmt.Sprintf("%s [%da]", dnsStr, dns.ANCount)
			}
			if dns.QDCount != 1 {
				dnsStr = fmt.Sprintf("%s [%dq]", dnsStr, dns.QDCount)
			}
		}
		if dns.NSCount > 0 {
			dnsStr = fmt.Sprintf("%s [%dn]", dnsStr, dns.NSCount)
		}
		if dns.ARCount > 0 {
			dnsStr = fmt.Sprintf("%s [%dau]", dnsStr, dns.ARCount)
		}
		if dns.QDCount > 0 {
			for _, q := range dns.Questions {
				dnsStr = dnsStr + " " + q.Type.String()
				if q.Class != layers.DNSClassIN {
					dnsStr = dnsStr + " " + q.Class.String()
				}
				dnsStr = dnsStr + "? " + string(q.Name) + "."
			}
		}
	}
	return fmt.Sprintf("%s.%d > %s.%d: %s (%d)", src, srcPort, dst, dstPort, dnsStr, length)
}

func formatPacketUDP(packet *gopacket.Packet, udp *layers.UDP, src, dst string) string {
	length := int(udp.Length) - 8
	if udp.SrcPort == 53 || udp.DstPort == 53 || udp.SrcPort == 5353 || udp.DstPort == 5353 {
		if dnsLayer := (*packet).Layer(layers.LayerTypeDNS); dnsLayer != nil {
			dns, _ := dnsLayer.(*layers.DNS)
			return formatPacketDNS(dns, src, dst, int(udp.SrcPort), int(udp.DstPort), length)
		}
	}
	return fmt.Sprintf("%s.%d > %s.%d: UDP, length %d", src, udp.SrcPort, dst, udp.DstPort, length)
}

func formatPacketOSPF(ospf layers.OSPF, src, dst string, length int) string {
	var ospfType string
	switch ospf.Type {
	case layers.OSPFHello:
		ospfType = "Hello"
	case layers.OSPFDatabaseDescription:
		ospfType = "Database Description"
	case layers.OSPFLinkStateRequest:
		ospfType = "LS-Request"
	case layers.OSPFLinkStateUpdate:
		ospfType = "LS-Update"
	case layers.OSPFLinkStateAcknowledgment:
		ospfType = "LS-Ack"
	default:
		if ospf.Version == 3 {
			ospfType = fmt.Sprintf("unknown packet type (%d)", ospf.Type)
		} else {
			ospfType = fmt.Sprintf("unknown LS-type %d", ospf.Type)
		}
	}
	return fmt.Sprintf("%s > %s: OSPFv%d, %s, length %d", src, dst, ospf.Version, ospfType, length)
}

func formatPacketGRE(gre *layers.GRE, src, dst string, length int) string {
	out := fmt.Sprintf("%s > %s: GREv%d", src, dst, gre.Version)
	switch gre.Version {
	case 0:
		if gre.ChecksumPresent || gre.RoutingPresent {
			out = out + fmt.Sprintf(", off 0x%x", gre.Offset)
		}
		if gre.KeyPresent {
			out = out + fmt.Sprintf(", key=0x%x", gre.Key)
		}
		if gre.SeqPresent {
			out = out + fmt.Sprintf(", seq %d", gre.Seq)
		}
		if gre.RoutingPresent {
			sre := gre.GRERouting
			for sre != nil {
				switch sre.AddressFamily {
				//				case 0x0800:
				//					out = out + fmt.Sprintf(", (rtaf=ip%s)")
				//				case 0xfffe:
				//					out = out + fmt.Sprintf(", (rtaf=asn%s)")
				default:
					out = out + fmt.Sprintf(", (rtaf=0x%x)", sre.AddressFamily)
				}

				sre = sre.Next
			}
		}
		out = out + fmt.Sprintf(", length %d: ", length)
		switch gre.Protocol {
		case layers.EthernetTypeIPv4:
			out = out + formatPacket(gre.LayerPayload(), false)
		case layers.EthernetTypeIPv6:
			out = out + formatPacket(gre.LayerPayload(), true)
		default:
			out = out + fmt.Sprintf("gre-proto-0x%x", gre.Protocol&0xffff)
		}
	case 1:
		if gre.KeyPresent {
			out = out + fmt.Sprintf(", call %d", gre.Key&0xffff)
		}
		if gre.SeqPresent {
			out = out + fmt.Sprintf(", seq %d", gre.Seq)
		}
		if gre.AckPresent {
			out = out + fmt.Sprintf(", ack %d", gre.Ack)
		}
		if !gre.SeqPresent {
			out = out + ", no-payload"
		}
		out = out + fmt.Sprintf(", length %d: ", length)
		if gre.SeqPresent {
			switch gre.Protocol {
			case layers.EthernetTypePPP:
				if pppLayer := gopacket.NewPacket(gre.LayerPayload(), layers.LayerTypePPP, gopacket.Default).Layer(layers.LayerTypePPP); pppLayer != nil {
					ppp, _ := pppLayer.(*layers.PPP)
					out = out + formatPacketPPP(ppp)
				}
			default:
				out = out + fmt.Sprintf("gre-proto-0x%x", gre.Protocol&0xffff)
			}
		}
	default:
		out = out + " ERROR: unknown-version"
	}
	return out
}

func formatPacketPPP(ppp *layers.PPP) string {
	switch ppp.PPPType {
	case layers.PPPTypeIPv4:
		return formatPacket(ppp.LayerPayload(), false)
	case layers.PPPTypeIPv6:
		return formatPacket(ppp.LayerPayload(), true)
	case layers.PPPTypeMPLSUnicast:
		return fmt.Sprintf("MPLS, length %d", len(ppp.LayerPayload()))
	case layers.PPPTypeMPLSMulticast:
		return fmt.Sprintf("MPLS, length %d", len(ppp.LayerPayload()))
	default:
		return fmt.Sprintf("unknown PPP protocol (0x%x)", ppp.PPPType)
	}
}

func formatPacket(payload []byte, isIPv6 bool) string {
	if isIPv6 {
		packet := gopacket.NewPacket(payload, layers.LayerTypeIPv6, gopacket.Default)
		if ip6Layer := packet.Layer(layers.LayerTypeIPv6); ip6Layer != nil {
			ip6, _ := ip6Layer.(*layers.IPv6)
			length := int(ip6.Length)
			switch ip6.NextLayerType() {
			case layers.LayerTypeUDP:
				if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
					udp, _ := udpLayer.(*layers.UDP)
					return "IP6 " + formatPacketUDP(&packet, udp, ip6.SrcIP.String(), ip6.DstIP.String())
				}
			case layers.LayerTypeTCP:
				if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
					tcp, _ := tcpLayer.(*layers.TCP)
					return "IP6 " + formatPacketTCP(tcp, ip6.SrcIP.String(), ip6.DstIP.String(), length)
				}
			case layers.LayerTypeICMPv6:
				if icmpLayer := packet.Layer(layers.LayerTypeICMPv6); icmpLayer != nil {
					icmp, _ := icmpLayer.(*layers.ICMPv6)
					return "IP6 " + formatPacketICMPv6(&packet, icmp, ip6.SrcIP.String(), ip6.DstIP.String(), length)
				}
			case layers.LayerTypeOSPF:
				if ospfLayer := packet.Layer(layers.LayerTypeOSPF); ospfLayer != nil {
					ospf, _ := ospfLayer.(*layers.OSPFv3)
					return "IP6 " + formatPacketOSPF(ospf.OSPF, ip6.SrcIP.String(), ip6.DstIP.String(), length)
				}
			case layers.LayerTypeGRE:
				if greLayer := packet.Layer(layers.LayerTypeGRE); greLayer != nil {
					gre, _ := greLayer.(*layers.GRE)
					return "IP6 " + formatPacketGRE(gre, ip6.SrcIP.String(), ip6.DstIP.String(), length)
				}
			case layers.LayerTypeIPv4:
				return fmt.Sprintf("IP6 %s > %s: %s", ip6.SrcIP, ip6.DstIP, formatPacket(ip6.LayerPayload(), false))
			}
			return fmt.Sprintf("IP6 %s > %s: %s, length %d", ip6.SrcIP, ip6.DstIP, ip6.NextLayerType().String(), length)
		}
	} else {
		packet := gopacket.NewPacket(payload, layers.LayerTypeIPv4, gopacket.Default)
		if ip4Layer := packet.Layer(layers.LayerTypeIPv4); ip4Layer != nil {
			ip4, _ := ip4Layer.(*layers.IPv4)
			length := int(ip4.Length) - int(ip4.IHL)*4
			switch ip4.NextLayerType() {
			case layers.LayerTypeUDP:
				if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
					udp, _ := udpLayer.(*layers.UDP)
					return "IP " + formatPacketUDP(&packet, udp, ip4.SrcIP.String(), ip4.DstIP.String())
				}
			case layers.LayerTypeTCP:
				if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
					tcp, _ := tcpLayer.(*layers.TCP)
					return "IP " + formatPacketTCP(tcp, ip4.SrcIP.String(), ip4.DstIP.String(), length)
				}
			case layers.LayerTypeICMPv4:
				if icmpLayer := packet.Layer(layers.LayerTypeICMPv4); icmpLayer != nil {
					icmp, _ := icmpLayer.(*layers.ICMPv4)
					return "IP " + formatPacketICMPv4(icmp, ip4.SrcIP.String(), ip4.DstIP.String(), length)
				}
			case layers.LayerTypeOSPF:
				if ospfLayer := packet.Layer(layers.LayerTypeOSPF); ospfLayer != nil {
					ospf, _ := ospfLayer.(*layers.OSPFv2)
					if ospf.AuType == 2 {
						length = length - 16
					}
					return "IP " + formatPacketOSPF(ospf.OSPF, ip4.SrcIP.String(), ip4.DstIP.String(), length)
				}
			case layers.LayerTypeGRE:
				if greLayer := packet.Layer(layers.LayerTypeGRE); greLayer != nil {
					gre, _ := greLayer.(*layers.GRE)
					return "IP " + formatPacketGRE(gre, ip4.SrcIP.String(), ip4.DstIP.String(), length)
				}
			case layers.LayerTypeIPv6:
				return fmt.Sprintf("IP %s > %s: %s", ip4.SrcIP, ip4.DstIP, formatPacket(ip4.LayerPayload(), true))
			}
			return fmt.Sprintf("IP %s > %s: %s, length %d", ip4.SrcIP, ip4.DstIP, ip4.NextLayerType().String(), length)
		}
	}
	return ""
}
