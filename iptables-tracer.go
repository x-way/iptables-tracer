package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"time"

	"github.com/florianl/go-nflog"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"golang.org/x/sys/unix"
)

type iptablesRule struct {
	Table      string
	Chain      string
	Rule       string
	ChainEntry bool
}

var (
	traceDuration = flag.Duration("t", 10*time.Second, "how long to run the iptables-tracer")
	nflogGroup    = flag.Int("n", 22, "NFLOG group number to use")
	traceFilter   = flag.String("f", "-d 1.1.1.1", "trace filter (iptables match syntax)")
	traceID       = flag.Int("i", 0, "trace id (0 = use PID)")
	traceRules    = flag.Bool("r", false, "trace rules in addition to chains (experimental, currently broken!)")
	clearRules    = flag.Bool("c", false, "clear all iptables-tracer iptables rules from running config")
	fwMark        = flag.Int("m", 0, "fwmark to use for packet tracking")
	packetLimit   = flag.Int("l", 0, "limit of packets per minute to trace (0 = no limit)")
)

func main() {

	flag.Parse()

	var err error

	ruleMap := make(map[int]iptablesRule)
	chainMap := make(map[string][]string)

	if *traceID == 0 {
		*traceID = os.Getpid()
	}

	if *clearRules {
		cleanupIptables(0) // 0 -> clear all IDs
		return
	}

	chainRe := regexp.MustCompile(`^:(\S+)`)
	tableRe := regexp.MustCompile(`^\*(\S+)`)
	ruleRe := regexp.MustCompile(`^-[AI]\s+(\S+)\s+(.*)$`)
	commitRe := regexp.MustCompile(`^COMMIT`)

	var newIptablesConfig []string
	var lines []string

	if lines, err = readFromCommand(exec.Command("iptables-save")); err != nil {
		log.Fatal(err)
	}

	markFilter := ""
	if *fwMark != 0 {
		markFilter = fmt.Sprintf("-m mark --mark 0x%x/0x%x", *fwMark, *fwMark)

	}
	if *packetLimit != 0 && *fwMark == 0 {
		log.Fatal("Error: limit requires fwmark")
	}

	table := ""
	ruleIndex := 0
	maxLength := 0
	for _, line := range lines {
		if res := chainRe.FindStringSubmatch(line); res != nil {
			if table == "" {
				log.Fatal("Error: found chain definition before initial table definition")
			}
			chainMap[table] = append(chainMap[table], res[1])
			if len(res[1]) > maxLength {
				maxLength = len(res[1])
			}
		}
		if res := commitRe.FindStringSubmatch(line); res != nil {
			// we are at the end of a table, add aritificial rules for all chains in this table
			for _, chain := range chainMap[table] {
				ruleMap[ruleIndex] = iptablesRule{Table: table, Chain: chain, ChainEntry: true}
				traceRule := fmt.Sprintf("-I %s %s %s -j NFLOG --nflog-prefix \"iptr:%d:%d\" --nflog-group %d", chain, *traceFilter, markFilter, *traceID, ruleIndex, *nflogGroup)
				ruleIndex++
				newIptablesConfig = append(newIptablesConfig, traceRule)
				if table == "raw" && chain == "PREROUTING" && *packetLimit != 0 {
					newIptablesConfig = append(newIptablesConfig, fmt.Sprintf("-I %s %s -m comment --comment \"iptr:%d:limit\" -m limit --limit %d/minute --limit-burst 1 -j MARK --set-xmark 0x%x/0x%x", chain, *traceFilter, *traceID, *packetLimit, *fwMark, *fwMark))
				}
			}
		}
		if res := tableRe.FindStringSubmatch(line); res != nil {
			table = res[1]
		}
		if res := ruleRe.FindStringSubmatch(line); res != nil && *traceRules {
			if table == "" {
				log.Fatal("Error: found rule definition before initial table definition")
			}
			ruleMap[ruleIndex] = iptablesRule{Table: table, Chain: res[1], Rule: res[2]}
			traceRule := fmt.Sprintf("-A %s %s %s -j NFLOG --nflog-prefix \"iptr:%d:%d\" --nflog-group %d", res[1], *traceFilter, markFilter, *traceID, ruleIndex, *nflogGroup)
			ruleIndex++
			newIptablesConfig = append(newIptablesConfig, traceRule)
		}
		newIptablesConfig = append(newIptablesConfig, line)
	}

	if err = writeToCommand(exec.Command("iptables-restore", "-t"), newIptablesConfig); err != nil {
		log.Fatal(err)
	}
	if err = writeToCommand(exec.Command("iptables-restore"), newIptablesConfig); err != nil {
		log.Fatal(err)
	}
	defer cleanupIptables(*traceID)

	var nf *nflog.Nflog
	nf, err = nflog.Open()
	if err != nil {
		log.Fatal(err)
	}
	defer nf.Close()

	ctx, cancel := context.WithTimeout(context.Background(), *traceDuration)
	defer cancel()

	callback := func(m nflog.Msg) int {
		prefix := string(m[nflog.NfUlaAttrPrefix])
		prefixRe := regexp.MustCompile(`^iptr:(\d+):(\d+)`)
		if res := prefixRe.FindStringSubmatch(prefix); res != nil {
			if id, _ := strconv.Atoi(res[1]); id == *traceID {
				ruleID, _ := strconv.Atoi(res[2])
				if myRule, ok := ruleMap[ruleID]; ok {
					printRule(maxLength, time.Now(), myRule, m[nflog.NfUlaAttrMark], getIfaceName(m[nflog.NfUlaAttrIfindexIndev]), getIfaceName(m[nflog.NfUlaAttrIfindexOutdev]), m[nflog.NfUlaAttrPayload])
				}
			}
		}
		return 0
	}

	err = nf.Register(ctx, unix.AF_INET, *nflogGroup, nflog.NfUlnlCopyPacket, callback)
	if err != nil {
		log.Fatal(err)
	}

	select {
	// block until context expires
	case <-ctx.Done():
	}
}

func getIfaceName(data []byte) string {
	var iface *net.Interface
	var err error
	reader := bytes.NewReader(data)
	var index uint32
	binary.Read(reader, binary.BigEndian, &index)
	if iface, err = net.InterfaceByIndex(int(index)); err != nil {
		return ""
	}
	return iface.Name
}

func formatPacket(packet gopacket.Packet) string {
	if ip4Layer := packet.Layer(layers.LayerTypeIPv4); ip4Layer != nil {
		ip4, _ := ip4Layer.(*layers.IPv4)
		length := int(ip4.Length) - int(ip4.IHL)*4
		if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
			udp, _ := udpLayer.(*layers.UDP)
			length = int(udp.Length) - 8
			udpFlowStr := fmt.Sprintf("%s.%d > %s.%d:", ip4.SrcIP, udp.SrcPort, ip4.DstIP, udp.DstPort)
			if udp.SrcPort == 53 || udp.DstPort == 53 || udp.SrcPort == 5353 || udp.DstPort == 5353 {
				if dnsLayer := packet.Layer(layers.LayerTypeDNS); dnsLayer != nil {
					dns, _ := dnsLayer.(*layers.DNS)
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
								case layers.DNSTypeSOA:
									// nothing
								case layers.DNSTypeMX:
									dnsStr = fmt.Sprintf("%s %s. %d", dnsStr, string(r.MX.Name), r.MX.Preference)
								case layers.DNSTypeTXT:
									for _, s := range r.TXTs {
										dnsStr = fmt.Sprintf("%s \"%s\"", dnsStr, string(s))
									}
								case layers.DNSTypeSRV:
									dnsStr = fmt.Sprintf("%s %s.:%d %d %d", dnsStr, string(r.SRV.Name), r.SRV.Port, r.SRV.Priority, r.SRV.Weight)
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
					return fmt.Sprintf("%s %s (%d)", udpFlowStr, dnsStr, length)
				}
			}
			return fmt.Sprintf("%s UDP, length %d", udpFlowStr, length)
		}
		if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
			tcp, _ := tcpLayer.(*layers.TCP)
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
			return fmt.Sprintf("%s.%d > %s.%d: Flags [%s], seq %d, win %d, length %d", ip4.SrcIP, tcp.SrcPort, ip4.DstIP, tcp.DstPort, flags, tcp.Seq, tcp.Window, length)
		}
		if icmpLayer := packet.Layer(layers.LayerTypeICMPv4); icmpLayer != nil {
			icmp, _ := icmpLayer.(*layers.ICMPv4)
			switch icmpType := icmp.TypeCode.Type(); icmpType {
			case layers.ICMPv4TypeEchoRequest:
				return fmt.Sprintf("%s > %s: ICMP echo request, id %d, seq %d, length %d", ip4.SrcIP, ip4.DstIP, icmp.Id, icmp.Seq, length)
			case layers.ICMPv4TypeEchoReply:
				return fmt.Sprintf("%s > %s: ICMP echo reply, id %d, seq %d, length %d", ip4.SrcIP, ip4.DstIP, icmp.Id, icmp.Seq, length)
			default:
				return fmt.Sprintf("%s > %s: ICMP, length %d", ip4.SrcIP, ip4.DstIP, length)
			}
		}
		return fmt.Sprintf("%s > %s: %s, length %d", ip4.SrcIP, ip4.DstIP, ip4.NextLayerType().String(), length)
	}
	return ""
}

func printRule(maxLength int, ts time.Time, rule iptablesRule, fwMark []byte, iif string, oif string, payload []byte) {
	packetStr := formatPacket(gopacket.NewPacket(payload, layers.LayerTypeIPv4, gopacket.Default))
	if rule.ChainEntry {
		fmtStr := fmt.Sprintf("%%s %%-6s %%-%ds 0x%%08x %%s  [In:%%s Out:%%s]\n", maxLength)
		fmt.Printf(fmtStr, ts.Format("15:04:05.000000"), rule.Table, rule.Chain, fwMark, packetStr, iif, oif)
	} else {
		fmtStr := fmt.Sprintf("%%s %%-6s %%-%ds %%s 0x%%08x %%s  [In:%%s Out:%%s]\n", maxLength)
		fmt.Printf(fmtStr, ts.Format("15:04:05.000000"), rule.Table, rule.Chain, rule.Rule, fwMark, packetStr, iif, oif)
	}
}

func writeToCommand(cmd *exec.Cmd, lines []string) error {
	cmdWriter, err := cmd.StdinPipe()
	if err != nil {
		return err
	}
	if err = cmd.Start(); err != nil {
		return err
	}
	for _, line := range lines {
		io.WriteString(cmdWriter, line+"\n")
	}
	cmdWriter.Close()
	return cmd.Wait()
}

func readFromCommand(cmd *exec.Cmd) ([]string, error) {
	var cmdReader io.ReadCloser
	var lines []string
	cmdReader, err := cmd.StdoutPipe()
	if err != nil {
		return lines, err
	}
	scanner := bufio.NewScanner(cmdReader)
	if err = cmd.Start(); err != nil {
		return lines, err
	}
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	if err = scanner.Err(); err != nil {
		return lines, err
	}
	if err = cmd.Wait(); err != nil {
		return lines, err
	}
	return lines, nil
}

func cleanupIptables(cleanupID int) {
	var err error

	var lines []string
	var newIptablesConfig []string

	if lines, err = readFromCommand(exec.Command("iptables-save")); err != nil {
		log.Fatal(err)
	}
	iptrRe := regexp.MustCompile(`\s+--nflog-prefix\s+"iptr:(\d+):\d+"`)
	limitRe := regexp.MustCompile(`\s+--comment\s+"iptr:(\d+):limit"`)
	for _, line := range lines {
		if res := iptrRe.FindStringSubmatch(line); res != nil {
			if id, _ := strconv.Atoi(res[1]); id == cleanupID || cleanupID == 0 {
				continue
			}
		}
		if res := limitRe.FindStringSubmatch(line); res != nil {
			if id, _ := strconv.Atoi(res[1]); id == cleanupID || cleanupID == 0 {
				continue
			}
		}
		newIptablesConfig = append(newIptablesConfig, line)
	}

	if err = writeToCommand(exec.Command("iptables-restore", "-t"), newIptablesConfig); err != nil {
		log.Fatal(err)
	}
	if err = writeToCommand(exec.Command("iptables-restore"), newIptablesConfig); err != nil {
		log.Fatal(err)
	}
}
