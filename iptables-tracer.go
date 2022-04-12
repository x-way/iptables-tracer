package main

import (
	"bufio"
	"context"
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

	"github.com/florianl/go-nflog/v2"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/mdlayher/netlink"
	"github.com/x-way/iptables-tracer/pkg/ctprint"
	"github.com/x-way/pktdump"
)

type iptablesRule struct {
	Table      string
	Chain      string
	Rule       string
	ChainEntry bool
}

type msg struct {
	Time    time.Time
	Rule    iptablesRule
	Mark    uint32
	Iif     string
	Oif     string
	Payload []byte
	Ct      []byte
	CtInfo  uint32
}

var (
	traceDuration  = flag.Duration("t", 10*time.Second, "how long to run the iptables-tracer")
	packetGap      = flag.Duration("g", 10*time.Millisecond, "output empty line when two loglines are separated by at least this duration")
	nflogGroup     = flag.Int("n", 22, "NFLOG group number to use")
	traceFilter    = flag.String("f", "-p udp --dport 53", "trace filter (iptables match syntax)")
	traceID        = flag.Int("i", 0, "trace id (0 = use PID)")
	traceRules     = flag.Bool("r", false, "trace rules in addition to chains (experimental, currently broken!)")
	clearRules     = flag.Bool("c", false, "clear all iptables-tracer iptables rules from running config")
	fwMark         = flag.Int("m", 0, "fwmark to use for packet tracking")
	packetLimit    = flag.Int("l", 0, "limit of packets per minute to trace (0 = no limit)")
	ip6tables      = flag.Bool("6", false, "use ip6tables")
	debugConntrack = flag.Bool("x", false, "dump all conntrack information")
	saveCommand    string
	restoreCommand string
)

func main() {
	flag.Parse()

	if *ip6tables {
		saveCommand = "ip6tables-save"
		restoreCommand = "ip6tables-restore"
	} else {
		saveCommand = "iptables-save"
		restoreCommand = "iptables-restore"
	}

	var err error

	if *traceID == 0 {
		*traceID = os.Getpid()
	}

	if *clearRules {
		cleanupIptables(0) // 0 -> clear all IDs
		return
	}

	if (*packetLimit != 0 || *traceRules) && *fwMark == 0 {
		log.Fatal("Error: limit or trace rules requires fwmark")
	}

	lines := iptablesSave()
	newIptablesConfig, ruleMap, maxLength := extendIptablesPolicy(lines, *traceID, *traceFilter, *fwMark, *packetLimit, *traceRules, *nflogGroup)
	iptablesRestore(newIptablesConfig)

	defer cleanupIptables(*traceID)

	var nf *nflog.Nflog
	config := nflog.Config{
		Group:       uint16(*nflogGroup),
		Copymode:    nflog.CopyPacket,
		Flags:       nflog.FlagConntrack,
		ReadTimeout: time.Second,
	}
	nf, err = nflog.Open(&config)
	if err != nil {
		log.Fatal(err)
	}
	defer nf.Close()

	ctx, cancel := context.WithTimeout(context.Background(), *traceDuration)
	defer cancel()

	msgChannel := make(chan msg)

	callback := func(m nflog.Attribute) int {
		var prefix string
		if m.Prefix != nil {
			prefix = *m.Prefix
		}
		prefixRe := regexp.MustCompile(`^iptr:(\d+):(\d+)`)
		if res := prefixRe.FindStringSubmatch(prefix); res != nil {
			if id, _ := strconv.Atoi(res[1]); id == *traceID {
				ruleID, _ := strconv.Atoi(res[2])
				if myRule, ok := ruleMap[ruleID]; ok {
					var fwMark uint32
					var iif string
					var oif string
					var ctBytes []byte
					ctInfo := ^uint32(0)
					if m.Mark != nil {
						fwMark = *m.Mark
					}
					if m.InDev != nil {
						iif = GetIfaceName(*m.InDev)
					}
					if m.OutDev != nil {
						oif = GetIfaceName(*m.OutDev)
					}
					if m.Ct != nil {
						ctBytes = *m.Ct
					}
					if m.CtInfo != nil {
						ctInfo = *m.CtInfo
					}
					if m.Payload != nil {
						msgChannel <- msg{
							Time:    time.Now(),
							Rule:    myRule,
							Mark:    fwMark,
							Iif:     iif,
							Oif:     oif,
							Payload: *m.Payload,
							Ct:      ctBytes,
							CtInfo:  ctInfo,
						}
					}
				}
			}
		}
		return 0
	}

	go func() {
		var lastTime time.Time
		for msg := range msgChannel {
			if msg.Time.Sub(lastTime).Nanoseconds() > (*packetGap).Nanoseconds() && !lastTime.IsZero() {
				fmt.Println("")
			}
			lastTime = msg.Time
			printRule(maxLength, msg.Time, msg.Rule, msg.Mark, msg.Iif, msg.Oif, msg.Payload, msg.Ct, msg.CtInfo)
			if *debugConntrack && len(msg.Ct) > 0 {
				ctprint.Print(msg.Ct)
			}
		}
	}()

	errorFunc := func(err error) int {
		if opError, ok := err.(*netlink.OpError); ok {
			if opError.Timeout() || opError.Temporary() {
				return 0
			}
		}
		log.Fatalf("Could not receive message: %v\n", err)
		return 1
	}

	err = nf.RegisterWithErrorFunc(ctx, callback, errorFunc)
	if err != nil {
		log.Fatal(err)
	}

	// block until context expires
	<-ctx.Done()
	close(msgChannel)
}

func printRule(maxLength int, ts time.Time, rule iptablesRule, fwMark uint32, iif, oif string, payload, ct []byte, ctInfo uint32) {
	packetStr := ""
	if *ip6tables {
		packetStr = pktdump.Format(gopacket.NewPacket(payload, layers.LayerTypeIPv6, gopacket.Default))
	} else {
		packetStr = pktdump.Format(gopacket.NewPacket(payload, layers.LayerTypeIPv4, gopacket.Default))
	}
	ctStr := fmt.Sprintf(" %s 0x%08x", ctprint.InfoString(ctInfo), ctprint.GetCtMark(ct))
	if rule.ChainEntry {
		fmtStr := fmt.Sprintf("%%s %%-6s %%-%ds 0x%%08x%%s %%s  [In:%%s Out:%%s]\n", maxLength)
		fmt.Printf(fmtStr, ts.Format("15:04:05.000000"), rule.Table, rule.Chain, fwMark, ctStr, packetStr, iif, oif)
	} else {
		fmtStr := fmt.Sprintf("%%s %%-6s %%-%ds %%s 0x%%08x%%s %%s  [In:%%s Out:%%s]\n", maxLength)
		fmt.Printf(fmtStr, ts.Format("15:04:05.000000"), rule.Table, rule.Chain, rule.Rule, fwMark, ctStr, packetStr, iif, oif)
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
		if _, err := io.WriteString(cmdWriter, line+"\n"); err != nil {
			log.Fatal(err)
		}
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

func iptablesSave() []string {
	var err error
	var lines []string

	if lines, err = readFromCommand(exec.Command(saveCommand)); err != nil {
		log.Fatal(err)
	}

	return lines
}

func iptablesRestore(policy []string) {
	if err := writeToCommand(exec.Command(restoreCommand, "-t"), policy); err != nil {
		log.Fatal(err)
	}
	if err := writeToCommand(exec.Command(restoreCommand), policy); err != nil {
		log.Fatal(err)
	}
}

func cleanupIptables(cleanupID int) {
	iptablesRestore(clearIptablesPolicy(iptablesSave(), cleanupID))
}

// GetIfaceName takes a network interface index and returns the corresponding name
func GetIfaceName(index uint32) string {
	var iface *net.Interface
	var err error
	if iface, err = net.InterfaceByIndex(int(index)); err != nil {
		return ""
	}
	return iface.Name
}
