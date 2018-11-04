package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"github.com/florianl/go-nflog"
	"golang.org/x/sys/unix"
	"io"
	"log"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"time"
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
	if *packetLimit != 0 &&
		*fwMark == 0 {
		log.Fatal("Error: limit requires fwmark")
	}

	table := ""
	ruleIndex := 0
	for _, line := range lines {
		if res := chainRe.FindStringSubmatch(line); res != nil {
			if table == "" {
				log.Fatal("Error: found chain definition before initial table definition")
			}
			chainMap[table] = append(chainMap[table], res[1])
		}
		if res := commitRe.FindStringSubmatch(line); res != nil {
			// we are at the end of a table, add aritificial rules for all chains in this table
			for _, chain := range chainMap[table] {
				ruleMap[ruleIndex] = iptablesRule{Table: table, Chain: chain, ChainEntry: true}
				traceRule := fmt.Sprintf("-I %s %s %s -j NFLOG --nflog-prefix \"iptr:%d:%d\" --nflog-group %d", chain, *traceFilter, markFilter, *traceID, ruleIndex, *nflogGroup)
				ruleIndex++
				newIptablesConfig = append(newIptablesConfig, traceRule)
				if table == "raw" && chain == "PREROUTING" {
					newIptablesConfig = append(newIptablesConfig, fmt.Sprintf("-I %s %s -m limit --limit %d/minute --limit-burst 1 -j MARK --set-xmark 0x%x/0x%x", chain, *traceFilter, *packetLimit, *fwMark, *fwMark))
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
				ts := time.Now()
				if myRule, ok := ruleMap[ruleID]; ok {
					printRule(ts, myRule)
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

func printRule(ts time.Time, rule iptablesRule) {
	if rule.ChainEntry {
		fmt.Printf("%s %-6s %-30s\n", ts.Format(time.StampMilli), rule.Table, rule.Chain)
	} else {
		fmt.Printf("%s %-6s %-30s %s\n", ts.Format(time.StampMilli), rule.Table, rule.Chain, rule.Rule)
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
	if err = cmd.Wait(); err != nil {
		return err
	}
	return nil
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
	limitRe := regexp.MustCompile(`-A PREROUTING .* -m limit --limit (\d+)/minute --limit-burst \d+ -j MARK --set-xmark 0x([0-9a-f]+)/0x([0-9a-f]+)`)
	for _, line := range lines {
		if res := iptrRe.FindStringSubmatch(line); res != nil {
			if id, _ := strconv.Atoi(res[1]); id == cleanupID || cleanupID == 0 {
				continue
			}
		}
		if res := limitRe.FindStringSubmatch(line); res != nil {
			if limit, _ := strconv.Atoi(res[1]); limit == *packetLimit {
				if mark, _ := strconv.ParseInt(res[2], 16, 32); int(mark) == *fwMark {
					if mask, _ := strconv.ParseInt(res[3], 16, 32); int(mask) == *fwMark {
						continue
					}
				}
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
