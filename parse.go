package main

import (
	"fmt"
	"log"
	"regexp"
	"strconv"
	"strings"
)

func extendIptablesPolicy(lines []string, traceID int, traceFilter string, fwMark, packetLimit int, traceRules bool, nflogGroup int) ([]string, map[int]iptablesRule, int) {
	var newIptablesConfig []string
	maxChainNameLength := 0
	ruleMap := make(map[int]iptablesRule)
	chainMap := make(map[string][]string)

	chainRe := regexp.MustCompile(`^:(\S+)`)
	tableRe := regexp.MustCompile(`^\*(\S+)`)
	ruleRe := regexp.MustCompile(`^-[AI]\s+(\S+)\s+(.*)$`)
	commitRe := regexp.MustCompile(`^COMMIT`)

	markFilter := ""
	if fwMark != 0 {
		markFilter = fmt.Sprintf("-m mark --mark 0x%x/0x%x", fwMark, fwMark)
	}

	table := ""
	ruleIndex := 0
	for _, line := range lines {
		if res := chainRe.FindStringSubmatch(line); res != nil {
			if table == "" {
				log.Fatal("Error: found chain definition before initial table definition")
			}
			chainMap[table] = append(chainMap[table], res[1])
			if len(res[1]) > maxChainNameLength {
				maxChainNameLength = len(res[1])
			}
		}
		if res := commitRe.FindStringSubmatch(line); res != nil {
			// we are at the end of a table, add aritificial rules for all chains in this table
			for _, chain := range chainMap[table] {
				ruleMap[ruleIndex] = iptablesRule{Table: table, Chain: chain, ChainEntry: true}
				traceRule := buildTraceRule("-I", chain, traceFilter, markFilter, traceID, ruleIndex, nflogGroup)
				ruleIndex++
				newIptablesConfig = append(newIptablesConfig, traceRule)
				if table == "raw" && chain == "PREROUTING" && packetLimit != 0 {
					newIptablesConfig = append(newIptablesConfig, buildMarkRule("-I", chain, traceFilter, traceID, packetLimit, fwMark))
				}
			}
		}
		if res := tableRe.FindStringSubmatch(line); res != nil {
			table = res[1]
		}
		if res := ruleRe.FindStringSubmatch(line); res != nil && traceRules {
			if table == "" {
				log.Fatal("Error: found rule definition before initial table definition")
			}
			ruleMap[ruleIndex] = iptablesRule{Table: table, Chain: res[1], Rule: res[2]}
			traceRule := buildTraceRule("-A", res[1], traceFilter, markFilter, traceID, ruleIndex, nflogGroup)
			ruleIndex++
			newIptablesConfig = append(newIptablesConfig, traceRule)
		}
		newIptablesConfig = append(newIptablesConfig, line)
	}

	return newIptablesConfig, ruleMap, maxChainNameLength
}

func clearIptablesPolicy(policy []string, cleanupID int) []string {
	var newIptablesConfig []string
	iptrRe := regexp.MustCompile(`\s+--nflog-prefix\s+"iptr:(\d+):\d+"`)
	limitRe := regexp.MustCompile(`\s+--comment\s+"iptr:(\d+):mark"`)
	for _, line := range policy {
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
	return newIptablesConfig
}

func buildMarkRule(command, chain, traceFilter string, traceID, packetLimit, fwMark int) string {
	rule := []string{command, chain}
	if traceFilter != "" {
		rule = append(rule, traceFilter)
	}
	rule = append(rule, fmt.Sprintf("-m comment --comment \"iptr:%d:mark\"", traceID))
	if packetLimit != 0 {
		rule = append(rule, fmt.Sprintf("-m limit --limit %d/minute --limit-burst 1", packetLimit))
	}
	rule = append(rule, fmt.Sprintf("-j MARK --set-xmark 0x%x/0x%x", fwMark, fwMark))
	return strings.Join(rule, " ")
}

func buildTraceRule(command, chain, traceFilter, markFilter string, traceID, ruleIndex, nflogGroup int) string {
	rule := []string{command, chain}
	if traceFilter != "" {
		rule = append(rule, traceFilter)
	}
	if markFilter != "" {
		rule = append(rule, markFilter)
	}
	rule = append(rule, fmt.Sprintf("-j NFLOG --nflog-prefix \"iptr:%d:%d\" --nflog-group %d", traceID, ruleIndex, nflogGroup))
	return strings.Join(rule, " ")
}
