package main

import (
	"regexp"
	"strconv"
)

func clearIptablesPolicy(policy []string, cleanupID int) []string {
	var newIptablesConfig []string
	iptrRe := regexp.MustCompile(`\s+--nflog-prefix\s+"iptr:(\d+):\d+"`)
	limitRe := regexp.MustCompile(`\s+--comment\s+"iptr:(\d+):limit"`)
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
