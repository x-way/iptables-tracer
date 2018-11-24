package main

import (
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

func getTcpdumpOutput(filename string) string {
	out, err := exec.Command("tcpdump", "-S", "-t", "-n", "-r", filename).Output()
	if err != nil {
		log.Fatal(err)
	}
	return string(out)
}

func getFormatPacketOutput(filename string) string {
	f, _ := os.Open(filename)
	defer f.Close()
	handle, err := pcapgo.NewReader(f)
	if err != nil {
		log.Fatal(err)
	}
	out := ""
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		if ip4 := packet.Layer(layers.LayerTypeIPv4); ip4 != nil {
			out = out + formatPacket(append(ip4.LayerContents(), ip4.LayerPayload()...), false) + "\n"
		} else if ip6 := packet.Layer(layers.LayerTypeIPv6); ip6 != nil {
			out = out + formatPacket(append(ip6.LayerContents(), ip6.LayerPayload()...), true) + "\n"
		} else {
			log.Fatal("Non-IP packet found in " + filename)
		}
	}
	return out
}

func TestFormatPacketPCAP(t *testing.T) {
	files, err := ioutil.ReadDir("./tests")
	if err != nil {
		log.Fatal(err)
	}
	for _, f := range files {
		if filepath.Ext(f.Name()) == ".pcap" {
			expected := getTcpdumpOutput("./tests/" + f.Name())
			got := getFormatPacketOutput("./tests/" + f.Name())
			if got != expected {
				t.Errorf("pcap test failed for %s, got '%s', expected '%s'", f.Name(), got, expected)
			}
		}
	}
}
