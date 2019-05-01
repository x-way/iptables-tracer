package format

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
		if net := packet.NetworkLayer(); net != nil {
			switch net.LayerType() {
			case layers.LayerTypeIPv4:
				out = out + FormatPacket(append(net.LayerContents(), net.LayerPayload()...), false) + "\n"
			case layers.LayerTypeIPv6:
				out = out + FormatPacket(append(net.LayerContents(), net.LayerPayload()...), true) + "\n"
			default:
				log.Fatal("Non-IP packet found in " + filename)
			}
		} else {
			log.Fatal("Non-IP packet found in " + filename)
		}
	}
	return out
}

func TestFormatPacketPCAP(t *testing.T) {
	files, err := ioutil.ReadDir("../../tests")
	if err != nil {
		log.Fatal(err)
	}
	for _, f := range files {
		if filepath.Ext(f.Name()) == ".pcap" {
			expected := getTcpdumpOutput("../../tests/" + f.Name())
			got := getFormatPacketOutput("../../tests/" + f.Name())
			if got != expected {
				t.Errorf("pcap test failed for %s, got '%s', expected '%s'", f.Name(), got, expected)
			}
		}
	}
}
