# iptables-tracer
[![Build Status](https://travis-ci.org/x-way/iptables-tracer.svg?branch=master)](http://travis-ci.org/x-way/iptables-tracer)

Insert trace-points into the running configuration to observe the path of packets through the iptables chains.

## Usage

```
$ iptables-tracer -f "-s 192.0.2.1 -p tcp --dport 443" -t 30s
14:42:00.284882 raw    PREROUTING   0x00000000 IP 192.0.2.1.36028 > 203.0.113.41.443: Flags [S], seq 3964691400, win 29200, length 0  [In:eth0 Out:]
14:42:00.287255 mangle PREROUTING   0x00008000 IP 192.0.2.1.36028 > 203.0.113.41.443: Flags [S], seq 3964691400, win 29200, length 0  [In:eth0 Out:]
14:42:00.288966 nat    PREROUTING   0x00008000 IP 192.0.2.1.36028 > 203.0.113.41.443: Flags [S], seq 3964691400, win 29200, length 0  [In:eth0 Out:]
14:42:00.290545 mangle FORWARD      0x00008000 IP 192.0.2.1.36028 > 198.51.100.8.443: Flags [S], seq 3964691400, win 29200, length 0  [In:eth0 Out:eth1]
14:42:00.292123 filter FORWARD      0x00008002 IP 192.0.2.1.36028 > 198.51.100.8.443: Flags [S], seq 3964691400, win 29200, length 0  [In:eth0 Out:eth1]
14:42:00.293164 mangle POSTROUTING  0x00008002 IP 192.0.2.1.36028 > 198.51.100.8.443: Flags [S], seq 3964691400, win 29200, length 0  [In: Out:eth1]
14:42:00.293780 nat    POSTROUTING  0x00008002 IP 192.0.2.1.36028 > 198.51.100.8.443: Flags [S], seq 3964691400, win 29200, length 0  [In: Out:eth1]
```
