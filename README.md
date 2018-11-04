# iptables-tracer
Insert trace-points into the running configuration to observe the path of packets through the iptables chains.

Usage
-----

```
$ iptables-tracer -f "-s 192.0.2.123 -d 203.0.113.113 -p tcp --dport 443" -t 30s
Nov  4 22:24:31.638 raw    PREROUTING
Nov  4 22:24:31.639 mangle PREROUTING
Nov  4 22:24:31.639 nat    PREROUTING
Nov  4 22:24:31.639 mangle FORWARD
Nov  4 22:24:31.639 filter FORWARD
Nov  4 22:24:31.640 mangle POSTROUTING
Nov  4 22:24:31.640 nat    POSTROUTING
```
