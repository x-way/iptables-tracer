# iptables-tracer
Insert trace-points into the running configuration to observe the path of packets through the iptables chains.

Usage
-----

```
$ iptables-tracer -f "-s 192.0.2.123 -d 203.0.113.113 -p tcp --dport 443" -t 30s
Nov  6 07:14:51.584 raw    PREROUTING                     192.0.2.123:47010 > 203.0.113.113:443 (TCP)
Nov  6 07:14:51.585 mangle PREROUTING                     192.0.2.123:47010 > 203.0.113.113:443 (TCP)
Nov  6 07:14:51.585 nat    PREROUTING                     192.0.2.123:47010 > 203.0.113.113:443 (TCP)
Nov  6 07:14:51.586 mangle FORWARD                        192.0.2.123:47010 > 203.0.113.113:443 (TCP)
Nov  6 07:14:51.591 filter FORWARD                        192.0.2.123:47010 > 203.0.113.113:443 (TCP)
Nov  6 07:14:51.592 mangle POSTROUTING                    192.0.2.123:47010 > 203.0.113.113:443 (TCP)
Nov  6 07:14:51.592 nat    POSTROUTING                    192.0.2.123:47010 > 203.0.113.113:443 (TCP)
```
