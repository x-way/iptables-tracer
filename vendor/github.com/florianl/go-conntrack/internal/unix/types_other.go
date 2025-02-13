//go:build !linux
// +build !linux

package unix

const (
	AF_UNSPEC                 = 0x0
	AF_INET                   = 0x2
	AF_INET6                  = 0xa
	NFNETLINK_V0              = 0x0
	NFNL_SUBSYS_CTNETLINK     = 0x1
	NFNL_SUBSYS_CTNETLINK_EXP = 0x2
	NETLINK_NETFILTER         = 0xc
)
