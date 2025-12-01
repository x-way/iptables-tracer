//go:build !linux
// +build !linux

package unix

const (
	AF_UNSPEC                     = 0x0
	AF_INET                       = 0x2
	AF_INET6                      = 0xa
	NFNETLINK_V0                  = 0x0
	NFNL_SUBSYS_CTNETLINK         = 0x1
	NFNL_SUBSYS_CTNETLINK_EXP     = 0x2
	NFNL_SUBSYS_CTNETLINK_TIMEOUT = 0x8
	NETLINK_NETFILTER             = 0xc

	// Instruction classes
	BPF_LD   = 0x00
	BPF_LDX  = 0x01
	BPF_ALU  = 0x04
	BPF_JMP  = 0x05
	BPF_RET  = 0x06
	BPF_MISC = 0x07

	// ld/ldx fields
	BPF_W   = 0x00
	BPF_H   = 0x08
	BPF_B   = 0x10
	BPF_IMM = 0x00
	BPF_ABS = 0x20
	BPF_IND = 0x40

	// alu/jmp fields
	BPF_ADD = 0x00
	BPF_AND = 0x50
	BPF_JA  = 0x00
	BPF_JEQ = 0x10
	BPF_K   = 0x00

	// include/uapi/linux/filter.h
	BPF_TAX = 0x00
	BPF_TXA = 0x80
)
