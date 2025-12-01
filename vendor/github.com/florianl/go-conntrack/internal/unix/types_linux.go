//go:build linux
// +build linux

package unix

import (
	linux "golang.org/x/sys/unix"
)

// comment to make linter happy
const (
	AF_UNSPEC                     = linux.AF_UNSPEC
	AF_INET                       = linux.AF_INET
	AF_INET6                      = linux.AF_INET6
	NFNETLINK_V0                  = linux.NFNETLINK_V0
	NFNL_SUBSYS_CTNETLINK         = linux.NFNL_SUBSYS_CTNETLINK
	NFNL_SUBSYS_CTNETLINK_EXP     = linux.NFNL_SUBSYS_CTNETLINK_EXP
	NFNL_SUBSYS_CTNETLINK_TIMEOUT = linux.NFNL_SUBSYS_CTNETLINK_TIMEOUT
	NETLINK_NETFILTER             = linux.NETLINK_NETFILTER

	// Instruction classes
	BPF_LD   = linux.BPF_LD
	BPF_LDX  = linux.BPF_LDX
	BPF_ALU  = linux.BPF_ALU
	BPF_JMP  = linux.BPF_JMP
	BPF_RET  = linux.BPF_RET
	BPF_MISC = linux.BPF_MISC

	// ld/ldx fields
	BPF_W   = linux.BPF_W
	BPF_H   = linux.BPF_H
	BPF_B   = linux.BPF_B
	BPF_IMM = linux.BPF_IMM
	BPF_ABS = linux.BPF_ABS
	BPF_IND = linux.BPF_IND

	// alu/jmp fields
	BPF_ADD = linux.BPF_ADD
	BPF_AND = linux.BPF_AND
	BPF_JA  = linux.BPF_JA
	BPF_JEQ = linux.BPF_JEQ
	BPF_K   = linux.BPF_K

	// include/uapi/linux/filter.h
	BPF_TAX = linux.BPF_TAX
	BPF_TXA = linux.BPF_TXA
)
