/*
Package conntrack provides an API to interact with the conntrack subsystem of the netfilter family from the linux kernel.

Example:

	package main
	import (
		"fmt"
		ct "github.com/florianl/go-conntrack"
	)
	func main(){
		nfct, err := ct.Open(&ct.Config{})
		if err != nil {
			fmt.Println("Could not create nfct:", err)
			return
		}
		defer nfct.Close()
		sessions, err := nfct.Dump(ct.Conntrack, ct.IPv4)
		if err != nil {
			fmt.Println("Could not dump sessions:", err)
			return
		}
		for _, session := range sessions {
			fmt.Printf("[%2d] %s - %s\n", session.Origin.Proto.Number, session.Origin.Src, session.Origin.Dst)
		}
	}

This package processes information directly from the kernel and therefore it requires special privileges. You
can provide this privileges by adjusting the CAP_NET_ADMIN capabilities.

	setcap 'cap_net_admin=+ep' /your/executable
*/
package conntrack
