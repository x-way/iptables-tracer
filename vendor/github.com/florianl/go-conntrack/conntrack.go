package conntrack

import (
	"context"
	"encoding/binary"
	"fmt"
	"log"
	"time"
	"unsafe"

	"github.com/florianl/go-conntrack/internal/unix"

	"github.com/mdlayher/netlink"
	"github.com/mdlayher/netlink/nlenc"
)

// Supported conntrack subsystems
const (
	// Conntrack is the default table containing a list of all tracked connections
	Conntrack Table = unix.NFNL_SUBSYS_CTNETLINK

	// Expected is a table containing information about related connections to existing ones
	Expected Table = unix.NFNL_SUBSYS_CTNETLINK_EXP

	// Timeout is a table containing timeout information of connection flows.
	Timeout Table = unix.NFNL_SUBSYS_CTNETLINK_TIMEOUT
)

const (
	ipctnlMsgCtNew = iota
	ipctnlMsgCtGet
	ipctnlMsgCtDelete
	ipctnlMsgCtGetCtrZero
	ipctnlMsgCtGetStatsCPU
	ipctnlMsgCtGetStats
	ipctnlMsgCtGetDying
	ipctnlMsgCtGetUnconfirmed
)

const (
	ipctnlMsgExpNew = iota
	ipctnlMsgExpGet
	ipctnlMsgExpDelete
	ipctnlMsgExpGetStatsCPU
)

// for detailes see https://github.com/tensorflow/tensorflow/blob/master/tensorflow/go/tensor.go#L488-L505
var nativeEndian binary.ByteOrder

func init() {
	buf := [2]byte{}
	*(*uint16)(unsafe.Pointer(&buf[0])) = uint16(0xABCD)

	switch buf {
	case [2]byte{0xCD, 0xAB}:
		nativeEndian = binary.LittleEndian
	case [2]byte{0xAB, 0xCD}:
		nativeEndian = binary.BigEndian
	default:
		panic("Could not determine native endianness.")
	}
}

// devNull satisfies io.Writer, in case *log.Logger is not provided
type devNull struct{}

func (devNull) Write(p []byte) (int, error) {
	return 0, nil
}

// Open a connection to the conntrack subsystem
func Open(config *Config) (*Nfct, error) {
	var nfct Nfct

	con, err := netlink.Dial(unix.NETLINK_NETFILTER, &netlink.Config{NetNS: config.NetNS, DisableNSLockThread: config.DisableNSLockThread})
	if err != nil {
		return nil, err
	}
	nfct.Con = con

	if config.Logger == nil {
		nfct.logger = log.New(new(devNull), "", 0)
	} else {
		nfct.logger = config.Logger
	}

	if config.WriteTimeout > 0 {
		nfct.setWriteTimeout = func() error {
			deadline := time.Now().Add(config.WriteTimeout)
			return nfct.Con.SetWriteDeadline(deadline)
		}
	} else {
		nfct.setWriteTimeout = func() error { return nil }
	}

	nfct.addConntrackInformation = config.AddConntrackInformation

	return &nfct, nil
}

// Close the connection to the conntrack subsystem.
func (nfct *Nfct) Close() error {
	if nfct.ctxCancel != nil {
		nfct.ctxCancel()

		// Block until filters are removed and socket unsubscribed from groups
		<-nfct.shutdown
	}

	if nfct.errChan != nil {
		close(nfct.errChan)
	}
	return nfct.Con.Close()
}

// SetOption allows to enable or disable netlink socket options.
func (nfct *Nfct) SetOption(o netlink.ConnOption, enable bool) error {
	return nfct.Con.SetOption(o, enable)
}

// Flush a conntrack subsystem
func (nfct *Nfct) Flush(t Table, f Family) error {
	data := putExtraHeader(uint8(f), unix.NFNETLINK_V0, 0)
	req := netlink.Message{
		Header: netlink.Header{
			Type:  netlink.HeaderType(t << 8),
			Flags: netlink.Request | netlink.Acknowledge,
		},
		Data: data,
	}

	if t == Conntrack {
		req.Header.Type |= netlink.HeaderType(ipctnlMsgCtDelete)
	} else if t == Expected {
		req.Header.Type |= netlink.HeaderType(ipctnlMsgExpDelete)
	} else {
		return ErrUnknownCtTable
	}

	return nfct.execute(req)
}

// Dump a conntrack subsystem
func (nfct *Nfct) Dump(t Table, f Family) ([]Con, error) {
	data := putExtraHeader(uint8(f), unix.NFNETLINK_V0, 0)
	req := netlink.Message{
		Header: netlink.Header{
			Type:  netlink.HeaderType(t << 8),
			Flags: netlink.Request | netlink.Dump,
		},
		Data: data,
	}

	if t == Conntrack {
		req.Header.Type |= netlink.HeaderType(ipctnlMsgCtGet)
	} else if t == Expected {
		req.Header.Type |= netlink.HeaderType(ipctnlMsgExpGet)
	} else {
		return nil, ErrUnknownCtTable
	}

	return nfct.query(req)
}

// Create a new entry in the conntrack subsystem with certain attributes
func (nfct *Nfct) Create(t Table, f Family, attributes Con) error {
	query, err := nestAttributes(nfct.logger, &attributes)
	if err != nil {
		return err
	}
	data := putExtraHeader(uint8(f), unix.NFNETLINK_V0, unix.NFNL_SUBSYS_CTNETLINK)
	data = append(data, query...)

	req := netlink.Message{
		Header: netlink.Header{
			Type:  netlink.HeaderType(t << 8),
			Flags: netlink.Request | netlink.Acknowledge | netlink.Create | netlink.Excl,
		},
		Data: data,
	}

	if t == Conntrack {
		req.Header.Type |= netlink.HeaderType(ipctnlMsgCtNew)
	} else if t == Expected {
		req.Header.Type |= netlink.HeaderType(ipctnlMsgExpNew)
	} else {
		return ErrUnknownCtTable
	}

	return nfct.execute(req)
}

// Query conntrack subsystem with certain attributes
func (nfct *Nfct) Query(t Table, f Family, filter FilterAttr) ([]Con, error) {
	query, err := nestFilter(filter)
	if err != nil {
		return nil, err
	}
	data := putExtraHeader(uint8(f), unix.NFNETLINK_V0, unix.NFNL_SUBSYS_CTNETLINK)
	data = append(data, query...)

	req := netlink.Message{
		Header: netlink.Header{
			Type:  netlink.HeaderType(t << 8),
			Flags: netlink.Request | netlink.Dump,
		},
		Data: data,
	}

	if t == Conntrack {
		req.Header.Type |= netlink.HeaderType(ipctnlMsgCtGet)
	} else if t == Expected {
		req.Header.Type |= netlink.HeaderType(ipctnlMsgExpGet)
	} else {
		return nil, ErrUnknownCtTable
	}
	return nfct.query(req)
}

// Get returns matching conntrack entries with certain attributes
func (nfct *Nfct) Get(t Table, f Family, match Con) ([]Con, error) {
	if t != Conntrack {
		return nil, ErrUnknownCtTable
	}
	query, err := nestAttributes(nfct.logger, &match)
	if err != nil {
		return []Con{}, err
	}
	data := putExtraHeader(uint8(f), unix.NFNETLINK_V0, unix.NFNL_SUBSYS_CTNETLINK)
	data = append(data, query...)

	req := netlink.Message{
		Header: netlink.Header{
			Type:  netlink.HeaderType(t << 8),
			Flags: netlink.Request | netlink.Acknowledge,
		},
		Data: data,
	}

	if t == Conntrack {
		req.Header.Type |= netlink.HeaderType(ipctnlMsgCtGet)
	} else if t == Expected {
		req.Header.Type |= netlink.HeaderType(ipctnlMsgExpGet)
	} else {
		return []Con{}, ErrUnknownCtTable
	}

	return nfct.query(req)
}

// Update an existing conntrack entry
func (nfct *Nfct) Update(t Table, f Family, attributes Con) error {
	if t != Conntrack {
		return ErrUnknownCtTable
	}

	query, err := nestAttributes(nfct.logger, &attributes)
	if err != nil {
		return err
	}
	data := putExtraHeader(uint8(f), unix.NFNETLINK_V0, unix.NFNL_SUBSYS_CTNETLINK)
	data = append(data, query...)

	req := netlink.Message{
		Header: netlink.Header{
			Type:  netlink.HeaderType(t << 8),
			Flags: netlink.Request | netlink.Acknowledge,
		},
		Data: data,
	}

	if t == Conntrack {
		req.Header.Type |= netlink.HeaderType(ipctnlMsgCtNew)
	} else if t == Expected {
		req.Header.Type |= netlink.HeaderType(ipctnlMsgExpNew)
	} else {
		return ErrUnknownCtTable
	}

	return nfct.execute(req)
}

// Delete elements from the conntrack subsystem with certain attributes
func (nfct *Nfct) Delete(t Table, f Family, filters Con) error {
	query, err := nestAttributes(nfct.logger, &filters)
	if err != nil {
		return err
	}
	data := putExtraHeader(uint8(f), unix.NFNETLINK_V0, unix.NFNL_SUBSYS_CTNETLINK)
	data = append(data, query...)

	req := netlink.Message{
		Header: netlink.Header{
			Type:  netlink.HeaderType(t << 8),
			Flags: netlink.Request | netlink.Acknowledge,
		},
		Data: data,
	}

	if t == Conntrack {
		req.Header.Type |= netlink.HeaderType(ipctnlMsgCtDelete)
	} else if t == Expected {
		req.Header.Type |= netlink.HeaderType(ipctnlMsgExpDelete)
	} else {
		return ErrUnknownCtTable
	}

	return nfct.execute(req)
}

// DumpCPUStats dumps per CPU statistics
func (nfct *Nfct) DumpCPUStats(t Table) ([]CPUStat, error) {
	data := putExtraHeader(unix.AF_UNSPEC, unix.NFNETLINK_V0, 0)
	req := netlink.Message{
		Header: netlink.Header{
			Type:  netlink.HeaderType(t << 8),
			Flags: netlink.Request | netlink.Dump,
		},
		Data: data,
	}
	if t == Conntrack {
		req.Header.Type |= netlink.HeaderType(ipctnlMsgCtGetStatsCPU)
	} else if t == Expected {
		req.Header.Type |= netlink.HeaderType(ipctnlMsgExpGetStatsCPU)
	} else {
		return nil, ErrUnknownCtTable
	}
	return nfct.getCPUStats(req)
}

// ParseAttributes extracts all the attributes from the given data
func ParseAttributes(logger *log.Logger, data []byte) (Con, error) {
	// At least 2 bytes are needed for the header check
	if len(data) < 2 {
		return Con{}, ErrDataLength
	}
	c := Con{}
	err := extractAttributes(logger, &c, data)
	return c, err
}

// HookFunc is a function, that receives events from a Netlinkgroup.
// Return something different than 0, to stop receiving messages.
type HookFunc func(c Con) int

// AttachErrChan creates and attaches an error channel to the Nfct object.
// If an unexpected error is received this error will be reported via this
// channel.
// A call of (*Nfct).Close() will also close this channel.
func (nfct *Nfct) AttachErrChan() <-chan error {
	if nfct.errChan != nil {
		return nfct.errChan
	}
	errChan := make(chan error)
	nfct.errChan = errChan
	return errChan
}

// Register your function to receive events from a Netlinkgroup. If an unexpected error
// is received it will stop from processing further events.
// If your function returns something different than 0, it will stop.
func (nfct *Nfct) Register(ctx context.Context, t Table, group NetlinkGroup, fn HookFunc) error {
	return nfct.register(ctx, t, group, []ConnAttr{}, fn)
}

// RegisterFiltered registers your function to receive events from a Netlinkgroup and applies a filter.
// If an unexpected error is received it will stop from processing further events.
// If your function returns something different than 0, it will stop.
// ConnAttr of the same ConnAttrType will be linked by an OR operation.
// Otherwise, ConnAttr of different ConnAttrType will be connected by an AND operation for the filter.
// Note: When you add filters for IPv4 specific fields, it will automatically filter for IPv4-only events.
// The same rule applies for IPv6. However, if you apply a filter for both IPv4- and IPv6-specific fields,
// it will result in filtering out all events, meaning no event will match.
func (nfct *Nfct) RegisterFiltered(ctx context.Context, t Table, group NetlinkGroup, filter []ConnAttr, fn HookFunc) error {
	return nfct.register(ctx, t, group, filter, fn)
}

// EnableDebug print bpf filter for RegisterFiltered function
func (nfct *Nfct) EnableDebug() {
	nfct.debug = true
}

func (nfct *Nfct) register(ctx context.Context, t Table, groups NetlinkGroup, filter []ConnAttr, fn func(c Con) int) error {
	nfct.ctx, nfct.ctxCancel = context.WithCancel(ctx)
	nfct.shutdown = make(chan struct{})

	if err := nfct.manageGroups(t, uint32(groups), true); err != nil {
		return err
	}
	if err := nfct.attachFilter(t, filter); err != nil {
		return err
	}

	enricher := func(*Con, netlink.Header) {}
	if nfct.addConntrackInformation {
		enricher = func(c *Con, h netlink.Header) {
			var group NetlinkGroup

			if h.Type&0xFF == ipctnlMsgCtNew {
				if h.Flags&(netlink.Create|netlink.Excl) != 0 {
					group = NetlinkCtNew
				} else {
					group = NetlinkCtUpdate
				}
			} else {
				group = NetlinkCtDestroy
			}

			info := InfoSource{
				Table:        Table((h.Type & 0x300) >> 8),
				NetlinkGroup: group,
			}
			c.Info = &info
		}
	}

	go func() {
		go func() {
			// block until context is done
			<-nfct.ctx.Done()
			// Set the read deadline to a point in the past to interrupt
			// possible blocking Receive() calls.
			nfct.Con.SetReadDeadline(time.Now().Add(-1 * time.Second))

			if err := nfct.removeFilter(); err != nil {
				nfct.logger.Printf("could not remove filter: %v", err)
			}
			if err := nfct.manageGroups(t, uint32(groups), false); err != nil {
				nfct.logger.Printf("could not unsubscribe from group: %v", err)
			}
			close(nfct.shutdown)
		}()

		for {
			reply, err := nfct.Con.Receive()
			if err != nil {
				if nfct.ctx.Err() != nil {
					// TODO: Here we ignore internal/poll.ErrFileClosing which is expected after
					//       nfct.ctx is done. Maybe improve graceful handling.
					return
				}
				if opError, ok := err.(*netlink.OpError); ok {
					if opError.Timeout() || opError.Temporary() {
						continue
					}
				}
				if nfct.errChan != nil {
					nfct.errChan <- err
				} else {
					nfct.logger.Printf("receiving error: %v", err)
				}
				return
			}

			c := Con{}
			for _, msg := range reply {
				if err := parseConnectionMsg(nfct.logger, &c, msg, (int(msg.Header.Type)&0x300)>>8, int(msg.Header.Type)&0xF); err != nil {
					nfct.logger.Printf("could not parse received message: %v", err)
					continue
				}
				enricher(&c, msg.Header)
				if ret := fn(c); ret != 0 {
					return
				}
			}

		}
	}()
	return nil
}

func (nfct *Nfct) manageGroups(t Table, groups uint32, join bool) error {
	var manage func(group uint32) error

	if groups == 0 {
		nfct.logger.Println("will not join group 0")
		return nil
	}

	manage = nfct.Con.LeaveGroup
	if join {
		manage = nfct.Con.JoinGroup
	}

	var mapping map[uint32]uint32
	var nlGroups []NetlinkGroup
	switch t {
	case Conntrack:
		mapping = map[uint32]uint32{
			uint32(NetlinkCtNew):     1, // NFNLGRP_CONNTRACK_NEW
			uint32(NetlinkCtUpdate):  2, // NFNLGRP_CONNTRACK_UPDATE
			uint32(NetlinkCtDestroy): 3, // NFNLGRP_CONNTRACK_DESTROY
		}
		nlGroups = append(nlGroups, []NetlinkGroup{NetlinkCtNew, NetlinkCtUpdate, NetlinkCtDestroy}...)
	case Expected:
		mapping = map[uint32]uint32{
			uint32(NetlinkCtExpectedNew):     4, // NFNLGRP_CONNTRACK_EXP_NEW
			uint32(NetlinkCtExpectedUpdate):  5, // NFNLGRP_CONNTRACK_EXP_UPDATE
			uint32(NetlinkCtExpectedDestroy): 6, // NFNLGRP_CONNTRACK_EXP_DESTROY
		}
		nlGroups = append(nlGroups, []NetlinkGroup{NetlinkCtExpectedNew, NetlinkCtExpectedUpdate, NetlinkCtExpectedDestroy}...)
	default:
		return ErrUnknownCtTable
	}

	for _, v := range nlGroups {
		if groups&uint32(v) == uint32(v) {
			if err := manage(mapping[groups&uint32(v)]); err != nil {
				return err
			}
		}
	}
	return nil
}

// ErrMsg as defined in nlmsgerr
type ErrMsg struct {
	Code  int
	Len   uint32
	Type  uint16
	Flags uint16
	Seq   uint32
	Pid   uint32
}

func unmarschalErrMsg(b []byte) (ErrMsg, error) {
	var msg ErrMsg

	msg.Code = int(nlenc.Uint32(b[0:4]))
	msg.Len = nlenc.Uint32(b[4:8])
	msg.Type = nlenc.Uint16(b[8:10])
	msg.Flags = nlenc.Uint16(b[10:12])
	msg.Seq = nlenc.Uint32(b[12:16])
	msg.Pid = nlenc.Uint32(b[16:20])

	return msg, nil
}

func (nfct *Nfct) execute(req netlink.Message) error {
	if err := nfct.setWriteTimeout(); err != nil {
		nfct.logger.Printf("could not set write timeout: %v", err)
	}
	reply, e := nfct.Con.Execute(req)
	if e != nil {
		return e
	}
	if e := netlink.Validate(req, reply); e != nil {
		return e
	}
	for _, msg := range reply {
		errMsg, err := unmarschalErrMsg(msg.Data)
		if err != nil {
			return err
		}
		if errMsg.Code != 0 {
			return fmt.Errorf("%#v", errMsg)
		}
	}
	return nil
}

func (nfct *Nfct) send(req netlink.Message) error {
	if err := nfct.setWriteTimeout(); err != nil {
		nfct.logger.Printf("could not set write timeout: %v", err)
	}
	verify, err := nfct.Con.Send(req)
	if err != nil {
		return err
	}

	if err := netlink.Validate(req, []netlink.Message{verify}); err != nil {
		return err
	}

	return nil
}

func (nfct *Nfct) query(req netlink.Message) ([]Con, error) {

	if err := nfct.send(req); err != nil {
		return nil, err
	}

	reply, err := nfct.Con.Receive()
	if err != nil {
		return nil, err
	}

	var conn []Con
	for _, msg := range reply {
		c := Con{}
		if err := parseConnectionMsg(nfct.logger, &c, msg, (int(req.Header.Type)&0x300)>>8, int(req.Header.Type)&0xF); err != nil {
			return nil, err
		}
		// check if c is an empty struct
		if (Con{}) == c {
			continue
		}
		conn = append(conn, c)
	}
	return conn, nil
}

func (nfct *Nfct) getCPUStats(req netlink.Message) ([]CPUStat, error) {
	var stats []CPUStat
	if err := nfct.send(req); err != nil {
		return nil, err
	}
	reply, err := nfct.Con.Receive()
	if err != nil {
		return nil, err
	}

	for _, msg := range reply {
		if msg.Header.Type == netlink.Error {
			errMsg, err := unmarschalErrMsg(msg.Data)
			if err != nil {
				nfct.logger.Printf("could not unmarshal ErrMsg: %v", err)
				continue
			}
			if errMsg.Code == 0 {
				continue
			}
			nfct.logger.Printf("unknown error: %v", errMsg)
			continue
		}

		var stat CPUStat
		offset := checkHeader(msg.Data[:2])
		switch Table((int(req.Header.Type) & 0x300) >> 8) {
		case Conntrack:
			if err := extractCPUStats(&stat, nfct.logger, msg.Data[offset:]); err != nil {
				nfct.logger.Printf("could not extract CPU stats: %v", err)
				continue
			}
		case Expected:
			if err := extractExpCPUStats(&stat, nfct.logger, msg.Data[offset:]); err != nil {
				nfct.logger.Printf("could not extract CPU stats: %v", err)
				continue
			}
		default:
			return nil, fmt.Errorf("unknown table")
		}

		stats = append(stats, stat)
	}
	return stats, nil
}

// /include/uapi/linux/netfilter/nfnetlink.h:struct nfgenmsg{} res_id is Big Endian
func putExtraHeader(familiy, version uint8, resid uint16) []byte {
	buf := make([]byte, 2)
	binary.BigEndian.PutUint16(buf, resid)
	return append([]byte{familiy, version}, buf...)
}

type extractFunc func(*log.Logger, *Con, []byte) error

func parseConnectionMsg(logger *log.Logger, c *Con, msg netlink.Message, reqTable, reqType int) error {

	if msg.Header.Type == netlink.Error {
		errMsg, err := unmarschalErrMsg(msg.Data)
		if err != nil {
			return err
		}
		if errMsg.Code == 0 {
			return nil
		}
		return fmt.Errorf("%#v", errMsg)
	}

	var fnMap map[int]extractFunc

	switch reqTable {
	case unix.NFNL_SUBSYS_CTNETLINK:
		fnMap = map[int]extractFunc{
			ipctnlMsgCtNew:    extractAttributes,
			ipctnlMsgCtGet:    extractAttributes,
			ipctnlMsgCtDelete: extractAttributes,
		}
	case unix.NFNL_SUBSYS_CTNETLINK_EXP:
		fnMap = map[int]extractFunc{
			ipctnlMsgExpNew:    extractExpectAttributes,
			ipctnlMsgExpGet:    extractExpectAttributes,
			ipctnlMsgExpDelete: extractExpectAttributes,
		}
	default:
		return fmt.Errorf("unknown conntrack table")
	}

	if fn, ok := fnMap[reqType]; ok {
		return fn(logger, c, msg.Data)
	}

	return fmt.Errorf("unknown message type: 0x%02x", reqType)
}
