package conntrack

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/florianl/go-conntrack/internal/unix"

	"github.com/mdlayher/netlink"
)

// Config contains options for a Conn.
type Config struct {
	// NetNS specifies the network namespace the Conn will operate in.
	//
	// If set (non-zero), Conn will enter the specified network namespace and
	// an error will occur in Dial if the operation fails.
	//
	// If not set (zero), a best-effort attempt will be made to enter the
	// network namespace of the calling thread: this means that any changes made
	// to the calling thread's network namespace will also be reflected in Conn.
	// If this operation fails (due to lack of permissions or because network
	// namespaces are disabled by kernel configuration), Dial will not return
	// an error, and the Conn will operate in the default network namespace of
	// the process. This enables non-privileged use of Conn in applications
	// which do not require elevated privileges.
	NetNS int

	// Time till a read action times out - only available for Go >= 1.12
	//
	// Deprecated: Cancel the context passed to RegisterFiltered() or Register()
	// to remove the conntrack gracefully. Setting this value does no longer
	// have an effect on conntrack.
	ReadTimeout time.Duration

	// Time till a write action times out - only available for Go >= 1.12
	WriteTimeout time.Duration

	// Interface to log internals.
	Logger *log.Logger

	// DisableNSLockThread disables package netlink's default goroutine thread
	// locking behavior.
	//
	// By default, the library will lock the processing goroutine to its
	// corresponding OS thread in order to enable communication over netlink to
	// a different network namespace.
	//
	// If the caller already knows that the netlink socket is in the same
	// namespace as the calling thread, this can introduce a performance
	// impact. This option disables the OS thread locking behavior if
	// performance considerations are of interest.
	//
	// If disabled, it is the responsibility of the caller to make sure that all
	// threads are running in the correct namespace.
	//
	// When DisableNSLockThread is set, the caller cannot set the NetNS value.
	DisableNSLockThread bool

	// AddConntrackInformation enriches Con and provides additional information of
	// the Netlink/Conntrack origin.
	AddConntrackInformation bool
}

// Nfct represents a conntrack handler
type Nfct struct {
	// Con is the pure representation of a netlink socket
	Con *netlink.Conn

	logger *log.Logger

	errChan chan error

	debug bool

	setWriteTimeout func() error

	ctx       context.Context
	ctxCancel context.CancelFunc
	shutdown  chan struct{}

	addConntrackInformation bool
}

// adjust the WriteTimeout (mostly for testing)
func adjustWriteTimeout(nfct *Nfct, fn func() error) {
	nfct.setWriteTimeout = fn
}

// SecCtx contains additional information about the security context
type SecCtx struct {
	Name *string
}

// Timestamp contains start and/or stop times
type Timestamp struct {
	Start *time.Time
	Stop  *time.Time
}

// TCPFlags contains additional information for TCP flags
type TCPFlags struct {
	Flags *uint8
	Mask  *uint8
}

// TCPInfo contains additional information for TCP sessions
type TCPInfo struct {
	State      *uint8
	WScaleOrig *uint8
	WScaleRepl *uint8
	FlagsOrig  *TCPFlags
	FlagsReply *TCPFlags
}

// DCCPInfo contains additional information for DCCP sessions
type DCCPInfo struct {
	State        *uint8
	Role         *uint8
	HandshakeSeq *uint64
}

// SCTPInfo contains additional information for SCTP sessions
type SCTPInfo struct {
	State        *uint8
	VTagOriginal *uint32
	VTagReply    *uint32
}

// Helper contains additional information
type Helper struct {
	Name *string
	Info *string
}

// SeqAdj contains additional information about corrections
type SeqAdj struct {
	CorrectionPos *uint32
	OffsetBefore  *uint32
	OffsetAfter   *uint32
}

// Counter contains additional information about the traffic
type Counter struct {
	Packets   *uint64
	Bytes     *uint64
	Packets32 *uint32
	Bytes32   *uint32
}

// ProtoInfo contains additional information to certain protocols
type ProtoInfo struct {
	TCP  *TCPInfo
	DCCP *DCCPInfo
	SCTP *SCTPInfo
}

// ProtoTuple contains information about the used protocol
type ProtoTuple struct {
	Number     *uint8
	SrcPort    *uint16
	DstPort    *uint16
	IcmpID     *uint16
	IcmpType   *uint8
	IcmpCode   *uint8
	Icmpv6ID   *uint16
	Icmpv6Type *uint8
	Icmpv6Code *uint8
}

// IPTuple contains the source and destination IP
type IPTuple struct {
	Src   *net.IP
	Dst   *net.IP
	Proto *ProtoTuple
	Zone  *uint16
}

// NatInfo contains addition NAT information of a connection
type NatInfo struct {
	Dir   *uint32
	Tuple *IPTuple
}

// Exp extends the information of a connection by information from the expected table
type Exp struct {
	Master     *IPTuple
	Tuple      *IPTuple
	Mask       *IPTuple
	Flags      *uint32
	Class      *uint32
	ID         *uint32
	Timeout    *uint32
	Zone       *uint16
	HelperName *string
	Fn         *string
	Nat        *NatInfo
}

// Nat contains information for source/destination NAT
type Nat struct {
	IPMin *net.IP
	IPMax *net.IP
	Proto *ProtoTuple
}

// Con contains all the information of a connection
type Con struct {
	Info *InfoSource

	Origin        *IPTuple
	Reply         *IPTuple
	ProtoInfo     *ProtoInfo
	CounterOrigin *Counter
	CounterReply  *Counter
	Helper        *Helper
	NatSrc        *Nat
	SeqAdjOrig    *SeqAdj
	SeqAdjRepl    *SeqAdj
	ID            *uint32
	Status        *uint32
	StatusMask    *uint32
	Use           *uint32
	Mark          *uint32
	MarkMask      *uint32
	Timeout       *uint32
	Zone          *uint16
	Timestamp     *Timestamp
	SecCtx        *SecCtx
	Exp           *Exp
}

// InfoSource provides further information from Netlink about a connection.
type InfoSource struct {
	// Conntrack table this information originates from.
	Table Table

	// NetlinkGroup this information originates from.
	NetlinkGroup NetlinkGroup
}

// CPUStat contains various conntrack related per CPU statistics
type CPUStat struct {
	// ID of the CPU
	ID uint32

	// Values from the conntrack table
	Found         *uint32
	Invalid       *uint32
	Ignore        *uint32
	Insert        *uint32
	InsertFailed  *uint32
	Drop          *uint32
	EarlyDrop     *uint32
	Error         *uint32
	SearchRestart *uint32

	// Values from the expect table
	ExpNew    *uint32
	ExpCreate *uint32
	ExpDelete *uint32
}

// Table specifies the subsystem of conntrack
type Table int

// NetlinkGroup represents a Netlink multicast group
type NetlinkGroup uint32

// Supported Netlink groups
const (
	NetlinkCtNew             NetlinkGroup = 1 << iota
	NetlinkCtUpdate          NetlinkGroup = 1 << iota
	NetlinkCtDestroy         NetlinkGroup = 1 << iota
	NetlinkCtExpectedNew     NetlinkGroup = 1 << iota
	NetlinkCtExpectedUpdate  NetlinkGroup = 1 << iota
	NetlinkCtExpectedDestroy NetlinkGroup = 1 << iota
)

// Family specifies the network family
type Family uint8

// Supported family types
const (
	IPv6 Family = unix.AF_INET6
	IPv4 Family = unix.AF_INET
)

// FilterAttr represents a very basic filter
type FilterAttr struct {
	Mark, MarkMask []byte
}

// ConnAttr represents the type and value of a attribute of a connection
type ConnAttr struct {
	Type ConnAttrType
	Data []byte
	// Mask is required for specific attributes, if you want to filter for them
	Mask []byte
	// Negates this attribute for filtering
	Negate bool
}

func (ca ConnAttr) String() string {
	return fmt.Sprintf("Type: %2d - Data: [%v] - Mask: [%v] - Negate: %t\n", ca.Type, ca.Data, ca.Mask, ca.Negate)
}

// ConnAttrType specifies the attribute of a connection
type ConnAttrType uint16

// Attributes of a connection
// based on libnetfilter_conntrack.h
const (
	AttrOrigIPv4Src             ConnAttrType = iota /* u32 bits, requires a mask if applied as filter */
	AttrOrigIPv4Dst             ConnAttrType = iota /* u32 bits, requires a mask if applied as filter */
	AttrReplIPv4Src             ConnAttrType = iota /* u32 bits, requires a mask if applied as filter */
	AttrReplIPv4Dst             ConnAttrType = iota /* u32 bits, requires a mask if applied as filter */
	AttrOrigIPv6Src             ConnAttrType = iota /* u128 bits */
	AttrOrigIPv6Dst             ConnAttrType = iota /* u128 bits */
	AttrReplIPv6Src             ConnAttrType = iota /* u128 bits */
	AttrReplIPv6Dst             ConnAttrType = iota /* u128 bits */
	AttrOrigPortSrc             ConnAttrType = iota /* u16 bits */
	AttrOrigPortDst             ConnAttrType = iota /* u16 bits */
	AttrReplPortSrc             ConnAttrType = iota /* u16 bits */
	AttrReplPortDst             ConnAttrType = iota /* u16 bits */
	AttrIcmpType                ConnAttrType = iota /* u8 bits */
	AttrIcmpCode                ConnAttrType = iota /* u8 bits */
	AttrIcmpID                  ConnAttrType = iota /* u16 bits */
	AttrOrigL3Proto             ConnAttrType = iota /* u8 bits */
	AttrReplL3Proto             ConnAttrType = iota /* u8 bits */
	AttrOrigL4Proto             ConnAttrType = iota /* u8 bits */
	AttrReplL4Proto             ConnAttrType = iota /* u8 bits */
	AttrTCPState                ConnAttrType = iota /* u8 bits */
	AttrSNatIPv4                ConnAttrType = iota /* u32 bits */
	AttrDNatIPv4                ConnAttrType = iota /* u32 bits */
	AttrSNatPort                ConnAttrType = iota /* u16 bits */
	AttrDNatPort                ConnAttrType = iota /* u16 bits */
	AttrTimeout                 ConnAttrType = iota /* u32 bits */
	AttrMark                    ConnAttrType = iota /* u32 bits, requires a mask if applied as filter */
	AttrMarkMask                ConnAttrType = iota /* u32 bits */
	AttrOrigCounterPackets      ConnAttrType = iota /* u64 bits */
	AttrReplCounterPackets      ConnAttrType = iota /* u64 bits */
	AttrOrigCounterBytes        ConnAttrType = iota /* u64 bits */
	AttrReplCounterBytes        ConnAttrType = iota /* u64 bits */
	AttrUse                     ConnAttrType = iota /* u32 bits */
	AttrID                      ConnAttrType = iota /* u32 bits */
	AttrStatus                  ConnAttrType = iota /* u32 bits  */
	AttrTCPFlagsOrig            ConnAttrType = iota /* u8 bits */
	AttrTCPFlagsRepl            ConnAttrType = iota /* u8 bits */
	AttrTCPMaskOrig             ConnAttrType = iota /* u8 bits */
	AttrTCPMaskRepl             ConnAttrType = iota /* u8 bits */
	AttrMasterIPv4Src           ConnAttrType = iota /* u32 bits */
	AttrMasterIPv4Dst           ConnAttrType = iota /* u32 bits */
	AttrMasterIPv6Src           ConnAttrType = iota /* u128 bits */
	AttrMasterIPv6Dst           ConnAttrType = iota /* u128 bits */
	AttrMasterPortSrc           ConnAttrType = iota /* u16 bits */
	AttrMasterPortDst           ConnAttrType = iota /* u16 bits */
	AttrMasterL3Proto           ConnAttrType = iota /* u8 bits */
	AttrMasterL4Proto           ConnAttrType = iota /* u8 bits */
	AttrSecmark                 ConnAttrType = iota /* u32 bits */
	AttrOrigNatSeqCorrectionPos ConnAttrType = iota /* u32 bits */
	AttrOrigNatSeqOffsetBefore  ConnAttrType = iota /* u32 bits */
	AttrOrigNatSeqOffsetAfter   ConnAttrType = iota /* u32 bits */
	AttrReplNatSeqCorrectionPos ConnAttrType = iota /* u32 bits */
	AttrReplNatSeqOffsetBefore  ConnAttrType = iota /* u32 bits */
	AttrReplNatSeqOffsetAfter   ConnAttrType = iota /* u32 bits */
	AttrSctpState               ConnAttrType = iota /* u8 bits */
	AttrSctpVtagOrig            ConnAttrType = iota /* u32 bits */
	AttrSctpVtagRepl            ConnAttrType = iota /* u32 bits */
	AttrHelperName              ConnAttrType = iota /* string (30 bytes max) */
	AttrDccpState               ConnAttrType = iota /* u8 bits */
	AttrDccpRole                ConnAttrType = iota /* u8 bits */
	AttrDccpHandshakeSeq        ConnAttrType = iota /* u64 bits */
	AttrTCPWScaleOrig           ConnAttrType = iota /* u8 bits */
	AttrTCPWScaleRepl           ConnAttrType = iota /* u8 bits */
	AttrZone                    ConnAttrType = iota /* u16 bits */
	AttrSecCtx                  ConnAttrType = iota /* string */
	AttrTimestampStart          ConnAttrType = iota /* u64 bits linux >= 2.6.38 */
	AttrTimestampStop           ConnAttrType = iota /* u64 bits linux >= 2.6.38 */
	AttrHelperInfo              ConnAttrType = iota /* variable length */
	AttrConnlabels              ConnAttrType = iota /* variable length */
	AttrConnlabelsMask          ConnAttrType = iota /* variable length */
	AttrOrigzone                ConnAttrType = iota /* u16 bits */
	AttrReplzone                ConnAttrType = iota /* u16 bits */
	AttrSNatIPv6                ConnAttrType = iota /* u128 bits */
	AttrDNatIPv6                ConnAttrType = iota /* u128 bits */

	AttrIcmpv6Type ConnAttrType = iota /* u8 bits */
	AttrIcmpv6Code ConnAttrType = iota /* u8 bits */
	AttrIcmpv6ID   ConnAttrType = iota /* u16 bits */

	attrMax ConnAttrType = iota /* This is for internal use only	*/

	AttrExpID     ConnAttrType = iota /* u32 bits */
	AttrExpFlags  ConnAttrType = iota /* u32 bits */
	AttrExpClass  ConnAttrType = iota /* u32 bits */
	AttrExpNATDir ConnAttrType = iota /* u32 bits */

	// for internal use only
	attrUnspec ConnAttrType = iota
)

// Various errors which may occur when processing attributes
var (
	ErrAttrLength         = errors.New("incorrect length of attribute")
	ErrAttrNotImplemented = errors.New("attribute not implemented")
	ErrAttrNotExist       = errors.New("type of attribute does not exist")
	ErrDataLength         = errors.New("incorrect length of provided data")
)

// ErrUnknownCtTable will be return, if the function can not be performed on this subsystem
var ErrUnknownCtTable = errors.New("not supported for this subsystem")
