package conntrack

import (
	"encoding/binary"
	"log"
	"net"
	"time"

	"github.com/florianl/go-conntrack/internal/unix"

	"github.com/mdlayher/netlink"
)

const (
	ctaUnspec = iota
	ctaTupleOrig
	ctaTupleReply
	ctaStatus
	ctaProtoinfo
	ctaHelp
	ctaNatSrc
	ctaTimeout
	ctaMark
	ctaCountersOrig
	ctaCountersReply
	ctaUse
	ctaID
	ctaNatDst
	ctaTupleMaster
	ctaSeqAdjOrig
	ctaSeqAdjRepl
	ctaSecmark
	ctaZone
	ctaSecCtx
	ctaTimestamp
	ctaMarkMask
	ctaLables
	ctaLablesMask
	ctaSynProxy
	ctaFilter
	ctaStatusMask
)

const (
	ctaTupleIP    = 1
	ctaTupleProto = 2
	ctaTupleZone  = 3
)

const (
	ctaIPv4Src = 1
	ctaIPv4Dst = 2
	ctaIPv6Src = 3
	ctaIPv6Dst = 4
)

const (
	ctaProtoNum        = 1
	ctaProtoSrcPort    = 2
	ctaProtoDstPort    = 3
	ctaProtoIcmpID     = 4
	ctaProtoIcmpType   = 5
	ctaProtoIcmpCode   = 6
	ctaProtoIcmpv6ID   = 7
	ctaProtoIcmpv6Type = 8
	ctaProtoIcmpv6Code = 9
)

const (
	ctaProtoinfoTCP  = 1
	ctaProtoinfoDCCP = 2
	ctaProtoinfoSCTP = 3
)

const (
	ctaProtoinfoTCPState      = 1
	ctaProtoinfoTCPWScaleOrig = 2
	ctaProtoinfoTCPWScaleRepl = 3
	ctaProtoinfoTCPFlagsOrig  = 4
	ctaProtoinfoTCPFlagsRepl  = 5
)

const (
	ctaProtoinfoDCCPState        = 1
	ctaProtoinfoDCCPRole         = 2
	ctaProtoinfoDCCPHandshakeSeq = 3
)

const (
	ctaProtoinfoSCTPState        = 1
	ctaProtoinfoSCTPVTagOriginal = 2
	ctaProtoinfoSCTPVTagReply    = 3
)

const (
	ctaCounterPackets   = 1
	ctaCounterBytes     = 2
	ctaCounter32Packets = 3
	ctaCounter32Bytes   = 4
)

const (
	ctaTimestampStart = 1
	ctaTimestampStop  = 2
)

const (
	ctaSecCtxName = 1
)

const (
	ctaHelpName = 1
	ctaHelpInfo = 2
)

const (
	ctaSeqAdjCorrPos      = 1
	ctaSeqAdjOffsetBefore = 2
	ctaSeqAdjOffsetAfter  = 3
)

const (
	ctaNatV4MinIP = 1
	ctaNatV4MaxIP = 2
	ctaNatProto   = 3
	ctaNatV6MinIP = 4
	ctaNatV6MaxIP = 5
)

const nlafNested = (1 << 15)

func extractSecCtx(v *SecCtx, logger *log.Logger, data []byte) error {
	ad, err := netlink.NewAttributeDecoder(data)
	if err != nil {
		return err
	}
	ad.ByteOrder = binary.BigEndian
	for ad.Next() {
		switch ad.Type() {
		case ctaSecCtxName:
			tmp := ad.String()
			v.Name = &tmp
		default:
			logger.Printf("extractSecCtx(): %d | %d\t %v", ad.Type(), ad.Type()&0xFF, ad.Bytes())
		}
	}
	return ad.Err()
}

func extractTimestamp(v *Timestamp, logger *log.Logger, data []byte) error {
	ad, err := netlink.NewAttributeDecoder(data)
	if err != nil {
		return err
	}
	ad.ByteOrder = binary.BigEndian
	for ad.Next() {
		switch ad.Type() {
		case ctaTimestampStart:
			tmp := ad.Uint64()
			ts := time.Unix(0, int64(tmp))
			v.Start = &ts
		case ctaTimestampStop:
			tmp := ad.Uint64()
			ts := time.Unix(0, int64(tmp))
			v.Stop = &ts
		default:
			logger.Printf("extractTimestamp(): %d | %d\t %v", ad.Type(), ad.Type()&0xFF, ad.Bytes())
		}
	}
	return ad.Err()
}

func extractCounter(v *Counter, logger *log.Logger, data []byte) error {
	ad, err := netlink.NewAttributeDecoder(data)
	if err != nil {
		return err
	}
	ad.ByteOrder = binary.BigEndian
	for ad.Next() {
		switch ad.Type() {
		case ctaCounterPackets:
			tmp := ad.Uint64()
			v.Packets = &tmp
		case ctaCounterBytes:
			tmp := ad.Uint64()
			v.Bytes = &tmp
		case ctaCounter32Packets:
			tmp := ad.Uint32()
			v.Packets32 = &tmp
		case ctaCounter32Bytes:
			tmp := ad.Uint32()
			v.Bytes32 = &tmp
		default:
			logger.Printf("extractCounter(): %d | %d\t %v", ad.Type(), ad.Type()&0xFF, ad.Bytes())
		}
	}
	return ad.Err()
}

func extractDCCPInfo(v *DCCPInfo, logger *log.Logger, data []byte) error {
	ad, err := netlink.NewAttributeDecoder(data)
	if err != nil {
		return err
	}
	ad.ByteOrder = binary.BigEndian
	for ad.Next() {
		switch ad.Type() {
		case ctaProtoinfoDCCPState:
			tmp := ad.Uint8()
			v.State = &tmp
		case ctaProtoinfoDCCPRole:
			tmp := ad.Uint8()
			v.Role = &tmp
		case ctaProtoinfoDCCPHandshakeSeq:
			tmp := ad.Uint64()
			v.HandshakeSeq = &tmp
		default:
			logger.Printf("extractDCCPInfo(): %d | %d\t %v", ad.Type(), ad.Type()&0xFF, ad.Bytes())
		}
	}
	return ad.Err()
}

func extractSCTPInfo(v *SCTPInfo, logger *log.Logger, data []byte) error {
	ad, err := netlink.NewAttributeDecoder(data)
	if err != nil {
		return err
	}
	ad.ByteOrder = binary.BigEndian
	for ad.Next() {
		switch ad.Type() {
		case ctaProtoinfoSCTPState:
			tmp := ad.Uint8()
			v.State = &tmp
		case ctaProtoinfoSCTPVTagOriginal:
			tmp := ad.Uint32()
			v.VTagOriginal = &tmp
		case ctaProtoinfoSCTPVTagReply:
			tmp := ad.Uint32()
			v.VTagReply = &tmp
		default:
			logger.Printf("extractSCTPInfo(): %d | %d\t %v", ad.Type(), ad.Type()&0xFF, ad.Bytes())
		}
	}
	return ad.Err()
}

func extractSeqAdj(v *SeqAdj, logger *log.Logger, data []byte) error {
	ad, err := netlink.NewAttributeDecoder(data)
	if err != nil {
		return err
	}
	ad.ByteOrder = binary.BigEndian
	for ad.Next() {
		switch ad.Type() {
		case ctaSeqAdjCorrPos:
			tmp := ad.Uint32()
			v.CorrectionPos = &tmp
		case ctaSeqAdjOffsetBefore:
			tmp := ad.Uint32()
			v.OffsetBefore = &tmp
		case ctaSeqAdjOffsetAfter:
			tmp := ad.Uint32()
			v.OffsetAfter = &tmp
		default:
			logger.Printf("extractSeqAdj(): %d | %d\t %v", ad.Type(), ad.Type()&0xFF, ad.Bytes())
		}
	}
	return ad.Err()
}

func extractNat(v *Nat, logger *log.Logger, data []byte) error {
	ad, err := netlink.NewAttributeDecoder(data)
	if err != nil {
		return err
	}
	ad.ByteOrder = binary.BigEndian
	for ad.Next() {
		switch ad.Type() {
		case ctaNatV4MinIP:
			tmp := net.IP(ad.Bytes())
			v.IPMin = &tmp
		case ctaNatV4MaxIP:
			tmp := net.IP(ad.Bytes())
			v.IPMax = &tmp
		case ctaNatV6MinIP:
			tmp := net.IP(ad.Bytes())
			v.IPMin = &tmp
		case ctaNatV6MaxIP:
			tmp := net.IP(ad.Bytes())
			v.IPMax = &tmp
		default:
			logger.Printf("extractNat(): %d | %d\t %v", ad.Type(), ad.Type()&0xFF, ad.Bytes())
		}
	}
	return ad.Err()
}

func marshalNat(logger *log.Logger, v *Nat) ([]byte, error) {
	ae := netlink.NewAttributeEncoder()

	if v.IPMin != nil {
		if v.IPMin.To4() == nil && v.IPMin.To16() != nil {
			ae.Bytes(ctaNatV6MinIP, *v.IPMin)
		} else {
			tmp := (*v.IPMin).To4()
			ae.Bytes(ctaNatV4MinIP, tmp)
		}
	}
	if v.IPMax != nil {
		if v.IPMax.To4() == nil && v.IPMax.To16() != nil {
			ae.Bytes(ctaNatV6MaxIP, *v.IPMax)
		} else {
			tmp := (*v.IPMax).To4()
			ae.Bytes(ctaNatV4MaxIP, tmp)
		}
	}
	return ae.Encode()
}

func extractTCPInfo(v *TCPInfo, logger *log.Logger, data []byte) error {
	ad, err := netlink.NewAttributeDecoder(data)
	if err != nil {
		return err
	}
	ad.ByteOrder = binary.BigEndian
	for ad.Next() {
		switch ad.Type() {
		case ctaProtoinfoTCPState:
			tmp := ad.Uint8()
			v.State = &tmp
		case ctaProtoinfoTCPWScaleOrig:
			tmp := ad.Uint8()
			v.WScaleOrig = &tmp
		case ctaProtoinfoTCPWScaleRepl:
			tmp := ad.Uint8()
			v.WScaleRepl = &tmp
		case ctaProtoinfoTCPFlagsOrig:
			flags := &TCPFlags{}
			tmp := ad.Bytes()
			if len(tmp) > 0 {
				flags.Flags = &tmp[0]
			}
			if len(tmp) > 1 {
				flags.Mask = &tmp[1]
			}
			v.FlagsOrig = flags
		case ctaProtoinfoTCPFlagsRepl:
			flags := &TCPFlags{}
			tmp := ad.Bytes()
			if len(tmp) > 0 {
				flags.Flags = &tmp[0]
			}
			if len(tmp) > 1 {
				flags.Mask = &tmp[1]
			}
			v.FlagsReply = flags
		default:
			logger.Printf("extractTCPInfo(): %d | %d\t %v", ad.Type(), ad.Type()&0xFF, ad.Bytes())
		}
	}
	return ad.Err()
}

func marshalTCPInfo(logger *log.Logger, v *TCPInfo) ([]byte, error) {
	ae := netlink.NewAttributeEncoder()

	if v.State != nil {
		ae.ByteOrder = binary.BigEndian
		ae.Uint8(ctaProtoinfoTCPState, *v.State)
		ae.ByteOrder = nativeEndian
	}
	if v.WScaleOrig != nil {
		ae.ByteOrder = binary.BigEndian
		ae.Uint8(ctaProtoinfoTCPWScaleOrig, *v.WScaleOrig)
		ae.ByteOrder = nativeEndian
	}
	if v.WScaleRepl != nil {
		ae.ByteOrder = binary.BigEndian
		ae.Uint8(ctaProtoinfoTCPWScaleRepl, *v.WScaleRepl)
		ae.ByteOrder = nativeEndian
	}
	if v.FlagsOrig != nil {
		tmp := []byte{0x00, 0xff}
		if v.FlagsOrig.Flags != nil {
			tmp[0] = *v.FlagsOrig.Flags
		}
		if v.FlagsOrig.Mask != nil {
			tmp[1] = *v.FlagsOrig.Mask
		}
		ae.Bytes(ctaProtoinfoTCPFlagsOrig, tmp)
	}
	if v.FlagsReply != nil {
		tmp := []byte{0x00, 0xff}
		if v.FlagsReply.Flags != nil {
			tmp[0] = *v.FlagsReply.Flags
		}
		if v.FlagsReply.Mask != nil {
			tmp[1] = *v.FlagsReply.Mask
		}
		ae.Bytes(ctaProtoinfoTCPFlagsRepl, tmp)
	}

	return ae.Encode()
}

func extractProtoInfo(v *ProtoInfo, logger *log.Logger, data []byte) error {
	ad, err := netlink.NewAttributeDecoder(data)
	if err != nil {
		return err
	}
	ad.ByteOrder = nativeEndian
	for ad.Next() {
		switch ad.Type() {
		case ctaProtoinfoTCP:
			tcp := &TCPInfo{}
			if err := extractTCPInfo(tcp, logger, ad.Bytes()); err != nil {
				return err
			}
			v.TCP = tcp
		case ctaProtoinfoDCCP:
			dccp := &DCCPInfo{}
			if err := extractDCCPInfo(dccp, logger, ad.Bytes()); err != nil {
				return err
			}
			v.DCCP = dccp
		case ctaProtoinfoSCTP:
			sctp := &SCTPInfo{}
			if err := extractSCTPInfo(sctp, logger, ad.Bytes()); err != nil {
				return err
			}
			v.SCTP = sctp
		default:
			logger.Printf("extractProtoInfo(): %d | %d\t %v", ad.Type(), ad.Type()&0xFF, ad.Bytes())
		}
	}
	return ad.Err()
}

func marshalProtoInfo(logger *log.Logger, v *ProtoInfo) ([]byte, error) {
	ae := netlink.NewAttributeEncoder()

	if v.TCP != nil {
		data, err := marshalTCPInfo(logger, v.TCP)
		if err != nil {
			return []byte{}, err
		}
		ae.Bytes(ctaProtoinfoTCP|nlafNested, data)
	}

	return ae.Encode()
}

func extractHelper(v *Helper, logger *log.Logger, data []byte) error {
	ad, err := netlink.NewAttributeDecoder(data)
	if err != nil {
		return err
	}
	ad.ByteOrder = binary.BigEndian
	for ad.Next() {
		switch ad.Type() {
		case ctaHelpName:
			tmp := ad.String()
			v.Name = &tmp
		case ctaHelpInfo:
			tmp := ad.String()
			v.Info = &tmp
		default:
			logger.Printf("extractHelper(): %d | %d\t %v", ad.Type(), ad.Type()&0xFF, ad.Bytes())
		}
	}
	return ad.Err()
}

func marshalHelper(logger *log.Logger, v *Helper) ([]byte, error) {
	ae := netlink.NewAttributeEncoder()

	if v.Name != nil {
		ae.String(ctaHelpName, *v.Name)
	}
	if v.Info != nil {
		ae.String(ctaHelpInfo, *v.Info)
	}

	return ae.Encode()
}

func extractProtoTuple(logger *log.Logger, data []byte) (ProtoTuple, error) {
	var proto ProtoTuple
	ad, err := netlink.NewAttributeDecoder(data)
	if err != nil {
		return proto, err
	}
	ad.ByteOrder = binary.BigEndian
	for ad.Next() {
		switch ad.Type() {
		case ctaProtoNum:
			tmp := ad.Uint8()
			proto.Number = &tmp
		case ctaProtoSrcPort:
			tmp := ad.Uint16()
			proto.SrcPort = &tmp
		case ctaProtoDstPort:
			tmp := ad.Uint16()
			proto.DstPort = &tmp
		case ctaProtoIcmpID:
			tmp := ad.Uint16()
			proto.IcmpID = &tmp
		case ctaProtoIcmpType:
			tmp := ad.Uint8()
			proto.IcmpType = &tmp
		case ctaProtoIcmpCode:
			tmp := ad.Uint8()
			proto.IcmpCode = &tmp
		case ctaProtoIcmpv6ID:
			tmp := ad.Uint16()
			proto.Icmpv6ID = &tmp
		case ctaProtoIcmpv6Type:
			tmp := ad.Uint8()
			proto.Icmpv6Type = &tmp
		case ctaProtoIcmpv6Code:
			tmp := ad.Uint8()
			proto.Icmpv6Code = &tmp
		default:
			logger.Printf("extractProtoTuple(): %d | %d\t %v", ad.Type(), ad.Type()&0xFF, ad.Bytes())
		}
	}
	return proto, ad.Err()
}

func marshalProtoTuple(logger *log.Logger, v *ProtoTuple) ([]byte, error) {
	ae := netlink.NewAttributeEncoder()
	ae.ByteOrder = binary.BigEndian
	if v.Number != nil {
		ae.Uint8(ctaProtoNum, *v.Number)
	}
	if v.SrcPort != nil {
		ae.Uint16(ctaProtoSrcPort, *v.SrcPort)
	}
	if v.DstPort != nil {
		ae.Uint16(ctaProtoDstPort, *v.DstPort)
	}
	if v.IcmpID != nil {
		ae.Uint16(ctaProtoIcmpID, *v.IcmpID)
	}
	if v.IcmpType != nil {
		ae.Uint8(ctaProtoIcmpType, *v.IcmpType)
	}
	if v.IcmpCode != nil {
		ae.Uint8(ctaProtoIcmpCode, *v.IcmpCode)
	}
	if v.Icmpv6ID != nil {
		ae.Uint16(ctaProtoIcmpv6ID, *v.Icmpv6ID)
	}
	if v.Icmpv6Type != nil {
		ae.Uint8(ctaProtoIcmpv6Type, *v.Icmpv6Type)
	}
	if v.Icmpv6Code != nil {
		ae.Uint8(ctaProtoIcmpv6Code, *v.Icmpv6Code)
	}

	return ae.Encode()
}

func extractIP(logger *log.Logger, data []byte) (net.IP, net.IP, error) {
	var src, dst net.IP
	ad, err := netlink.NewAttributeDecoder(data)
	if err != nil {
		return src, dst, err
	}
	ad.ByteOrder = nativeEndian
	for ad.Next() {
		switch ad.Type() {
		case ctaIPv4Src:
			src = net.IP(ad.Bytes())
		case ctaIPv4Dst:
			dst = net.IP(ad.Bytes())
		case ctaIPv6Src:
			src = net.IP(ad.Bytes())
		case ctaIPv6Dst:
			dst = net.IP(ad.Bytes())
		default:
			logger.Printf("extractIP(): %d | %d\t %v", ad.Type(), ad.Type()&0xFF, ad.Bytes())
		}
	}
	return src, dst, ad.Err()
}

func marshalIP(logger *log.Logger, v *IPTuple) ([]byte, error) {
	ae := netlink.NewAttributeEncoder()

	if v.Src != nil {
		if v.Src.To4() == nil && v.Src.To16() != nil {
			ae.Bytes(ctaIPv6Src, *v.Src)
		} else {
			tmp := (*v.Src).To4()
			ae.Bytes(ctaIPv4Src, tmp)
		}
	}

	if v.Dst != nil {
		if v.Dst.To4() == nil && v.Dst.To16() != nil {
			ae.Bytes(ctaIPv6Dst, *v.Dst)
		} else {
			tmp := (*v.Dst).To4()
			ae.Bytes(ctaIPv4Dst, tmp)
		}
	}

	return ae.Encode()
}

func extractIPTuple(v *IPTuple, logger *log.Logger, data []byte) error {
	ad, err := netlink.NewAttributeDecoder(data)
	if err != nil {
		return err
	}
	ad.ByteOrder = nativeEndian
	for ad.Next() {
		switch ad.Type() {
		case ctaTupleIP:
			src, dst, err := extractIP(logger, ad.Bytes())
			if err != nil {
				return err
			}
			v.Src = &src
			v.Dst = &dst
		case ctaTupleProto:
			proto, err := extractProtoTuple(logger, ad.Bytes())
			if err != nil {
				return err
			}
			v.Proto = &proto
		case ctaTupleZone:
			ad.ByteOrder = binary.BigEndian
			zone := ad.Uint16()
			v.Zone = &zone
			ad.ByteOrder = nativeEndian
		default:
			logger.Printf("extractIPTuple(): %d | %d\t %v", ad.Type(), ad.Type()&0xFF, ad.Bytes())
		}
	}
	return ad.Err()
}

func marshalIPTuple(logger *log.Logger, v *IPTuple) ([]byte, error) {
	ae := netlink.NewAttributeEncoder()

	if v.Src != nil || v.Dst != nil {
		data, err := marshalIP(logger, v)
		if err != nil {
			return []byte{}, err
		}
		ae.Bytes(ctaTupleIP|nlafNested, data)
	}

	if v.Proto != nil {
		data, err := marshalProtoTuple(logger, v.Proto)
		if err != nil {
			return []byte{}, err
		}
		ae.Bytes(ctaTupleProto|nlafNested, data)
	}

	return ae.Encode()
}

func extractAttribute(c *Con, logger *log.Logger, data []byte) error {
	ad, err := netlink.NewAttributeDecoder(data)
	if err != nil {
		return err
	}
	for ad.Next() {
		switch ad.Type() {
		case ctaTupleOrig:
			tuple := &IPTuple{}
			if err := extractIPTuple(tuple, logger, ad.Bytes()); err != nil {
				return err
			}
			c.Origin = tuple
		case ctaTupleReply:
			tuple := &IPTuple{}
			if err := extractIPTuple(tuple, logger, ad.Bytes()); err != nil {
				return err
			}
			c.Reply = tuple
		case ctaProtoinfo:
			protoInfo := &ProtoInfo{}
			if err := extractProtoInfo(protoInfo, logger, ad.Bytes()); err != nil {
				return err
			}
			c.ProtoInfo = protoInfo
		case ctaHelp:
			help := &Helper{}
			if err := extractHelper(help, logger, ad.Bytes()); err != nil {
				return err
			}
			c.Helper = help
		case ctaID:
			ad.ByteOrder = binary.BigEndian
			tmp := ad.Uint32()
			c.ID = &tmp
			ad.ByteOrder = nativeEndian
		case ctaStatus:
			ad.ByteOrder = binary.BigEndian
			tmp := ad.Uint32()
			c.Status = &tmp
			ad.ByteOrder = nativeEndian
		case ctaUse:
			ad.ByteOrder = binary.BigEndian
			tmp := ad.Uint32()
			c.Use = &tmp
			ad.ByteOrder = nativeEndian
		case ctaMark:
			ad.ByteOrder = binary.BigEndian
			tmp := ad.Uint32()
			c.Mark = &tmp
			ad.ByteOrder = nativeEndian
		case ctaMarkMask:
			ad.ByteOrder = binary.BigEndian
			tmp := ad.Uint32()
			c.MarkMask = &tmp
			ad.ByteOrder = nativeEndian
		case ctaTimeout:
			ad.ByteOrder = binary.BigEndian
			tmp := ad.Uint32()
			c.Timeout = &tmp
			ad.ByteOrder = nativeEndian
		case ctaCountersOrig:
			orig := &Counter{}
			if err := extractCounter(orig, logger, ad.Bytes()); err != nil {
				return err
			}
			c.CounterOrigin = orig
		case ctaCountersReply:
			reply := &Counter{}
			if err := extractCounter(reply, logger, ad.Bytes()); err != nil {
				return err
			}
			c.CounterReply = reply
		case ctaSeqAdjOrig:
			orig := &SeqAdj{}
			if err := extractSeqAdj(orig, logger, ad.Bytes()); err != nil {
				return err
			}
			c.SeqAdjOrig = orig
		case ctaSeqAdjRepl:
			reply := &SeqAdj{}
			if err := extractSeqAdj(reply, logger, ad.Bytes()); err != nil {
				return err
			}
			c.SeqAdjRepl = reply
		case ctaZone:
			ad.ByteOrder = binary.BigEndian
			zone := ad.Uint16()
			c.Zone = &zone
			ad.ByteOrder = nativeEndian
		case ctaSecCtx:
			secCtx := &SecCtx{}
			if err := extractSecCtx(secCtx, logger, ad.Bytes()); err != nil {
				return err
			}
			c.SecCtx = secCtx
		case ctaTimestamp:
			ts := &Timestamp{}
			if err := extractTimestamp(ts, logger, ad.Bytes()); err != nil {
				return err
			}
			c.Timestamp = ts
		case ctaNatSrc:
			nat := &Nat{}
			if err := extractNat(nat, logger, ad.Bytes()); err != nil {
				return err
			}
			c.NatSrc = nat
		case ctaStatusMask:
			ad.ByteOrder = binary.BigEndian
			tmp := ad.Uint32()
			c.StatusMask = &tmp
			ad.ByteOrder = nativeEndian
		default:
			logger.Printf("extractAttribute() - Unknown attribute: %d %d %v\n", ad.Type()&0xFF, ad.Type(), ad.Bytes())
		}
	}
	return ad.Err()
}

func checkHeader(data []byte) int {
	if (data[0] == unix.AF_INET || data[0] == unix.AF_INET6) && data[1] == unix.NFNETLINK_V0 {
		return 4
	}
	return 0
}

func extractAttributes(logger *log.Logger, c *Con, msg []byte) error {
	offset := checkHeader(msg[:2])
	if err := extractAttribute(c, logger, msg[offset:]); err != nil {
		return err
	}
	return nil
}
