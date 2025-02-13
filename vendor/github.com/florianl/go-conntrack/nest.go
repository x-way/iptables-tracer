package conntrack

import (
	"encoding/binary"
	"log"

	"github.com/mdlayher/netlink"
)

func nestAttributes(logger *log.Logger, filters *Con) ([]byte, error) {
	ae := netlink.NewAttributeEncoder()

	if filters.Origin != nil {
		data, err := marshalIPTuple(logger, filters.Origin)
		if err != nil {
			return []byte{}, err
		}
		ae.Bytes(ctaTupleOrig|nlafNested, data)
	}
	if filters.Reply != nil {
		data, err := marshalIPTuple(logger, filters.Reply)
		if err != nil {
			return []byte{}, err
		}
		ae.Bytes(ctaTupleReply|nlafNested, data)
	}

	if filters.ID != nil {
		ae.ByteOrder = binary.BigEndian
		ae.Uint32(ctaID, *filters.ID)
		ae.ByteOrder = nativeEndian
	}
	if filters.Mark != nil {
		ae.ByteOrder = binary.BigEndian
		ae.Uint32(ctaMark, *filters.Mark)
		ae.ByteOrder = nativeEndian
	}

	if filters.MarkMask != nil {
		ae.ByteOrder = binary.BigEndian
		ae.Uint32(ctaMarkMask, *filters.MarkMask)
		ae.ByteOrder = nativeEndian
	}

	if filters.Timeout != nil {
		ae.ByteOrder = binary.BigEndian
		ae.Uint32(ctaTimeout, *filters.Timeout)
		ae.ByteOrder = nativeEndian
	}
	if filters.Status != nil {
		ae.ByteOrder = binary.BigEndian
		ae.Uint32(ctaStatus, *filters.Status)
		ae.ByteOrder = nativeEndian
	}
	if filters.ProtoInfo != nil {
		data, err := marshalProtoInfo(logger, filters.ProtoInfo)
		if err != nil {
			return []byte{}, err
		}
		ae.Bytes(ctaProtoinfo|nlafNested, data)
	}
	if filters.Helper != nil {
		data, err := marshalHelper(logger, filters.Helper)
		if err != nil {
			return []byte{}, err
		}
		ae.Bytes(ctaHelp|nlafNested, data)
	}

	if filters.NatSrc != nil {
		data, err := marshalNat(logger, filters.NatSrc)
		if err != nil {
			return []byte{}, err
		}
		ae.Bytes(ctaNatSrc|nlafNested, data)
	}

	if filters.Exp != nil {
		if err := nestExpectedAttributes(logger, ae, filters.Exp); err != nil {
			return []byte{}, err
		}
	}

	return ae.Encode()
}

func nestExpectedAttributes(logger *log.Logger, ae *netlink.AttributeEncoder, filters *Exp) error {

	if filters.Master != nil {
		data, err := marshalIPTuple(logger, filters.Master)
		if err != nil {
			return err
		}
		ae.Bytes(ctaExpMaster|nlafNested, data)
	}
	if filters.Mask != nil {
		data, err := marshalIPTuple(logger, filters.Mask)
		if err != nil {
			return err
		}
		ae.Bytes(ctaExpMask|nlafNested, data)
	}
	if filters.Tuple != nil {
		data, err := marshalIPTuple(logger, filters.Tuple)
		if err != nil {
			return err
		}
		ae.Bytes(ctaExpTuple|nlafNested, data)
	}
	if filters.Flags != nil {
		ae.ByteOrder = binary.BigEndian
		ae.Uint32(ctaExpFlags, *filters.Flags)
		ae.ByteOrder = nativeEndian
	}
	if filters.Class != nil {
		ae.ByteOrder = binary.BigEndian
		ae.Uint32(ctaExpClass, *filters.Class)
		ae.ByteOrder = nativeEndian
	}
	if filters.ID != nil {
		ae.ByteOrder = binary.BigEndian
		ae.Uint32(ctaExpID, *filters.ID)
		ae.ByteOrder = nativeEndian
	}
	if filters.Timeout != nil {
		ae.ByteOrder = binary.BigEndian
		ae.Uint32(ctaExpTimeout, *filters.Timeout)
		ae.ByteOrder = nativeEndian
	}
	if filters.Zone != nil {
		ae.ByteOrder = binary.BigEndian
		ae.Uint16(ctaExpZone, *filters.Zone)
		ae.ByteOrder = nativeEndian
	}
	if filters.HelperName != nil {
		ae.ByteOrder = binary.BigEndian
		ae.String(ctaExpHelpName, *filters.HelperName)
		ae.ByteOrder = nativeEndian
	}
	if filters.Fn != nil {
		ae.ByteOrder = binary.BigEndian
		ae.String(ctaExpFn, *filters.Fn)
		ae.ByteOrder = nativeEndian
	}
	if filters.Nat != nil {
		data, err := marshalNatInfo(logger, filters.Nat)
		if err != nil {
			return err
		}
		ae.Bytes(ctaExpNat|nlafNested, data)
	}
	return nil
}
