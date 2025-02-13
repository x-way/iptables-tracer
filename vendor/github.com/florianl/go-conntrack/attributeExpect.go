package conntrack

import (
	"encoding/binary"
	"log"

	"github.com/mdlayher/netlink"
)

const (
	ctaExpUnspec = iota
	ctaExpMaster
	ctaExpTuple
	ctaExpMask
	ctaExpTimeout
	ctaExpID
	ctaExpHelpName
	ctaExpZone
	ctaExpFlags
	ctaExpClass
	ctaExpNat
	ctaExpFn
)

const (
	ctaExpNatUnspec = iota
	ctaExpNatDir
	ctaExpNatTuple
)

func extractNatInfo(v *NatInfo, logger *log.Logger, data []byte) error {
	ad, err := netlink.NewAttributeDecoder(data)
	if err != nil {
		return err
	}
	ad.ByteOrder = nativeEndian
	for ad.Next() {
		switch ad.Type() {
		case ctaExpNatDir:
			ad.ByteOrder = binary.BigEndian
			tmp := ad.Uint32()
			v.Dir = &tmp
			ad.ByteOrder = nativeEndian
		case ctaExpNatTuple:
			tuple := &IPTuple{}
			if err := extractIPTuple(tuple, logger, ad.Bytes()); err != nil {
				return err
			}
			v.Tuple = tuple
		default:
			logger.Printf("extractNatInfo(): %d | %d\t %v", ad.Type(), ad.Type()&0xFF, ad.Bytes())
		}
	}
	return ad.Err()
}

func marshalNatInfo(logger *log.Logger, v *NatInfo) ([]byte, error) {
	ae := netlink.NewAttributeEncoder()

	if v.Dir != nil {
		ae.ByteOrder = binary.BigEndian
		ae.Uint32(ctaExpNatDir, *v.Dir)
		ae.ByteOrder = nativeEndian
	}
	if v.Tuple != nil {
		data, err := marshalIPTuple(logger, v.Tuple)
		if err != nil {
			return []byte{}, err
		}
		ae.Bytes(ctaExpNatTuple|nlafNested, data)
	}

	return ae.Encode()
}

func extractAttributeExpect(c *Con, logger *log.Logger, data []byte) error {
	ad, err := netlink.NewAttributeDecoder(data)
	if err != nil {
		return err
	}

	c.Exp = &Exp{}

	for ad.Next() {
		switch ad.Type() {
		case ctaExpMaster:
			tuple := &IPTuple{}
			if err := extractIPTuple(tuple, logger, ad.Bytes()); err != nil {
				return err
			}
			c.Origin = tuple
		case ctaExpTuple:
			tuple := &IPTuple{}
			if err := extractIPTuple(tuple, logger, ad.Bytes()); err != nil {
				return err
			}
			c.Exp.Tuple = tuple
		case ctaExpMask:
			tuple := &IPTuple{}
			if err := extractIPTuple(tuple, logger, ad.Bytes()); err != nil {
				return err
			}
			c.Exp.Mask = tuple
		case ctaExpTimeout:
			ad.ByteOrder = binary.BigEndian
			tmp := ad.Uint32()
			c.Exp.Timeout = &tmp
			ad.ByteOrder = nativeEndian
		case ctaExpID:
			ad.ByteOrder = binary.BigEndian
			tmp := ad.Uint32()
			c.Exp.ID = &tmp
			ad.ByteOrder = nativeEndian
		case ctaExpHelpName:
			tmp := ad.String()
			c.Exp.HelperName = &tmp
		case ctaExpZone:
			ad.ByteOrder = binary.BigEndian
			zone := ad.Uint16()
			c.Exp.Zone = &zone
			ad.ByteOrder = nativeEndian
		case ctaExpFlags:
			ad.ByteOrder = binary.BigEndian
			tmp := ad.Uint32()
			c.Exp.Flags = &tmp
			ad.ByteOrder = nativeEndian
		case ctaExpClass:
			ad.ByteOrder = binary.BigEndian
			tmp := ad.Uint32()
			c.Exp.Class = &tmp
			ad.ByteOrder = nativeEndian
		case ctaExpNat:
			tmp := &NatInfo{}
			if err := extractNatInfo(tmp, logger, ad.Bytes()); err != nil {
				return err
			}
			c.Exp.Nat = tmp
		case ctaExpFn:
			tmp := ad.String()
			c.Exp.Fn = &tmp
		default:
			logger.Printf("extractAttributeExpect() - Unknown attribute: %d %d %v\n", ad.Type()&0xFF, ad.Type(), ad.Bytes())
		}
	}
	return ad.Err()
}

func extractExpectAttributes(logger *log.Logger, c *Con, msg []byte) error {
	offset := checkHeader(msg[:2])
	if err := extractAttributeExpect(c, logger, msg[offset:]); err != nil {
		return err
	}
	return nil
}
