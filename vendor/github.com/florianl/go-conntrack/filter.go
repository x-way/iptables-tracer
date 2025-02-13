package conntrack

import (
	"errors"

	"github.com/mdlayher/netlink"
)

// Error which may occur when processing the filter attribute
var (
	ErrFilterAttrLength = errors.New("incorrect length of filter attribute")
)

func nestFilter(filter FilterAttr) ([]byte, error) {
	var attrs []netlink.Attribute

	if len(filter.Mark) != 4 {
		return nil, ErrFilterAttrLength
	}
	if len(filter.MarkMask) != 4 {
		return nil, ErrFilterAttrLength
	}
	attrs = append(attrs, netlink.Attribute{Type: ctaMark, Data: filter.Mark}, netlink.Attribute{Type: ctaMarkMask, Data: filter.MarkMask})

	return netlink.MarshalAttributes(attrs)
}
