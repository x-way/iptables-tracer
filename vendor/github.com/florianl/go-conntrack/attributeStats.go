package conntrack

import (
	"encoding/binary"
	"log"

	"github.com/mdlayher/netlink"
)

const (
	ctaStatsUnspec   = iota
	ctaStatsSearched /* no longer used */
	ctaStatsFound
	ctaStatsNew /* no longer used */
	ctaStatsInvalid
	ctaStatsIgnore
	ctaStatsDelete     /* no longer used */
	ctaStatsDeleteList /* no longer used */
	ctaStatsInsert
	ctaStatsInsertFailed
	ctaStatsDrop
	ctaStatsEarlyDrop
	ctaStatsError
	ctaStatsSearchRestart
)

const (
	ctaStatsExpUnspec = iota
	ctaStatsExpNew
	ctaStatsExpCreate
	ctaStatsExpDelete
)

func extractCPUStats(s *CPUStat, logger *log.Logger, data []byte) error {
	ad, err := netlink.NewAttributeDecoder(data)
	if err != nil {
		return err
	}

	// the CPU ID does not have its own attribute
	s.ID = binary.BigEndian.Uint32(data[0:4])

	ad.ByteOrder = binary.BigEndian
	for ad.Next() {
		switch ad.Type() {
		case ctaStatsFound:
			tmp := ad.Uint32()
			s.Found = &tmp
		case ctaStatsInvalid:
			tmp := ad.Uint32()
			s.Invalid = &tmp
		case ctaStatsIgnore:
			tmp := ad.Uint32()
			s.Ignore = &tmp
		case ctaStatsInsert:
			tmp := ad.Uint32()
			s.Insert = &tmp
		case ctaStatsInsertFailed:
			tmp := ad.Uint32()
			s.InsertFailed = &tmp
		case ctaStatsDrop:
			tmp := ad.Uint32()
			s.Drop = &tmp
		case ctaStatsEarlyDrop:
			tmp := ad.Uint32()
			s.EarlyDrop = &tmp
		case ctaStatsError:
			tmp := ad.Uint32()
			s.Error = &tmp
		case ctaStatsSearchRestart:
			tmp := ad.Uint32()
			s.SearchRestart = &tmp
		default:
			logger.Printf("extractCPUStats()): %d | %d\t %v", ad.Type(), ad.Type()&0xFF, ad.Bytes())
		}
	}
	return ad.Err()
}

func extractExpCPUStats(s *CPUStat, logger *log.Logger, data []byte) error {
	ad, err := netlink.NewAttributeDecoder(data)
	if err != nil {
		return err
	}

	// the CPU ID does not have its own attribute
	s.ID = binary.BigEndian.Uint32(data[0:4])

	ad.ByteOrder = binary.BigEndian
	for ad.Next() {
		switch ad.Type() {
		case ctaStatsExpNew:
			tmp := ad.Uint32()
			s.ExpNew = &tmp
		case ctaStatsExpCreate:
			tmp := ad.Uint32()
			s.ExpCreate = &tmp
		case ctaStatsExpDelete:
			tmp := ad.Uint32()
			s.ExpDelete = &tmp
		default:
			logger.Printf("extractExpCPUStats()): %d | %d\t %v", ad.Type(), ad.Type()&0xFF, ad.Bytes())
		}
	}
	return ad.Err()
}
