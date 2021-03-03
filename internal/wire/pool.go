package wire

import (
	"sync"

	"github.com/lucas-clemente/quic-go/internal/protocol"
)

var streamFramePool, ackFramePool sync.Pool

func init() {
	streamFramePool.New = func() interface{} {
		return &StreamFrame{
			Data:     make([]byte, 0, protocol.MaxReceivePacketSize),
			fromPool: true,
		}
	}
	ackFramePool.New = func() interface{} {
		return &AckFrame{
			AckRanges: make([]AckRange, 0, protocol.MaxNumAckRanges),
		}
	}
}

func GetStreamFrame() *StreamFrame {
	f := streamFramePool.Get().(*StreamFrame)
	return f
}

func putStreamFrame(f *StreamFrame) {
	if !f.fromPool {
		return
	}
	if protocol.ByteCount(cap(f.Data)) != protocol.MaxReceivePacketSize {
		panic("wire.putStreamFrame called with frame of wrong size!")
	}
	streamFramePool.Put(f)
}

// GetAckFrame gets an ACK frame from the pool.
// It is the callers responsibility to fill *all* of the fields of the returned ACK frame.
func GetAckFrame() *AckFrame {
	return ackFramePool.Get().(*AckFrame)
}

func putAckFrame(f *AckFrame) {
	if cap(f.AckRanges) != protocol.MaxNumAckRanges {
		panic("wire.putAckFrame called with frame with wrong ACK range list length!")
	}
	ackFramePool.Put(f)
}
