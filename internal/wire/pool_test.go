package wire

import (
	"github.com/lucas-clemente/quic-go/internal/protocol"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Pool", func() {
	Context("for STREAM frames", func() {
		It("gets and puts STREAM frames", func() {
			f := GetStreamFrame()
			putStreamFrame(f)
		})

		It("panics when putting a STREAM frame with a wrong capacity", func() {
			f := GetStreamFrame()
			f.Data = []byte("foobar")
			Expect(func() { putStreamFrame(f) }).To(Panic())
		})

		It("accepts STREAM frames not from the buffer, but ignores them", func() {
			f := &StreamFrame{Data: []byte("foobar")}
			putStreamFrame(f)
		})
	})

	Context("for ACK frames", func() {
		It("gets and puts ACK frames", func() {
			f := GetAckFrame()
			putAckFrame(f)
		})

		It("panics when putting a STREAM frame with a wrong capacity", func() {
			f := GetAckFrame()
			f.AckRanges = make([]AckRange, 0, protocol.MaxNumAckRanges-1)
			Expect(func() { putAckFrame(f) }).To(Panic())
		})
	})
})
