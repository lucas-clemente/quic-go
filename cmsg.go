// +build darwin linux

package quic

import (
	"syscall"
	"unsafe"

	"github.com/lucas-clemente/quic-go/internal/protocol"
)

// ecnFromControlMessage parses b as an array of socket control messages.
// This is an optimization over using syscall.ParseSocketControlMessage() (which returns a []syscall.SocketControlMessage).
// thereby avoiding unnecessary allocations.
func ecnFromControlMessage(b []byte) (protocol.ECN, error) {
	var ecn protocol.ECN
	i := 0
	for i+syscall.CmsgLen(0) <= len(b) {
		h, dbuf, err := socketControlMessageHeaderAndData(b[i:])
		if err != nil {
			return 0, err
		}
		if h.Level == syscall.IPPROTO_IP && h.Type == msgTypeIPTOS {
			ecn = protocol.ECN(dbuf[0] & ecnMask)
			break
		}
		if h.Level == syscall.IPPROTO_IPV6 && h.Type == syscall.IPV6_TCLASS {
			ecn = protocol.ECN(dbuf[0] & ecnMask)
			break
		}
		i += cmsgAlignOf(int(h.Len))
	}
	return ecn, nil
}

func socketControlMessageHeaderAndData(b []byte) (*syscall.Cmsghdr, []byte, error) {
	h := (*syscall.Cmsghdr)(unsafe.Pointer(&b[0]))
	//nolint:unconvert // h.Len uses a different type depending on the architecture
	if h.Len < syscall.SizeofCmsghdr || uint64(h.Len) > uint64(len(b)) {
		return nil, nil, syscall.EINVAL
	}
	return h, b[cmsgAlignOf(syscall.SizeofCmsghdr):h.Len], nil
}

//go:linkname cmsgAlignOf syscall.cmsgAlignOf
func cmsgAlignOf(salen int) int
