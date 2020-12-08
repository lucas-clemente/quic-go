package wire

import (
	"bytes"
	"encoding/binary"
	"io"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Header Parsing", func() {
	appendVersion := func(data []byte, v protocol.VersionNumber) []byte {
		offset := len(data)
		data = append(data, []byte{0, 0, 0, 0}...)
		binary.BigEndian.PutUint32(data[offset:], uint32(v))
		return data
	}

	It("distinguishes between long and short header packets", func() {
		Expect(IsLongHeader(0b10101011)).To(BeTrue())
		Expect(IsLongHeader(0b00101011)).To(BeFalse())
	})

	Context("Parsing the Connection ID", func() {
		It("parses the connection ID of a long header packet", func() {
			buf := &bytes.Buffer{}
			Expect((&ExtendedHeader{
				Header: Header{
					IsLongHeader:     true,
					Type:             protocol.PacketTypeHandshake,
					DestConnectionID: protocol.ConnectionID{0xde, 0xca, 0xfb, 0xad},
					SrcConnectionID:  protocol.ConnectionID{1, 2, 3, 4, 5, 6},
					Version:          versionIETFFrames,
				},
				PacketNumberLen: 2,
			}).Write(buf, versionIETFFrames)).To(Succeed())
			connID, err := ParseConnectionID(buf.Bytes(), 8)
			Expect(err).ToNot(HaveOccurred())
			Expect(connID).To(Equal(protocol.ConnectionID{0xde, 0xca, 0xfb, 0xad}))
		})

		It("parses the connection ID of a short header packet", func() {
			buf := &bytes.Buffer{}
			Expect((&ExtendedHeader{
				Header: Header{
					DestConnectionID: protocol.ConnectionID{0xde, 0xca, 0xfb, 0xad},
				},
				PacketNumberLen: 2,
			}).Write(buf, versionIETFFrames)).To(Succeed())
			buf.Write([]byte("foobar"))
			connID, err := ParseConnectionID(buf.Bytes(), 4)
			Expect(err).ToNot(HaveOccurred())
			Expect(connID).To(Equal(protocol.ConnectionID{0xde, 0xca, 0xfb, 0xad}))
		})

		It("errors on EOF, for short header packets", func() {
			buf := &bytes.Buffer{}
			Expect((&ExtendedHeader{
				Header: Header{
					DestConnectionID: protocol.ConnectionID{1, 2, 3, 4, 5, 6, 7, 8},
				},
				PacketNumberLen: 2,
			}).Write(buf, versionIETFFrames)).To(Succeed())
			data := buf.Bytes()[:buf.Len()-2] // cut the packet number
			_, err := ParseConnectionID(data, 8)
			Expect(err).ToNot(HaveOccurred())
			for i := 0; i < len(data); i++ {
				b := make([]byte, i)
				copy(b, data[:i])
				_, err := ParseConnectionID(b, 8)
				Expect(err).To(MatchError(io.EOF))
			}
		})

		It("errors on EOF, for long header packets", func() {
			buf := &bytes.Buffer{}
			Expect((&ExtendedHeader{
				Header: Header{
					IsLongHeader:     true,
					Type:             protocol.PacketTypeHandshake,
					DestConnectionID: protocol.ConnectionID{0xde, 0xca, 0xfb, 0xad, 0x13, 0x37},
					SrcConnectionID:  protocol.ConnectionID{1, 2, 3, 4, 5, 6, 8, 9},
					Version:          versionIETFFrames,
				},
				PacketNumberLen: 2,
			}).Write(buf, versionIETFFrames)).To(Succeed())
			data := buf.Bytes()[:buf.Len()-2] // cut the packet number
			_, err := ParseConnectionID(data, 8)
			Expect(err).ToNot(HaveOccurred())
			for i := 0; i < 1 /* first byte */ +4 /* version */ +1 /* conn ID lengths */ +6; /* dest conn ID */ i++ {
				b := make([]byte, i)
				copy(b, data[:i])
				_, err := ParseConnectionID(b, 8)
				Expect(err).To(MatchError(io.EOF))
			}
		})
	})

	Context("Identifying Version Negotiation Packets", func() {
		It("identifies version negotiation packets", func() {
			Expect(IsVersionNegotiationPacket([]byte{0x80 | 0x56, 0, 0, 0, 0})).To(BeTrue())
			Expect(IsVersionNegotiationPacket([]byte{0x56, 0, 0, 0, 0})).To(BeFalse())
			Expect(IsVersionNegotiationPacket([]byte{0x80, 1, 0, 0, 0})).To(BeFalse())
			Expect(IsVersionNegotiationPacket([]byte{0x80, 0, 1, 0, 0})).To(BeFalse())
			Expect(IsVersionNegotiationPacket([]byte{0x80, 0, 0, 1, 0})).To(BeFalse())
			Expect(IsVersionNegotiationPacket([]byte{0x80, 0, 0, 0, 1})).To(BeFalse())
		})

		It("returns false on EOF", func() {
			vnp := []byte{0x80, 0, 0, 0, 0}
			for i := range vnp {
				Expect(IsVersionNegotiationPacket(vnp[:i])).To(BeFalse())
			}
		})
	})

	Context("Long Headers", func() {
		It("parses a Long Header", func() {
			destConnID := protocol.ConnectionID{9, 8, 7, 6, 5, 4, 3, 2, 1}
			srcConnID := protocol.ConnectionID{0xde, 0xad, 0xbe, 0xef}
			data := []byte{0xc0 ^ 0x3}
			data = appendVersion(data, versionIETFFrames)
			data = append(data, 0x9) // dest conn id length
			data = append(data, destConnID...)
			data = append(data, 0x4) // src conn id length
			data = append(data, srcConnID...)
			data = append(data, encodeVarInt(6)...)  // token length
			data = append(data, []byte("foobar")...) // token
			data = append(data, encodeVarInt(10)...) // length
			hdrLen := len(data)
			data = append(data, []byte{0, 0, 0xbe, 0xef}...) // packet number
			data = append(data, []byte("foobar")...)
			Expect(IsVersionNegotiationPacket(data)).To(BeFalse())

			Expect(IsLongHeader(data[0])).To(BeTrue())
			hdr, pdata, rest, err := ParseLongHeaderPacket(data)
			Expect(err).ToNot(HaveOccurred())
			Expect(pdata).To(Equal(data))
			Expect(hdr.IsLongHeader).To(BeTrue())
			Expect(hdr.DestConnectionID).To(Equal(destConnID))
			Expect(hdr.SrcConnectionID).To(Equal(srcConnID))
			Expect(hdr.Type).To(Equal(protocol.PacketTypeInitial))
			Expect(hdr.Token).To(Equal([]byte("foobar")))
			Expect(hdr.Length).To(Equal(protocol.ByteCount(10)))
			Expect(hdr.Version).To(Equal(versionIETFFrames))
			Expect(rest).To(BeEmpty())
			b := bytes.NewReader(data)
			extHdr, err := hdr.ParseExtended(b, versionIETFFrames)
			Expect(err).ToNot(HaveOccurred())
			Expect(extHdr.PacketNumber).To(Equal(protocol.PacketNumber(0xbeef)))
			Expect(extHdr.PacketNumberLen).To(Equal(protocol.PacketNumberLen4))
			Expect(b.Len()).To(Equal(6)) // foobar
			Expect(hdr.ParsedLen()).To(BeEquivalentTo(hdrLen))
			Expect(extHdr.ParsedLen()).To(Equal(hdr.ParsedLen() + 4))
		})

		It("errors when the QUIC bit is not set", func() {
			data := []byte{
				0b10000000,
				0x11,                   // connection ID lengths
				0xde, 0xca, 0xfb, 0xad, // dest conn ID
				0xde, 0xad, 0xbe, 0xef, // src conn ID
			}
			_, _, _, err := ParseLongHeaderPacket(data)
			Expect(err).To(MatchError("not a QUIC packet"))
		})

		It("stops parsing when encountering an unsupported version", func() {
			data := []byte{
				0b11000000,
				0xde, 0xad, 0xbe, 0xef,
				0x8,                                    // dest conn ID len
				0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, // dest conn ID
				0x8,                                    // src conn ID len
				0x8, 0x7, 0x6, 0x5, 0x4, 0x3, 0x2, 0x1, // src conn ID
				'f', 'o', 'o', 'b', 'a', 'r', // unspecified bytes
			}
			hdr, _, rest, err := ParseLongHeaderPacket(data)
			Expect(err).To(MatchError(ErrUnsupportedVersion))
			Expect(hdr.IsLongHeader).To(BeTrue())
			Expect(hdr.Version).To(Equal(protocol.VersionNumber(0xdeadbeef)))
			Expect(hdr.DestConnectionID).To(Equal(protocol.ConnectionID{0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8}))
			Expect(hdr.SrcConnectionID).To(Equal(protocol.ConnectionID{0x8, 0x7, 0x6, 0x5, 0x4, 0x3, 0x2, 0x1}))
			Expect(rest).To(BeEmpty())
		})

		It("parses a Long Header without a destination connection ID", func() {
			data := []byte{0xc0 ^ 0x1<<4}
			data = appendVersion(data, versionIETFFrames)
			data = append(data, 0x0)                               // dest conn ID len
			data = append(data, 0x4)                               // src conn ID len
			data = append(data, []byte{0xde, 0xad, 0xbe, 0xef}...) // source connection ID
			data = append(data, encodeVarInt(0)...)                // length
			data = append(data, []byte{0xde, 0xca, 0xfb, 0xad}...)
			Expect(IsLongHeader(data[0])).To(BeTrue())
			hdr, _, _, err := ParseLongHeaderPacket(data)
			Expect(err).ToNot(HaveOccurred())
			Expect(hdr.Type).To(Equal(protocol.PacketType0RTT))
			Expect(hdr.SrcConnectionID).To(Equal(protocol.ConnectionID{0xde, 0xad, 0xbe, 0xef}))
			Expect(hdr.DestConnectionID).To(BeEmpty())
		})

		It("parses a Long Header without a source connection ID", func() {
			data := []byte{0xc0 ^ 0x2<<4}
			data = appendVersion(data, versionIETFFrames)
			data = append(data, 0xa)                                      // dest conn ID len
			data = append(data, []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}...) // dest connection ID
			data = append(data, 0x0)                                      // src conn ID len
			data = append(data, encodeVarInt(0)...)                       // length
			data = append(data, []byte{0xde, 0xca, 0xfb, 0xad}...)
			hdr, _, _, err := ParseLongHeaderPacket(data)
			Expect(err).ToNot(HaveOccurred())
			Expect(hdr.SrcConnectionID).To(BeEmpty())
			Expect(hdr.DestConnectionID).To(Equal(protocol.ConnectionID{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}))
		})

		It("parses a Long Header with a 2 byte packet number", func() {
			data := []byte{0xc0 ^ 0x1}
			data = appendVersion(data, versionIETFFrames) // version number
			data = append(data, []byte{0x0, 0x0}...)      // connection ID lengths
			data = append(data, encodeVarInt(0)...)       // token length
			data = append(data, encodeVarInt(0)...)       // length
			data = append(data, []byte{0x1, 0x23}...)

			hdr, _, _, err := ParseLongHeaderPacket(data)
			Expect(err).ToNot(HaveOccurred())
			b := bytes.NewReader(data)
			extHdr, err := hdr.ParseExtended(b, versionIETFFrames)
			Expect(err).ToNot(HaveOccurred())
			Expect(extHdr.PacketNumber).To(Equal(protocol.PacketNumber(0x123)))
			Expect(extHdr.PacketNumberLen).To(Equal(protocol.PacketNumberLen2))
			Expect(b.Len()).To(BeZero())
		})

		It("parses a Retry packet", func() {
			data := []byte{0xc0 | 0x3<<4 | (10 - 3) /* connection ID length */}
			data = appendVersion(data, versionIETFFrames)
			data = append(data, []byte{6}...)                             // dest conn ID len
			data = append(data, []byte{6, 5, 4, 3, 2, 1}...)              // dest conn ID
			data = append(data, []byte{10}...)                            // src conn ID len
			data = append(data, []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}...) // source connection ID
			data = append(data, []byte{'f', 'o', 'o', 'b', 'a', 'r'}...)  // token
			data = append(data, []byte{16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1}...)
			hdr, pdata, rest, err := ParseLongHeaderPacket(data)
			Expect(err).ToNot(HaveOccurred())
			Expect(hdr.Type).To(Equal(protocol.PacketTypeRetry))
			Expect(hdr.DestConnectionID).To(Equal(protocol.ConnectionID{6, 5, 4, 3, 2, 1}))
			Expect(hdr.SrcConnectionID).To(Equal(protocol.ConnectionID{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}))
			Expect(hdr.Token).To(Equal([]byte("foobar")))
			Expect(pdata).To(Equal(data))
			Expect(rest).To(BeEmpty())
		})

		It("errors if the Retry packet is too short for the integrity tag", func() {
			data := []byte{0xc0 | 0x3<<4 | (10 - 3) /* connection ID length */}
			data = appendVersion(data, versionIETFFrames)
			data = append(data, []byte{0, 0}...)                         // conn ID lens
			data = append(data, []byte{'f', 'o', 'o', 'b', 'a', 'r'}...) // token
			data = append(data, []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}...)
			// this results in a token length of 0
			_, _, _, err := ParseLongHeaderPacket(data)
			Expect(err).To(MatchError(io.EOF))
		})

		It("errors if the token length is too large", func() {
			data := []byte{0xc0 ^ 0x1}
			data = appendVersion(data, versionIETFFrames)
			data = append(data, 0x0)                   // connection ID lengths
			data = append(data, encodeVarInt(4)...)    // token length: 4 bytes (1 byte too long)
			data = append(data, encodeVarInt(0x42)...) // length, 1 byte
			data = append(data, []byte{0x12, 0x34}...) // packet number

			_, _, _, err := ParseLongHeaderPacket(data)
			Expect(err).To(MatchError(io.EOF))
		})

		It("errors if the 5th or 6th bit are set", func() {
			data := []byte{0xc0 | 0x2<<4 | 0x8 /* set the 5th bit */ | 0x1 /* 2 byte packet number */}
			data = appendVersion(data, versionIETFFrames)
			data = append(data, []byte{0x0, 0x0}...)   // connection ID lengths
			data = append(data, encodeVarInt(2)...)    // length
			data = append(data, []byte{0x12, 0x34}...) // packet number
			hdr, _, _, err := ParseLongHeaderPacket(data)
			Expect(err).ToNot(HaveOccurred())
			Expect(hdr.Type).To(Equal(protocol.PacketTypeHandshake))
			extHdr, err := hdr.ParseExtended(bytes.NewReader(data), versionIETFFrames)
			Expect(err).To(MatchError(ErrInvalidReservedBits))
			Expect(extHdr).ToNot(BeNil())
			Expect(extHdr.PacketNumber).To(Equal(protocol.PacketNumber(0x1234)))
		})

		It("errors on EOF, when parsing the header", func() {
			data := []byte{0xc0 ^ 0x2<<4}
			data = appendVersion(data, versionIETFFrames)
			data = append(data, 0x8)                                                       // dest conn ID len
			data = append(data, []byte{0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0x13, 0x37}...) // dest conn ID
			data = append(data, 0x8)                                                       // src conn ID len
			data = append(data, []byte{0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0x13, 0x37}...) // src conn ID
			for i := 0; i < len(data); i++ {
				_, _, _, err := ParseLongHeaderPacket(data[:i])
				Expect(err).To(Equal(io.EOF))
			}
		})

		It("errors on EOF, when parsing the extended header", func() {
			data := []byte{0xc0 | 0x2<<4 | 0x3}
			data = appendVersion(data, versionIETFFrames)
			data = append(data, []byte{0x0, 0x0}...) // connection ID lengths
			data = append(data, encodeVarInt(0)...)  // length
			hdrLen := len(data)
			data = append(data, []byte{0xde, 0xad, 0xbe, 0xef}...) // packet number
			for i := hdrLen; i < len(data); i++ {
				data = data[:i]
				hdr, _, _, err := ParseLongHeaderPacket(data)
				Expect(err).ToNot(HaveOccurred())
				b := bytes.NewReader(data)
				_, err = hdr.ParseExtended(b, versionIETFFrames)
				Expect(err).To(Equal(io.EOF))
			}
		})

		It("errors on EOF, for a Retry packet", func() {
			data := []byte{0xc0 ^ 0x3<<4}
			data = appendVersion(data, versionIETFFrames)
			data = append(data, []byte{0x0, 0x0}...)                      // connection ID lengths
			data = append(data, 0xa)                                      // Orig Destination Connection ID length
			data = append(data, []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}...) // source connection ID
			hdrLen := len(data)
			for i := hdrLen; i < len(data); i++ {
				data = data[:i]
				hdr, _, _, err := ParseLongHeaderPacket(data)
				Expect(err).ToNot(HaveOccurred())
				b := bytes.NewReader(data)
				_, err = hdr.ParseExtended(b, versionIETFFrames)
				Expect(err).To(Equal(io.EOF))
			}
		})

		Context("coalesced packets", func() {
			It("cuts packets", func() {
				buf := &bytes.Buffer{}
				hdr := Header{
					IsLongHeader:     true,
					Type:             protocol.PacketTypeInitial,
					DestConnectionID: protocol.ConnectionID{1, 2, 3, 4},
					Length:           2 + 6,
					Version:          versionIETFFrames,
				}
				Expect((&ExtendedHeader{
					Header:          hdr,
					PacketNumber:    0x1337,
					PacketNumberLen: 2,
				}).Write(buf, versionIETFFrames)).To(Succeed())
				hdrRaw := append([]byte{}, buf.Bytes()...)
				buf.Write([]byte("foobar")) // payload of the first packet
				buf.Write([]byte("raboof")) // second packet
				parsedHdr, data, rest, err := ParseLongHeaderPacket(buf.Bytes())
				Expect(err).ToNot(HaveOccurred())
				Expect(parsedHdr.Type).To(Equal(hdr.Type))
				Expect(parsedHdr.DestConnectionID).To(Equal(hdr.DestConnectionID))
				Expect(data).To(Equal(append(hdrRaw, []byte("foobar")...)))
				Expect(rest).To(Equal([]byte("raboof")))
			})

			It("errors on packets that are smaller than the length in the packet header, for too small packet number", func() {
				buf := &bytes.Buffer{}
				Expect((&ExtendedHeader{
					Header: Header{
						IsLongHeader:     true,
						Type:             protocol.PacketTypeInitial,
						DestConnectionID: protocol.ConnectionID{1, 2, 3, 4},
						Length:           3,
						Version:          versionIETFFrames,
					},
					PacketNumber:    0x1337,
					PacketNumberLen: 2,
				}).Write(buf, versionIETFFrames)).To(Succeed())
				_, _, _, err := ParseLongHeaderPacket(buf.Bytes())
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("packet length (2 bytes) is smaller than the expected length (3 bytes)"))
			})

			It("errors on packets that are smaller than the length in the packet header, for too small payload", func() {
				buf := &bytes.Buffer{}
				Expect((&ExtendedHeader{
					Header: Header{
						IsLongHeader:     true,
						Type:             protocol.PacketTypeInitial,
						DestConnectionID: protocol.ConnectionID{1, 2, 3, 4},
						Length:           1000,
						Version:          versionIETFFrames,
					},
					PacketNumber:    0x1337,
					PacketNumberLen: 2,
				}).Write(buf, versionIETFFrames)).To(Succeed())
				buf.Write(make([]byte, 500-2 /* for packet number length */))
				_, _, _, err := ParseLongHeaderPacket(buf.Bytes())
				Expect(err).To(MatchError("packet length (500 bytes) is smaller than the expected length (1000 bytes)"))
			})
		})
	})

	It("tells its packet type for logging", func() {
		Expect((&Header{IsLongHeader: true, Type: protocol.PacketTypeHandshake}).PacketType()).To(Equal("Handshake"))
		Expect((&Header{}).PacketType()).To(Equal("1-RTT"))
	})
})
