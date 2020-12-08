package wire

import (
	"bytes"
	"log"
	"os"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Header", func() {
	const versionIETFHeader = protocol.VersionTLS // a QUIC version that uses the IETF Header format

	It("checks the value of the reserved bits in a short header packet", func() {
		Expect(CheckShortHeaderReservedBits(0b01100111)).To(BeTrue())
		Expect(CheckShortHeaderReservedBits(0b01110111)).To(BeFalse())
		Expect(CheckShortHeaderReservedBits(0b01111011)).To(BeFalse())
		Expect(CheckShortHeaderReservedBits(0b01111111)).To(BeFalse())
	})

	It("reads the value of the key phase bit", func() {
		Expect(ReadKeyPhaseBit(0b00000011)).To(Equal(protocol.KeyPhaseZero))
		Expect(ReadKeyPhaseBit(0b00000111)).To(Equal(protocol.KeyPhaseOne))
	})

	It("reads a 1-byte packet number", func() {
		pn, pnLen, err := ReadPacketNumber(bytes.NewReader([]byte{0x24}), 0b11111100)
		Expect(err).ToNot(HaveOccurred())
		Expect(pnLen).To(Equal(protocol.PacketNumberLen1))
		Expect(pn).To(Equal(protocol.PacketNumber(0x24)))
	})

	It("reads a 2-byte packet number", func() {
		pn, pnLen, err := ReadPacketNumber(bytes.NewReader([]byte{0x13, 0x37}), 0b11111101)
		Expect(err).ToNot(HaveOccurred())
		Expect(pnLen).To(Equal(protocol.PacketNumberLen2))
		Expect(pn).To(Equal(protocol.PacketNumber(0x1337)))
	})

	It("reads a 3-byte packet number", func() {
		pn, pnLen, err := ReadPacketNumber(bytes.NewReader([]byte{0x13, 0x33, 0x37}), 0b11111110)
		Expect(err).ToNot(HaveOccurred())
		Expect(pnLen).To(Equal(protocol.PacketNumberLen3))
		Expect(pn).To(Equal(protocol.PacketNumber(0x133337)))
	})

	It("reads a 4-byte packet number", func() {
		pn, pnLen, err := ReadPacketNumber(bytes.NewReader([]byte{0xde, 0xad, 0xbe, 0xef}), 0b11111111)
		Expect(err).ToNot(HaveOccurred())
		Expect(pnLen).To(Equal(protocol.PacketNumberLen4))
		Expect(pn).To(Equal(protocol.PacketNumber(0xdeadbeef)))
	})

	Context("Writing", func() {
		var buf *bytes.Buffer

		BeforeEach(func() {
			buf = &bytes.Buffer{}
		})

		Context("Long Header", func() {
			srcConnID := protocol.ConnectionID{1, 2, 3, 4, 5, 6, 7, 8}

			It("writes", func() {
				Expect((&ExtendedHeader{
					Header: Header{
						IsLongHeader:     true,
						Type:             protocol.PacketTypeHandshake,
						DestConnectionID: protocol.ConnectionID{0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe},
						SrcConnectionID:  protocol.ConnectionID{0xde, 0xca, 0xfb, 0xad, 0x0, 0x0, 0x13, 0x37},
						Version:          0x1020304,
						Length:           protocol.MaxPacketSizeIPv4,
					},
					PacketNumber:    0xdecaf,
					PacketNumberLen: protocol.PacketNumberLen3,
				}).Write(buf, versionIETFHeader)).To(Succeed())
				expected := []byte{
					0xc0 | 0x2<<4 | 0x2,
					0x1, 0x2, 0x3, 0x4, // version number
					0x6,                                // dest connection ID length
					0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, // dest connection ID
					0x8,                                          // src connection ID length
					0xde, 0xca, 0xfb, 0xad, 0x0, 0x0, 0x13, 0x37, // source connection ID
				}
				expected = append(expected, encodeVarInt(protocol.MaxPacketSizeIPv4)...) // length
				expected = append(expected, []byte{0xd, 0xec, 0xaf}...)                  // packet number
				Expect(buf.Bytes()).To(Equal(expected))
			})

			It("refuses to write a header with a too long connection ID", func() {
				err := (&ExtendedHeader{
					Header: Header{
						IsLongHeader:     true,
						SrcConnectionID:  srcConnID,
						DestConnectionID: protocol.ConnectionID{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21}, // connection IDs must be at most 20 bytes long
						Version:          0x1020304,
						Type:             0x5,
					},
					PacketNumber:    0xdecafbad,
					PacketNumberLen: protocol.PacketNumberLen4,
				}).Write(buf, versionIETFHeader)
				Expect(err).To(MatchError("invalid connection ID length: 21 bytes"))
			})

			It("writes a header with a 20 byte connection ID", func() {
				err := (&ExtendedHeader{
					Header: Header{
						IsLongHeader:     true,
						SrcConnectionID:  srcConnID,
						DestConnectionID: protocol.ConnectionID{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20}, // connection IDs must be at most 20 bytes long
						Version:          0x1020304,
						Type:             0x5,
					},
					PacketNumber:    0xdecafbad,
					PacketNumberLen: protocol.PacketNumberLen4,
				}).Write(buf, versionIETFHeader)
				Expect(err).ToNot(HaveOccurred())
				Expect(buf.Bytes()).To(ContainSubstring(string([]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20})))
			})

			It("writes an Initial containing a token", func() {
				token := []byte("Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.")
				Expect((&ExtendedHeader{
					Header: Header{
						IsLongHeader: true,
						Version:      0x1020304,
						Type:         protocol.PacketTypeInitial,
						Token:        token,
					},
					PacketNumber:    0xdecafbad,
					PacketNumberLen: protocol.PacketNumberLen4,
				}).Write(buf, versionIETFHeader)).To(Succeed())
				expectedSubstring := append(encodeVarInt(uint64(len(token))), token...)
				Expect(buf.Bytes()).To(ContainSubstring(string(expectedSubstring)))
			})

			It("uses a 2-byte encoding for the length on Initial packets", func() {
				Expect((&ExtendedHeader{
					Header: Header{
						IsLongHeader: true,
						Version:      0x1020304,
						Type:         protocol.PacketTypeInitial,
						Length:       37,
					},
					PacketNumber:    0xdecafbad,
					PacketNumberLen: protocol.PacketNumberLen4,
				}).Write(buf, versionIETFHeader)).To(Succeed())
				b := &bytes.Buffer{}
				utils.WriteVarIntWithLen(b, 37, 2)
				Expect(buf.Bytes()[buf.Len()-6 : buf.Len()-4]).To(Equal(b.Bytes()))
			})

			It("writes a Retry packet", func() {
				token := []byte("Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat.")
				Expect((&ExtendedHeader{Header: Header{
					IsLongHeader: true,
					Version:      0x1020304,
					Type:         protocol.PacketTypeRetry,
					Token:        token,
				}}).Write(buf, versionIETFHeader)).To(Succeed())
				expected := []byte{
					0xc0 | 0x3<<4,
					0x1, 0x2, 0x3, 0x4, // version number
					0x0, // dest connection ID length
					0x0, // src connection ID length
				}
				expected = append(expected, token...)
				Expect(buf.Bytes()).To(Equal(expected))
			})
		})

		Context("short header", func() {
			It("writes a header with connection ID", func() {
				Expect((&ExtendedHeader{
					Header: Header{
						DestConnectionID: protocol.ConnectionID{0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0x13, 0x37},
					},
					PacketNumberLen: protocol.PacketNumberLen1,
					PacketNumber:    0x42,
				}).Write(buf, versionIETFHeader)).To(Succeed())
				Expect(buf.Bytes()).To(Equal([]byte{
					0x40,
					0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0x13, 0x37, // connection ID
					0x42, // packet number
				}))
			})

			It("writes a header without connection ID", func() {
				Expect((&ExtendedHeader{
					PacketNumberLen: protocol.PacketNumberLen1,
					PacketNumber:    0x42,
				}).Write(buf, versionIETFHeader)).To(Succeed())
				Expect(buf.Bytes()).To(Equal([]byte{
					0x40,
					0x42, // packet number
				}))
			})

			It("writes a header with a 2 byte packet number", func() {
				Expect((&ExtendedHeader{
					PacketNumberLen: protocol.PacketNumberLen2,
					PacketNumber:    0x765,
				}).Write(buf, versionIETFHeader)).To(Succeed())
				expected := []byte{0x40 | 0x1}
				expected = append(expected, []byte{0x7, 0x65}...) // packet number
				Expect(buf.Bytes()).To(Equal(expected))
			})

			It("writes a header with a 4 byte packet number", func() {
				Expect((&ExtendedHeader{
					PacketNumberLen: protocol.PacketNumberLen4,
					PacketNumber:    0x12345678,
				}).Write(buf, versionIETFHeader)).To(Succeed())
				expected := []byte{0x40 | 0x3}
				expected = append(expected, []byte{0x12, 0x34, 0x56, 0x78}...)
				Expect(buf.Bytes()).To(Equal(expected))
			})

			It("errors when given an invalid packet number length", func() {
				err := (&ExtendedHeader{
					PacketNumberLen: 5,
					PacketNumber:    0xdecafbad,
				}).Write(buf, versionIETFHeader)
				Expect(err).To(MatchError("invalid packet number length: 5"))
			})

			It("writes the Key Phase Bit", func() {
				Expect((&ExtendedHeader{
					KeyPhase:        protocol.KeyPhaseOne,
					PacketNumberLen: protocol.PacketNumberLen1,
					PacketNumber:    0x42,
				}).Write(buf, versionIETFHeader)).To(Succeed())
				Expect(buf.Bytes()).To(Equal([]byte{
					0x40 | 0x4,
					0x42, // packet number
				}))
			})
		})
	})

	Context("getting the length", func() {
		var buf *bytes.Buffer

		BeforeEach(func() {
			buf = &bytes.Buffer{}
		})

		It("has the right length for the Long Header, for a short length", func() {
			h := &ExtendedHeader{
				Header: Header{
					IsLongHeader:     true,
					Type:             protocol.PacketTypeHandshake,
					DestConnectionID: protocol.ConnectionID{1, 2, 3, 4, 5, 6, 7, 8},
					SrcConnectionID:  protocol.ConnectionID{1, 2, 3, 4, 5, 6, 7, 8},
					Length:           1,
				},
				PacketNumberLen: protocol.PacketNumberLen1,
			}
			expectedLen := 1 /* type byte */ + 4 /* version */ + 1 /* dest conn ID len */ + 8 /* dest conn id */ + 1 /* src conn ID len */ + 8 /* src conn id */ + 2 /* length */ + 1 /* packet number */
			Expect(h.GetLength(versionIETFHeader)).To(BeEquivalentTo(expectedLen))
			Expect(h.Write(buf, versionIETFHeader)).To(Succeed())
			Expect(buf.Len()).To(Equal(expectedLen))
		})

		It("has the right length for the Long Header, for a long length", func() {
			h := &ExtendedHeader{
				Header: Header{
					IsLongHeader:     true,
					Type:             protocol.PacketTypeHandshake,
					DestConnectionID: protocol.ConnectionID{1, 2, 3, 4, 5, 6, 7, 8},
					SrcConnectionID:  protocol.ConnectionID{1, 2, 3, 4, 5, 6, 7, 8},
					Length:           1500,
				},
				PacketNumberLen: protocol.PacketNumberLen2,
			}
			expectedLen := 1 /* type byte */ + 4 /* version */ + 1 /* dest conn id len */ + 8 /* dest conn id */ + 1 /* src conn ID len */ + 8 /* src conn id */ + 2 /* long len */ + 2 /* packet number */
			Expect(h.GetLength(versionIETFHeader)).To(BeEquivalentTo(expectedLen))
			Expect(h.Write(buf, versionIETFHeader)).To(Succeed())
			Expect(buf.Len()).To(Equal(expectedLen))
		})

		It("has the right length for an Initial that has a short length", func() {
			h := &ExtendedHeader{
				Header: Header{
					IsLongHeader:     true,
					Type:             protocol.PacketTypeInitial,
					DestConnectionID: protocol.ConnectionID{1, 2, 3, 4, 5, 6, 7, 8},
					SrcConnectionID:  protocol.ConnectionID{1, 2, 3, 4},
					Length:           15,
				},
				PacketNumberLen: protocol.PacketNumberLen2,
			}
			expectedLen := 1 /* type byte */ + 4 /* version */ + 1 /* dest conn id len */ + 8 /* dest conn id */ + 1 /* src conn ID len */ + 4 /* src conn id */ + 1 /* token length */ + 2 /* length len */ + 2 /* packet number */
			Expect(h.GetLength(versionIETFHeader)).To(BeEquivalentTo(expectedLen))
			Expect(h.Write(buf, versionIETFHeader)).To(Succeed())
			Expect(buf.Len()).To(Equal(expectedLen))
		})

		It("has the right length for an Initial not containing a Token", func() {
			h := &ExtendedHeader{
				Header: Header{
					IsLongHeader:     true,
					Type:             protocol.PacketTypeInitial,
					DestConnectionID: protocol.ConnectionID{1, 2, 3, 4, 5, 6, 7, 8},
					SrcConnectionID:  protocol.ConnectionID{1, 2, 3, 4},
					Length:           1500,
				},
				PacketNumberLen: protocol.PacketNumberLen2,
			}
			expectedLen := 1 /* type byte */ + 4 /* version */ + 1 /* dest conn id len */ + 8 /* dest conn id */ + 1 /* src conn ID len */ + 4 /* src conn id */ + 1 /* token length */ + 2 /* length len */ + 2 /* packet number */
			Expect(h.GetLength(versionIETFHeader)).To(BeEquivalentTo(expectedLen))
			Expect(h.Write(buf, versionIETFHeader)).To(Succeed())
			Expect(buf.Len()).To(Equal(expectedLen))
		})

		It("has the right length for an Initial containing a Token", func() {
			h := &ExtendedHeader{
				Header: Header{
					IsLongHeader:     true,
					DestConnectionID: protocol.ConnectionID{1, 2, 3, 4, 5, 6, 7, 8},
					SrcConnectionID:  protocol.ConnectionID{1, 2, 3, 4},
					Type:             protocol.PacketTypeInitial,
					Length:           1500,
					Token:            []byte("foo"),
				},
				PacketNumberLen: protocol.PacketNumberLen2,
			}
			expectedLen := 1 /* type byte */ + 4 /* version */ + 1 /* dest conn id len */ + 8 /* dest conn id */ + 1 /* src conn id len */ + 4 /* src conn id */ + 1 /* token length */ + 3 /* token */ + 2 /* long len */ + 2 /* packet number */
			Expect(h.GetLength(versionIETFHeader)).To(BeEquivalentTo(expectedLen))
			Expect(h.Write(buf, versionIETFHeader)).To(Succeed())
			Expect(buf.Len()).To(Equal(expectedLen))
		})

		It("has the right length for a Short Header containing a connection ID", func() {
			h := &ExtendedHeader{
				Header: Header{
					DestConnectionID: protocol.ConnectionID{1, 2, 3, 4, 5, 6, 7, 8},
				},
				PacketNumberLen: protocol.PacketNumberLen1,
			}
			Expect(h.GetLength(versionIETFHeader)).To(Equal(protocol.ByteCount(1 + 8 + 1)))
			Expect(h.Write(buf, versionIETFHeader)).To(Succeed())
			Expect(buf.Len()).To(Equal(10))
		})

		It("has the right length for a short header without a connection ID", func() {
			h := &ExtendedHeader{PacketNumberLen: protocol.PacketNumberLen1}
			Expect(h.GetLength(versionIETFHeader)).To(Equal(protocol.ByteCount(1 + 1)))
			Expect(h.Write(buf, versionIETFHeader)).To(Succeed())
			Expect(buf.Len()).To(Equal(2))
		})

		It("has the right length for a short header with a 2 byte packet number", func() {
			h := &ExtendedHeader{PacketNumberLen: protocol.PacketNumberLen2}
			Expect(h.GetLength(versionIETFHeader)).To(Equal(protocol.ByteCount(1 + 2)))
			Expect(h.Write(buf, versionIETFHeader)).To(Succeed())
			Expect(buf.Len()).To(Equal(3))
		})

		It("has the right length for a short header with a 5 byte packet number", func() {
			h := &ExtendedHeader{PacketNumberLen: protocol.PacketNumberLen4}
			Expect(h.GetLength(versionIETFHeader)).To(Equal(protocol.ByteCount(1 + 4)))
			Expect(h.Write(buf, versionIETFHeader)).To(Succeed())
			Expect(buf.Len()).To(Equal(5))
		})
	})

	Context("Logging", func() {
		var (
			buf    *bytes.Buffer
			logger utils.Logger
		)

		BeforeEach(func() {
			buf = &bytes.Buffer{}
			logger = utils.DefaultLogger
			logger.SetLogLevel(utils.LogLevelDebug)
			log.SetOutput(buf)
		})

		AfterEach(func() {
			log.SetOutput(os.Stdout)
		})

		It("logs Long Headers", func() {
			(&ExtendedHeader{
				Header: Header{
					IsLongHeader:     true,
					DestConnectionID: protocol.ConnectionID{0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0x13, 0x37},
					SrcConnectionID:  protocol.ConnectionID{0xde, 0xca, 0xfb, 0xad, 0x013, 0x37, 0x13, 0x37},
					Type:             protocol.PacketTypeHandshake,
					Length:           54321,
					Version:          0xfeed,
				},
				PacketNumber:    1337,
				PacketNumberLen: protocol.PacketNumberLen2,
			}).Log(logger)
			Expect(buf.String()).To(ContainSubstring("Long Header{Type: Handshake, DestConnectionID: 0xdeadbeefcafe1337, SrcConnectionID: 0xdecafbad13371337, PacketNumber: 1337, PacketNumberLen: 2, Length: 54321, Version: 0xfeed}"))
		})

		It("logs Initial Packets with a Token", func() {
			(&ExtendedHeader{
				Header: Header{
					IsLongHeader:     true,
					DestConnectionID: protocol.ConnectionID{0xca, 0xfe, 0x13, 0x37},
					SrcConnectionID:  protocol.ConnectionID{0xde, 0xca, 0xfb, 0xad},
					Type:             protocol.PacketTypeInitial,
					Token:            []byte{0xde, 0xad, 0xbe, 0xef},
					Length:           100,
					Version:          0xfeed,
				},
				PacketNumber:    42,
				PacketNumberLen: protocol.PacketNumberLen2,
			}).Log(logger)
			Expect(buf.String()).To(ContainSubstring("Long Header{Type: Initial, DestConnectionID: 0xcafe1337, SrcConnectionID: 0xdecafbad, Token: 0xdeadbeef, PacketNumber: 42, PacketNumberLen: 2, Length: 100, Version: 0xfeed}"))
		})

		It("logs Initial packets without a Token", func() {
			(&ExtendedHeader{
				Header: Header{
					IsLongHeader:     true,
					DestConnectionID: protocol.ConnectionID{0xca, 0xfe, 0x13, 0x37},
					SrcConnectionID:  protocol.ConnectionID{0xde, 0xca, 0xfb, 0xad},
					Type:             protocol.PacketTypeInitial,
					Length:           100,
					Version:          0xfeed,
				},
				PacketNumber:    42,
				PacketNumberLen: protocol.PacketNumberLen2,
			}).Log(logger)
			Expect(buf.String()).To(ContainSubstring("Long Header{Type: Initial, DestConnectionID: 0xcafe1337, SrcConnectionID: 0xdecafbad, Token: (empty), PacketNumber: 42, PacketNumberLen: 2, Length: 100, Version: 0xfeed}"))
		})

		It("logs Retry packets with a Token", func() {
			(&ExtendedHeader{
				Header: Header{
					IsLongHeader:     true,
					DestConnectionID: protocol.ConnectionID{0xca, 0xfe, 0x13, 0x37},
					SrcConnectionID:  protocol.ConnectionID{0xde, 0xca, 0xfb, 0xad},
					Type:             protocol.PacketTypeRetry,
					Token:            []byte{0x12, 0x34, 0x56},
					Version:          0xfeed,
				},
			}).Log(logger)
			Expect(buf.String()).To(ContainSubstring("Long Header{Type: Retry, DestConnectionID: 0xcafe1337, SrcConnectionID: 0xdecafbad, Token: 0x123456, Version: 0xfeed}"))
		})

		It("logs Short Headers containing a connection ID", func() {
			(&ExtendedHeader{
				Header: Header{
					DestConnectionID: protocol.ConnectionID{0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0x13, 0x37},
				},
				KeyPhase:        protocol.KeyPhaseOne,
				PacketNumber:    1337,
				PacketNumberLen: 4,
			}).Log(logger)
			Expect(buf.String()).To(ContainSubstring("Short Header{DestConnectionID: 0xdeadbeefcafe1337, PacketNumber: 1337, PacketNumberLen: 4, KeyPhase: 1}"))
		})
	})
})
