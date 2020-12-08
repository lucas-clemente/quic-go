package quic

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"net"
	"reflect"
	"runtime/pprof"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/lucas-clemente/quic-go/internal/handshake"
	mocklogging "github.com/lucas-clemente/quic-go/internal/mocks/logging"
	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/qerr"
	"github.com/lucas-clemente/quic-go/internal/testdata"
	"github.com/lucas-clemente/quic-go/internal/utils"
	"github.com/lucas-clemente/quic-go/internal/wire"
	"github.com/lucas-clemente/quic-go/logging"

	"github.com/golang/mock/gomock"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

func areServersRunning() bool {
	var b bytes.Buffer
	pprof.Lookup("goroutine").WriteTo(&b, 1)
	return strings.Contains(b.String(), "quic-go.(*baseServer).run")
}

var _ = Describe("Server", func() {
	var (
		conn    *MockPacketConn
		tlsConf *tls.Config
	)

	getPacket := func(hdr *wire.Header, p []byte) *receivedPacket {
		buffer := getPacketBuffer()
		buf := bytes.NewBuffer(buffer.Data)
		if hdr.IsLongHeader {
			hdr.Length = 4 + protocol.ByteCount(len(p)) + 16
		}
		Expect((&wire.ExtendedHeader{
			Header:          *hdr,
			PacketNumber:    0x42,
			PacketNumberLen: protocol.PacketNumberLen4,
		}).Write(buf, protocol.VersionTLS)).To(Succeed())
		n := buf.Len()
		buf.Write(p)
		data := buffer.Data[:buf.Len()]
		sealer, _ := handshake.NewInitialAEAD(hdr.DestConnectionID, protocol.PerspectiveClient)
		_ = sealer.Seal(data[n:n], data[n:], 0x42, data[:n])
		data = data[:len(data)+16]
		sealer.EncryptHeader(data[n:n+16], &data[0], data[n-4:n])
		return &receivedPacket{
			remoteAddr: &net.UDPAddr{IP: net.IPv4(4, 5, 6, 7), Port: 456},
			data:       data,
			buffer:     buffer,
		}
	}

	getInitial := func(destConnID protocol.ConnectionID) *receivedPacket {
		senderAddr := &net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 42}
		hdr := &wire.Header{
			IsLongHeader:     true,
			Type:             protocol.PacketTypeInitial,
			SrcConnectionID:  protocol.ConnectionID{5, 4, 3, 2, 1},
			DestConnectionID: destConnID,
			Version:          protocol.VersionTLS,
		}
		p := getPacket(hdr, make([]byte, protocol.MinInitialPacketSize))
		p.buffer = getPacketBuffer()
		p.remoteAddr = senderAddr
		return p
	}

	getInitialWithRandomDestConnID := func() *receivedPacket {
		destConnID := make([]byte, 10)
		_, err := rand.Read(destConnID)
		Expect(err).ToNot(HaveOccurred())

		return getInitial(destConnID)
	}

	parseLongHeaderHeader := func(data []byte) *wire.Header {
		hdr, _, _, err := wire.ParseLongHeaderPacket(data)
		Expect(err).ToNot(HaveOccurred())
		return hdr
	}

	BeforeEach(func() {
		conn = NewMockPacketConn(mockCtrl)
		conn.EXPECT().LocalAddr().Return(&net.UDPAddr{}).AnyTimes()
		conn.EXPECT().ReadFrom(gomock.Any()).Do(func(_ []byte) { <-(make(chan struct{})) }).MaxTimes(1)
		tlsConf = testdata.GetTLSConfig()
		tlsConf.NextProtos = []string{"proto1"}
	})

	AfterEach(func() {
		Eventually(areServersRunning).Should(BeFalse())
	})

	It("errors when no tls.Config is given", func() {
		_, err := ListenAddr("localhost:0", nil, nil)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("quic: tls.Config not set"))
	})

	It("errors when the Config contains an invalid version", func() {
		version := protocol.VersionNumber(0x1234)
		_, err := Listen(nil, tlsConf, &Config{Versions: []protocol.VersionNumber{version}})
		Expect(err).To(MatchError("0x1234 is not a valid QUIC version"))
	})

	It("fills in default values if options are not set in the Config", func() {
		ln, err := Listen(conn, tlsConf, &Config{})
		Expect(err).ToNot(HaveOccurred())
		server := ln.(*baseServer)
		Expect(server.config.Versions).To(Equal(protocol.SupportedVersions))
		Expect(server.config.HandshakeTimeout).To(Equal(protocol.DefaultHandshakeTimeout))
		Expect(server.config.MaxIdleTimeout).To(Equal(protocol.DefaultIdleTimeout))
		Expect(reflect.ValueOf(server.config.AcceptToken)).To(Equal(reflect.ValueOf(defaultAcceptToken)))
		Expect(server.config.KeepAlive).To(BeFalse())
		// stop the listener
		Expect(ln.Close()).To(Succeed())
	})

	It("setups with the right values", func() {
		supportedVersions := []protocol.VersionNumber{protocol.VersionTLS}
		acceptToken := func(_ net.Addr, _ *Token) bool { return true }
		config := Config{
			Versions:          supportedVersions,
			AcceptToken:       acceptToken,
			HandshakeTimeout:  1337 * time.Hour,
			MaxIdleTimeout:    42 * time.Minute,
			KeepAlive:         true,
			StatelessResetKey: []byte("foobar"),
		}
		ln, err := Listen(conn, tlsConf, &config)
		Expect(err).ToNot(HaveOccurred())
		server := ln.(*baseServer)
		Expect(server.sessionHandler).ToNot(BeNil())
		Expect(server.config.Versions).To(Equal(supportedVersions))
		Expect(server.config.HandshakeTimeout).To(Equal(1337 * time.Hour))
		Expect(server.config.MaxIdleTimeout).To(Equal(42 * time.Minute))
		Expect(reflect.ValueOf(server.config.AcceptToken)).To(Equal(reflect.ValueOf(acceptToken)))
		Expect(server.config.KeepAlive).To(BeTrue())
		Expect(server.config.StatelessResetKey).To(Equal([]byte("foobar")))
		// stop the listener
		Expect(ln.Close()).To(Succeed())
	})

	It("listens on a given address", func() {
		addr := "127.0.0.1:13579"
		ln, err := ListenAddr(addr, tlsConf, &Config{})
		Expect(err).ToNot(HaveOccurred())
		Expect(ln.Addr().String()).To(Equal(addr))
		// stop the listener
		Expect(ln.Close()).To(Succeed())
	})

	It("errors if given an invalid address", func() {
		addr := "127.0.0.1"
		_, err := ListenAddr(addr, tlsConf, &Config{})
		Expect(err).To(BeAssignableToTypeOf(&net.AddrError{}))
	})

	It("errors if given an invalid address", func() {
		addr := "1.1.1.1:1111"
		_, err := ListenAddr(addr, tlsConf, &Config{})
		Expect(err).To(BeAssignableToTypeOf(&net.OpError{}))
	})

	Context("server accepting sessions that completed the handshake", func() {
		var (
			serv   *baseServer
			phm    *MockPacketHandlerManager
			tracer *mocklogging.MockTracer
		)

		BeforeEach(func() {
			tracer = mocklogging.NewMockTracer(mockCtrl)
			ln, err := Listen(conn, tlsConf, &Config{Tracer: tracer})
			Expect(err).ToNot(HaveOccurred())
			serv = ln.(*baseServer)
			phm = NewMockPacketHandlerManager(mockCtrl)
			serv.sessionHandler = phm
		})

		AfterEach(func() {
			phm.EXPECT().CloseServer().MaxTimes(1)
			serv.Close()
		})

		Context("handling packets", func() {
			It("drops Initial packets with a too short connection ID", func() {
				p := getPacket(&wire.Header{
					IsLongHeader:     true,
					Type:             protocol.PacketTypeInitial,
					DestConnectionID: protocol.ConnectionID{1, 2, 3, 4},
					Version:          serv.config.Versions[0],
				}, nil)
				tracer.EXPECT().DroppedPacket(p.remoteAddr, logging.PacketTypeInitial, p.Size(), logging.PacketDropUnexpectedPacket)
				serv.handlePacket(p)
				// make sure there are no Write calls on the packet conn
				time.Sleep(50 * time.Millisecond)
			})

			It("drops too small Initial", func() {
				p := getPacket(&wire.Header{
					IsLongHeader:     true,
					Type:             protocol.PacketTypeInitial,
					DestConnectionID: protocol.ConnectionID{1, 2, 3, 4, 5, 6, 7, 8},
					Version:          serv.config.Versions[0],
				}, make([]byte, protocol.MinInitialPacketSize-100),
				)
				tracer.EXPECT().DroppedPacket(p.remoteAddr, logging.PacketTypeInitial, p.Size(), logging.PacketDropUnexpectedPacket)
				serv.handlePacket(p)
				// make sure there are no Write calls on the packet conn
				time.Sleep(50 * time.Millisecond)
			})

			It("drops non-Initial packets", func() {
				p := getPacket(&wire.Header{
					IsLongHeader: true,
					Type:         protocol.PacketTypeHandshake,
					Version:      serv.config.Versions[0],
				}, []byte("invalid"))
				tracer.EXPECT().DroppedPacket(p.remoteAddr, logging.PacketTypeHandshake, p.Size(), logging.PacketDropUnexpectedPacket)
				serv.handlePacket(p)
				// make sure there are no Write calls on the packet conn
				time.Sleep(50 * time.Millisecond)
			})

			It("decodes the token from the Token field", func() {
				raddr := &net.UDPAddr{
					IP:   net.IPv4(192, 168, 13, 37),
					Port: 1337,
				}
				done := make(chan struct{})
				serv.config.AcceptToken = func(addr net.Addr, token *Token) bool {
					Expect(addr).To(Equal(raddr))
					Expect(token).ToNot(BeNil())
					close(done)
					return false
				}
				token, err := serv.tokenGenerator.NewRetryToken(raddr, nil, nil)
				Expect(err).ToNot(HaveOccurred())
				packet := getPacket(&wire.Header{
					IsLongHeader: true,
					Type:         protocol.PacketTypeInitial,
					Token:        token,
					Version:      serv.config.Versions[0],
				}, make([]byte, protocol.MinInitialPacketSize))
				packet.remoteAddr = raddr
				conn.EXPECT().WriteTo(gomock.Any(), gomock.Any()).MaxTimes(1)
				tracer.EXPECT().SentPacket(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).MaxTimes(1)
				serv.handlePacket(packet)
				Eventually(done).Should(BeClosed())
			})

			It("passes an empty token to the callback, if decoding fails", func() {
				raddr := &net.UDPAddr{
					IP:   net.IPv4(192, 168, 13, 37),
					Port: 1337,
				}
				done := make(chan struct{})
				serv.config.AcceptToken = func(addr net.Addr, token *Token) bool {
					Expect(addr).To(Equal(raddr))
					Expect(token).To(BeNil())
					close(done)
					return false
				}
				packet := getPacket(&wire.Header{
					IsLongHeader: true,
					Type:         protocol.PacketTypeInitial,
					Token:        []byte("foobar"),
					Version:      serv.config.Versions[0],
				}, make([]byte, protocol.MinInitialPacketSize))
				packet.remoteAddr = raddr
				conn.EXPECT().WriteTo(gomock.Any(), gomock.Any()).MaxTimes(1)
				tracer.EXPECT().SentPacket(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).MaxTimes(1)
				serv.handlePacket(packet)
				Eventually(done).Should(BeClosed())
			})

			It("creates a session when the token is accepted", func() {
				serv.config.AcceptToken = func(_ net.Addr, token *Token) bool { return true }
				retryToken, err := serv.tokenGenerator.NewRetryToken(
					&net.UDPAddr{},
					protocol.ConnectionID{0xde, 0xad, 0xc0, 0xde},
					protocol.ConnectionID{0xde, 0xca, 0xfb, 0xad},
				)
				Expect(err).ToNot(HaveOccurred())
				hdr := &wire.Header{
					IsLongHeader:     true,
					Type:             protocol.PacketTypeInitial,
					SrcConnectionID:  protocol.ConnectionID{5, 4, 3, 2, 1},
					DestConnectionID: protocol.ConnectionID{1, 2, 3, 4, 5, 6, 7, 8, 9, 10},
					Version:          protocol.VersionTLS,
					Token:            retryToken,
				}
				p := getPacket(hdr, make([]byte, protocol.MinInitialPacketSize))
				run := make(chan struct{})
				var token protocol.StatelessResetToken
				rand.Read(token[:])

				var newConnID protocol.ConnectionID
				phm.EXPECT().AddWithConnID(protocol.ConnectionID{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}, gomock.Any(), gomock.Any()).DoAndReturn(func(_, c protocol.ConnectionID, fn func() packetHandler) bool {
					newConnID = c
					phm.EXPECT().GetStatelessResetToken(gomock.Any()).DoAndReturn(func(c protocol.ConnectionID) protocol.StatelessResetToken {
						newConnID = c
						return token
					})
					fn()
					return true
				})
				tracer.EXPECT().TracerForConnection(protocol.PerspectiveServer, protocol.ConnectionID{0xde, 0xad, 0xc0, 0xde})
				sess := NewMockQuicSession(mockCtrl)
				serv.newSession = func(
					_ sendConn,
					_ sessionRunner,
					origDestConnID protocol.ConnectionID,
					retrySrcConnID *protocol.ConnectionID,
					clientDestConnID protocol.ConnectionID,
					destConnID protocol.ConnectionID,
					srcConnID protocol.ConnectionID,
					tokenP protocol.StatelessResetToken,
					_ *Config,
					_ *tls.Config,
					_ *handshake.TokenGenerator,
					enable0RTT bool,
					_ logging.ConnectionTracer,
					_ utils.Logger,
					_ protocol.VersionNumber,
				) quicSession {
					Expect(enable0RTT).To(BeFalse())
					Expect(origDestConnID).To(Equal(protocol.ConnectionID{0xde, 0xad, 0xc0, 0xde}))
					Expect(retrySrcConnID).To(Equal(&protocol.ConnectionID{0xde, 0xca, 0xfb, 0xad}))
					Expect(clientDestConnID).To(Equal(hdr.DestConnectionID))
					Expect(destConnID).To(Equal(hdr.SrcConnectionID))
					// make sure we're using a server-generated connection ID
					Expect(srcConnID).ToNot(Equal(hdr.DestConnectionID))
					Expect(srcConnID).ToNot(Equal(hdr.SrcConnectionID))
					Expect(srcConnID).To(Equal(newConnID))
					Expect(tokenP).To(Equal(token))
					sess.EXPECT().handlePacket(p)
					sess.EXPECT().run().Do(func() { close(run) })
					sess.EXPECT().Context().Return(context.Background())
					sess.EXPECT().HandshakeComplete().Return(context.Background())
					return sess
				}

				done := make(chan struct{})
				go func() {
					defer GinkgoRecover()
					serv.handlePacket(p)
					// the Handshake packet is written by the session.
					// Make sure there are no Write calls on the packet conn.
					time.Sleep(50 * time.Millisecond)
					close(done)
				}()
				// make sure we're using a server-generated connection ID
				Eventually(run).Should(BeClosed())
				Eventually(done).Should(BeClosed())
			})

			It("sends a Version Negotiation Packet for unsupported versions", func() {
				srcConnID := protocol.ConnectionID{1, 2, 3, 4, 5}
				destConnID := protocol.ConnectionID{1, 2, 3, 4, 5, 6}
				packet := getPacket(&wire.Header{
					IsLongHeader:     true,
					Type:             protocol.PacketTypeHandshake,
					SrcConnectionID:  srcConnID,
					DestConnectionID: destConnID,
					Version:          0x42,
				}, make([]byte, protocol.MinUnknownVersionPacketSize))
				raddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1337}
				packet.remoteAddr = raddr
				tracer.EXPECT().SentPacket(packet.remoteAddr, gomock.Any(), gomock.Any(), nil).Do(func(_ net.Addr, replyHdr *logging.Header, _ logging.ByteCount, _ []logging.Frame) {
					Expect(replyHdr.IsLongHeader).To(BeTrue())
					Expect(replyHdr.Version).To(BeZero())
					Expect(replyHdr.SrcConnectionID).To(Equal(destConnID))
					Expect(replyHdr.DestConnectionID).To(Equal(srcConnID))
				})
				done := make(chan struct{})
				conn.EXPECT().WriteTo(gomock.Any(), raddr).DoAndReturn(func(b []byte, _ net.Addr) (int, error) {
					defer close(done)
					Expect(wire.IsVersionNegotiationPacket(b)).To(BeTrue())
					hdr, versions, err := wire.ParseVersionNegotiationPacket(bytes.NewReader(b))
					Expect(err).ToNot(HaveOccurred())
					Expect(hdr.DestConnectionID).To(Equal(srcConnID))
					Expect(hdr.SrcConnectionID).To(Equal(destConnID))
					Expect(versions).ToNot(ContainElement(protocol.VersionNumber(0x42)))
					return len(b), nil
				})
				serv.handlePacket(packet)
				Eventually(done).Should(BeClosed())
			})

			It("ignores Version Negotiation packets", func() {
				data, err := wire.ComposeVersionNegotiation(
					protocol.ConnectionID{1, 2, 3, 4},
					protocol.ConnectionID{4, 3, 2, 1},
					[]protocol.VersionNumber{1, 2, 3},
				)
				Expect(err).ToNot(HaveOccurred())
				raddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1337}
				done := make(chan struct{})
				tracer.EXPECT().DroppedPacket(raddr, logging.PacketTypeVersionNegotiation, protocol.ByteCount(len(data)), logging.PacketDropUnexpectedPacket).Do(func(net.Addr, logging.PacketType, protocol.ByteCount, logging.PacketDropReason) {
					close(done)
				})
				serv.handlePacket(&receivedPacket{
					remoteAddr: raddr,
					data:       data,
					buffer:     getPacketBuffer(),
				})
				Eventually(done).Should(BeClosed())
				// make sure no other packet is sent
				time.Sleep(scaleDuration(20 * time.Millisecond))
			})

			It("doesn't send a Version Negotiation Packet for unsupported versions, if the packet is too small", func() {
				srcConnID := protocol.ConnectionID{1, 2, 3, 4, 5}
				destConnID := protocol.ConnectionID{1, 2, 3, 4, 5, 6}
				p := getPacket(&wire.Header{
					IsLongHeader:     true,
					Type:             protocol.PacketTypeHandshake,
					SrcConnectionID:  srcConnID,
					DestConnectionID: destConnID,
					Version:          0x42,
				}, make([]byte, protocol.MinUnknownVersionPacketSize-50))
				Expect(p.Size()).To(BeNumerically("<", protocol.MinUnknownVersionPacketSize))
				raddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1337}
				p.remoteAddr = raddr
				done := make(chan struct{})
				tracer.EXPECT().DroppedPacket(raddr, logging.PacketTypeNotDetermined, p.Size(), logging.PacketDropUnexpectedPacket).Do(func(net.Addr, logging.PacketType, protocol.ByteCount, logging.PacketDropReason) {
					close(done)
				})
				serv.handlePacket(p)
				Eventually(done).Should(BeClosed())
				// make sure no other packet is sent
				time.Sleep(scaleDuration(20 * time.Millisecond))
			})

			It("replies with a Retry packet, if a Token is required", func() {
				serv.config.AcceptToken = func(_ net.Addr, _ *Token) bool { return false }
				hdr := &wire.Header{
					IsLongHeader:     true,
					Type:             protocol.PacketTypeInitial,
					SrcConnectionID:  protocol.ConnectionID{5, 4, 3, 2, 1},
					DestConnectionID: protocol.ConnectionID{1, 2, 3, 4, 5, 6, 7, 8, 9, 10},
					Version:          protocol.VersionTLS,
				}
				packet := getPacket(hdr, make([]byte, protocol.MinInitialPacketSize))
				raddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1337}
				packet.remoteAddr = raddr
				tracer.EXPECT().SentPacket(packet.remoteAddr, gomock.Any(), gomock.Any(), nil).Do(func(_ net.Addr, replyHdr *logging.Header, _ logging.ByteCount, _ []logging.Frame) {
					Expect(replyHdr.Type).To(Equal(protocol.PacketTypeRetry))
					Expect(replyHdr.SrcConnectionID).ToNot(Equal(hdr.DestConnectionID))
					Expect(replyHdr.DestConnectionID).To(Equal(hdr.SrcConnectionID))
					Expect(replyHdr.Token).ToNot(BeEmpty())
				})
				done := make(chan struct{})
				conn.EXPECT().WriteTo(gomock.Any(), raddr).DoAndReturn(func(b []byte, _ net.Addr) (int, error) {
					defer close(done)
					replyHdr := parseLongHeaderHeader(b)
					Expect(replyHdr.Type).To(Equal(protocol.PacketTypeRetry))
					Expect(replyHdr.SrcConnectionID).ToNot(Equal(hdr.DestConnectionID))
					Expect(replyHdr.DestConnectionID).To(Equal(hdr.SrcConnectionID))
					Expect(replyHdr.Token).ToNot(BeEmpty())
					Expect(b[len(b)-16:]).To(Equal(handshake.GetRetryIntegrityTag(b[:len(b)-16], hdr.DestConnectionID)[:]))
					return len(b), nil
				})
				serv.handlePacket(packet)
				Eventually(done).Should(BeClosed())
			})

			It("sends an INVALID_TOKEN error, if an invalid retry token is received", func() {
				serv.config.AcceptToken = func(_ net.Addr, _ *Token) bool { return false }
				token, err := serv.tokenGenerator.NewRetryToken(&net.UDPAddr{}, nil, nil)
				Expect(err).ToNot(HaveOccurred())
				hdr := &wire.Header{
					IsLongHeader:     true,
					Type:             protocol.PacketTypeInitial,
					SrcConnectionID:  protocol.ConnectionID{5, 4, 3, 2, 1},
					DestConnectionID: protocol.ConnectionID{1, 2, 3, 4, 5, 6, 7, 8, 9, 10},
					Token:            token,
					Version:          protocol.VersionTLS,
				}
				packet := getPacket(hdr, make([]byte, protocol.MinInitialPacketSize))
				packet.data = append(packet.data, []byte("coalesced packet")...) // add some garbage to simulate a coalesced packet
				raddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1337}
				packet.remoteAddr = raddr
				tracer.EXPECT().SentPacket(packet.remoteAddr, gomock.Any(), gomock.Any(), gomock.Any()).Do(func(_ net.Addr, replyHdr *logging.Header, _ logging.ByteCount, frames []logging.Frame) {
					Expect(replyHdr.Type).To(Equal(protocol.PacketTypeInitial))
					Expect(replyHdr.SrcConnectionID).To(Equal(hdr.DestConnectionID))
					Expect(replyHdr.DestConnectionID).To(Equal(hdr.SrcConnectionID))
					Expect(frames).To(HaveLen(1))
					Expect(frames[0]).To(BeAssignableToTypeOf(&wire.ConnectionCloseFrame{}))
					ccf := frames[0].(*logging.ConnectionCloseFrame)
					Expect(ccf.IsApplicationError).To(BeFalse())
					Expect(ccf.ErrorCode).To(Equal(qerr.InvalidToken))
				})
				done := make(chan struct{})
				conn.EXPECT().WriteTo(gomock.Any(), raddr).DoAndReturn(func(b []byte, _ net.Addr) (int, error) {
					defer close(done)
					replyHdr := parseLongHeaderHeader(b)
					Expect(replyHdr.Type).To(Equal(protocol.PacketTypeInitial))
					Expect(replyHdr.SrcConnectionID).To(Equal(hdr.DestConnectionID))
					Expect(replyHdr.DestConnectionID).To(Equal(hdr.SrcConnectionID))
					_, opener := handshake.NewInitialAEAD(hdr.DestConnectionID, protocol.PerspectiveClient)
					extHdr, err := unpackLongHeader(opener, replyHdr, b, hdr.Version)
					Expect(err).ToNot(HaveOccurred())
					data, err := opener.Open(nil, b[extHdr.ParsedLen():], extHdr.PacketNumber, b[:extHdr.ParsedLen()])
					Expect(err).ToNot(HaveOccurred())
					f, err := wire.NewFrameParser(hdr.Version).ParseNext(bytes.NewReader(data), protocol.EncryptionInitial)
					Expect(err).ToNot(HaveOccurred())
					Expect(f).To(BeAssignableToTypeOf(&wire.ConnectionCloseFrame{}))
					ccf := f.(*wire.ConnectionCloseFrame)
					Expect(ccf.ErrorCode).To(Equal(qerr.InvalidToken))
					Expect(ccf.ReasonPhrase).To(BeEmpty())
					return len(b), nil
				})
				serv.handlePacket(packet)
				Eventually(done).Should(BeClosed())
			})

			It("doesn't send an INVALID_TOKEN error, if the packet is corrupted", func() {
				serv.config.AcceptToken = func(_ net.Addr, _ *Token) bool { return false }
				token, err := serv.tokenGenerator.NewRetryToken(&net.UDPAddr{}, nil, nil)
				Expect(err).ToNot(HaveOccurred())
				hdr := &wire.Header{
					IsLongHeader:     true,
					Type:             protocol.PacketTypeInitial,
					SrcConnectionID:  protocol.ConnectionID{5, 4, 3, 2, 1},
					DestConnectionID: protocol.ConnectionID{1, 2, 3, 4, 5, 6, 7, 8, 9, 10},
					Token:            token,
					Version:          protocol.VersionTLS,
				}
				packet := getPacket(hdr, make([]byte, protocol.MinInitialPacketSize))
				packet.data[len(packet.data)-10] ^= 0xff // corrupt the packet
				packet.remoteAddr = &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1337}
				tracer.EXPECT().DroppedPacket(packet.remoteAddr, logging.PacketTypeInitial, packet.Size(), logging.PacketDropPayloadDecryptError)
				serv.handlePacket(packet)
				// make sure there are no Write calls on the packet conn
				time.Sleep(50 * time.Millisecond)
			})

			It("creates a session, if no Token is required", func() {
				serv.config.AcceptToken = func(_ net.Addr, _ *Token) bool { return true }
				hdr := &wire.Header{
					IsLongHeader:     true,
					Type:             protocol.PacketTypeInitial,
					SrcConnectionID:  protocol.ConnectionID{5, 4, 3, 2, 1},
					DestConnectionID: protocol.ConnectionID{1, 2, 3, 4, 5, 6, 7, 8, 9, 10},
					Version:          protocol.VersionTLS,
				}
				p := getPacket(hdr, make([]byte, protocol.MinInitialPacketSize))
				run := make(chan struct{})
				var token protocol.StatelessResetToken
				rand.Read(token[:])

				var newConnID protocol.ConnectionID
				phm.EXPECT().AddWithConnID(protocol.ConnectionID{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}, gomock.Any(), gomock.Any()).DoAndReturn(func(_, c protocol.ConnectionID, fn func() packetHandler) bool {
					newConnID = c
					phm.EXPECT().GetStatelessResetToken(gomock.Any()).DoAndReturn(func(c protocol.ConnectionID) protocol.StatelessResetToken {
						newConnID = c
						return token
					})
					fn()
					return true
				})
				tracer.EXPECT().TracerForConnection(protocol.PerspectiveServer, protocol.ConnectionID{1, 2, 3, 4, 5, 6, 7, 8, 9, 10})

				sess := NewMockQuicSession(mockCtrl)
				serv.newSession = func(
					_ sendConn,
					_ sessionRunner,
					origDestConnID protocol.ConnectionID,
					retrySrcConnID *protocol.ConnectionID,
					clientDestConnID protocol.ConnectionID,
					destConnID protocol.ConnectionID,
					srcConnID protocol.ConnectionID,
					tokenP protocol.StatelessResetToken,
					_ *Config,
					_ *tls.Config,
					_ *handshake.TokenGenerator,
					enable0RTT bool,
					_ logging.ConnectionTracer,
					_ utils.Logger,
					_ protocol.VersionNumber,
				) quicSession {
					Expect(enable0RTT).To(BeFalse())
					Expect(origDestConnID).To(Equal(hdr.DestConnectionID))
					Expect(retrySrcConnID).To(BeNil())
					Expect(clientDestConnID).To(Equal(hdr.DestConnectionID))
					Expect(destConnID).To(Equal(hdr.SrcConnectionID))
					// make sure we're using a server-generated connection ID
					Expect(srcConnID).ToNot(Equal(hdr.DestConnectionID))
					Expect(srcConnID).ToNot(Equal(hdr.SrcConnectionID))
					Expect(srcConnID).To(Equal(newConnID))
					Expect(tokenP).To(Equal(token))
					sess.EXPECT().handlePacket(p)
					sess.EXPECT().run().Do(func() { close(run) })
					sess.EXPECT().Context().Return(context.Background())
					sess.EXPECT().HandshakeComplete().Return(context.Background())
					return sess
				}

				done := make(chan struct{})
				go func() {
					defer GinkgoRecover()
					serv.handlePacket(p)
					// the Handshake packet is written by the session
					// make sure there are no Write calls on the packet conn
					time.Sleep(50 * time.Millisecond)
					close(done)
				}()
				// make sure we're using a server-generated connection ID
				Eventually(run).Should(BeClosed())
				Eventually(done).Should(BeClosed())
			})

			It("passes queued 0-RTT packets to the session", func() {
				serv.config.AcceptToken = func(_ net.Addr, _ *Token) bool { return true }
				var createdSession bool
				sess := NewMockQuicSession(mockCtrl)
				connID := protocol.ConnectionID{1, 2, 3, 4, 5, 6, 7, 8, 9}
				initialPacket := getInitial(connID)
				zeroRTTPacket := getPacket(&wire.Header{
					IsLongHeader:     true,
					Type:             protocol.PacketType0RTT,
					SrcConnectionID:  protocol.ConnectionID{5, 4, 3, 2, 1},
					DestConnectionID: connID,
					Version:          protocol.VersionTLS,
				}, []byte("foobar"))
				sess.EXPECT().Context().Return(context.Background()).MaxTimes(1)
				sess.EXPECT().HandshakeComplete().Return(context.Background()).MaxTimes(1)
				sess.EXPECT().run().MaxTimes(1)
				gomock.InOrder(
					sess.EXPECT().handlePacket(initialPacket),
					sess.EXPECT().handlePacket(zeroRTTPacket),
				)
				serv.newSession = func(
					_ sendConn,
					runner sessionRunner,
					_ protocol.ConnectionID,
					_ *protocol.ConnectionID,
					_ protocol.ConnectionID,
					_ protocol.ConnectionID,
					_ protocol.ConnectionID,
					_ protocol.StatelessResetToken,
					_ *Config,
					_ *tls.Config,
					_ *handshake.TokenGenerator,
					_ bool,
					_ logging.ConnectionTracer,
					_ utils.Logger,
					_ protocol.VersionNumber,
				) quicSession {
					createdSession = true
					return sess
				}

				// Receive the 0-RTT packet first.
				Expect(serv.handlePacketImpl(zeroRTTPacket)).To(BeTrue())
				// Then receive the Initial packet.
				phm.EXPECT().GetStatelessResetToken(gomock.Any())
				phm.EXPECT().AddWithConnID(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(func(_, _ protocol.ConnectionID, fn func() packetHandler) bool {
					fn()
					return true
				})
				tracer.EXPECT().TracerForConnection(protocol.PerspectiveServer, gomock.Any())
				Expect(serv.handlePacketImpl(initialPacket)).To(BeTrue())
				Expect(createdSession).To(BeTrue())
			})

			It("drops packets if the receive queue is full", func() {
				phm.EXPECT().AddWithConnID(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(func(_, _ protocol.ConnectionID, fn func() packetHandler) bool {
					phm.EXPECT().GetStatelessResetToken(gomock.Any())
					fn()
					return true
				}).AnyTimes()
				tracer.EXPECT().TracerForConnection(protocol.PerspectiveServer, gomock.Any()).AnyTimes()

				serv.config.AcceptToken = func(net.Addr, *Token) bool { return true }
				acceptSession := make(chan struct{})
				var counter uint32 // to be used as an atomic, so we query it in Eventually
				serv.newSession = func(
					_ sendConn,
					runner sessionRunner,
					_ protocol.ConnectionID,
					_ *protocol.ConnectionID,
					_ protocol.ConnectionID,
					_ protocol.ConnectionID,
					_ protocol.ConnectionID,
					_ protocol.StatelessResetToken,
					_ *Config,
					_ *tls.Config,
					_ *handshake.TokenGenerator,
					_ bool,
					_ logging.ConnectionTracer,
					_ utils.Logger,
					_ protocol.VersionNumber,
				) quicSession {
					<-acceptSession
					atomic.AddUint32(&counter, 1)
					sess := NewMockQuicSession(mockCtrl)
					sess.EXPECT().handlePacket(gomock.Any()).MaxTimes(1)
					sess.EXPECT().run().MaxTimes(1)
					sess.EXPECT().Context().Return(context.Background()).MaxTimes(1)
					sess.EXPECT().HandshakeComplete().Return(context.Background()).MaxTimes(1)
					return sess
				}

				p := getInitial(protocol.ConnectionID{1, 2, 3, 4, 5, 6, 7, 8})
				serv.handlePacket(p)
				tracer.EXPECT().DroppedPacket(p.remoteAddr, logging.PacketTypeNotDetermined, p.Size(), logging.PacketDropDOSPrevention).MinTimes(1)
				var wg sync.WaitGroup
				for i := 0; i < 3*protocol.MaxServerUnprocessedPackets; i++ {
					wg.Add(1)
					go func() {
						defer GinkgoRecover()
						defer wg.Done()
						serv.handlePacket(getInitial(protocol.ConnectionID{1, 2, 3, 4, 5, 6, 7, 8}))
					}()
				}
				wg.Wait()

				close(acceptSession)
				Eventually(
					func() uint32 { return atomic.LoadUint32(&counter) },
					scaleDuration(100*time.Millisecond),
				).Should(BeEquivalentTo(protocol.MaxServerUnprocessedPackets + 1))
				Consistently(func() uint32 { return atomic.LoadUint32(&counter) }).Should(BeEquivalentTo(protocol.MaxServerUnprocessedPackets + 1))
			})

			It("only creates a single session for a duplicate Initial", func() {
				serv.config.AcceptToken = func(_ net.Addr, _ *Token) bool { return true }
				var createdSession bool
				sess := NewMockQuicSession(mockCtrl)
				serv.newSession = func(
					_ sendConn,
					runner sessionRunner,
					_ protocol.ConnectionID,
					_ *protocol.ConnectionID,
					_ protocol.ConnectionID,
					_ protocol.ConnectionID,
					_ protocol.ConnectionID,
					_ protocol.StatelessResetToken,
					_ *Config,
					_ *tls.Config,
					_ *handshake.TokenGenerator,
					_ bool,
					_ logging.ConnectionTracer,
					_ utils.Logger,
					_ protocol.VersionNumber,
				) quicSession {
					createdSession = true
					return sess
				}

				p := getInitial(protocol.ConnectionID{1, 2, 3, 4, 5, 6, 7, 8, 9})
				phm.EXPECT().AddWithConnID(protocol.ConnectionID{1, 2, 3, 4, 5, 6, 7, 8, 9}, gomock.Any(), gomock.Any()).Return(false)
				Expect(serv.handlePacketImpl(p)).To(BeTrue())
				Expect(createdSession).To(BeFalse())
			})

			It("rejects new connection attempts if the accept queue is full", func() {
				serv.config.AcceptToken = func(_ net.Addr, _ *Token) bool { return true }

				serv.newSession = func(
					_ sendConn,
					runner sessionRunner,
					_ protocol.ConnectionID,
					_ *protocol.ConnectionID,
					_ protocol.ConnectionID,
					_ protocol.ConnectionID,
					_ protocol.ConnectionID,
					_ protocol.StatelessResetToken,
					_ *Config,
					_ *tls.Config,
					_ *handshake.TokenGenerator,
					_ bool,
					_ logging.ConnectionTracer,
					_ utils.Logger,
					_ protocol.VersionNumber,
				) quicSession {
					sess := NewMockQuicSession(mockCtrl)
					sess.EXPECT().handlePacket(gomock.Any())
					sess.EXPECT().run()
					sess.EXPECT().Context().Return(context.Background())
					ctx, cancel := context.WithCancel(context.Background())
					cancel()
					sess.EXPECT().HandshakeComplete().Return(ctx)
					return sess
				}

				phm.EXPECT().AddWithConnID(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(func(_, _ protocol.ConnectionID, fn func() packetHandler) bool {
					phm.EXPECT().GetStatelessResetToken(gomock.Any())
					fn()
					return true
				}).Times(protocol.MaxAcceptQueueSize)
				tracer.EXPECT().TracerForConnection(protocol.PerspectiveServer, gomock.Any()).Times(protocol.MaxAcceptQueueSize)

				var wg sync.WaitGroup
				wg.Add(protocol.MaxAcceptQueueSize)
				for i := 0; i < protocol.MaxAcceptQueueSize; i++ {
					go func() {
						defer GinkgoRecover()
						defer wg.Done()
						serv.handlePacket(getInitialWithRandomDestConnID())
						// make sure there are no Write calls on the packet conn
						time.Sleep(50 * time.Millisecond)
					}()
				}
				wg.Wait()
				p := getInitialWithRandomDestConnID()
				hdr, _, _, err := wire.ParseLongHeaderPacket(p.data)
				Expect(err).ToNot(HaveOccurred())
				tracer.EXPECT().SentPacket(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any())
				done := make(chan struct{})
				conn.EXPECT().WriteTo(gomock.Any(), p.remoteAddr).DoAndReturn(func(b []byte, _ net.Addr) (int, error) {
					defer close(done)
					rejectHdr := parseLongHeaderHeader(b)
					Expect(rejectHdr.Type).To(Equal(protocol.PacketTypeInitial))
					Expect(rejectHdr.Version).To(Equal(hdr.Version))
					Expect(rejectHdr.DestConnectionID).To(Equal(hdr.SrcConnectionID))
					Expect(rejectHdr.SrcConnectionID).To(Equal(hdr.DestConnectionID))
					return len(b), nil
				})
				serv.handlePacket(p)
				Eventually(done).Should(BeClosed())
			})

			It("doesn't accept new sessions if they were closed in the mean time", func() {
				serv.config.AcceptToken = func(_ net.Addr, _ *Token) bool { return true }

				p := getInitial(protocol.ConnectionID{1, 2, 3, 4, 5, 6, 7, 8, 9, 10})
				ctx, cancel := context.WithCancel(context.Background())
				sessionCreated := make(chan struct{})
				sess := NewMockQuicSession(mockCtrl)
				serv.newSession = func(
					_ sendConn,
					runner sessionRunner,
					_ protocol.ConnectionID,
					_ *protocol.ConnectionID,
					_ protocol.ConnectionID,
					_ protocol.ConnectionID,
					_ protocol.ConnectionID,
					_ protocol.StatelessResetToken,
					_ *Config,
					_ *tls.Config,
					_ *handshake.TokenGenerator,
					_ bool,
					_ logging.ConnectionTracer,
					_ utils.Logger,
					_ protocol.VersionNumber,
				) quicSession {
					sess.EXPECT().handlePacket(p)
					sess.EXPECT().run()
					sess.EXPECT().Context().Return(ctx)
					ctx, cancel := context.WithCancel(context.Background())
					cancel()
					sess.EXPECT().HandshakeComplete().Return(ctx)
					close(sessionCreated)
					return sess
				}

				phm.EXPECT().AddWithConnID(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(func(_, _ protocol.ConnectionID, fn func() packetHandler) bool {
					phm.EXPECT().GetStatelessResetToken(gomock.Any())
					fn()
					return true
				})
				tracer.EXPECT().TracerForConnection(protocol.PerspectiveServer, gomock.Any())

				serv.handlePacket(p)
				// make sure there are no Write calls on the packet conn
				time.Sleep(50 * time.Millisecond)
				Eventually(sessionCreated).Should(BeClosed())
				cancel()
				time.Sleep(scaleDuration(200 * time.Millisecond))

				done := make(chan struct{})
				go func() {
					defer GinkgoRecover()
					serv.Accept(context.Background())
					close(done)
				}()
				Consistently(done).ShouldNot(BeClosed())

				// make the go routine return
				phm.EXPECT().CloseServer()
				sess.EXPECT().getPerspective().MaxTimes(2) // once for every conn ID
				Expect(serv.Close()).To(Succeed())
				Eventually(done).Should(BeClosed())
			})
		})

		Context("accepting sessions", func() {
			It("returns Accept when an error occurs", func() {
				testErr := errors.New("test err")

				done := make(chan struct{})
				go func() {
					defer GinkgoRecover()
					_, err := serv.Accept(context.Background())
					Expect(err).To(MatchError(testErr))
					close(done)
				}()

				serv.setCloseError(testErr)
				Eventually(done).Should(BeClosed())
			})

			It("returns immediately, if an error occurred before", func() {
				testErr := errors.New("test err")
				serv.setCloseError(testErr)
				for i := 0; i < 3; i++ {
					_, err := serv.Accept(context.Background())
					Expect(err).To(MatchError(testErr))
				}
			})

			It("returns when the context is canceled", func() {
				ctx, cancel := context.WithCancel(context.Background())
				done := make(chan struct{})
				go func() {
					defer GinkgoRecover()
					_, err := serv.Accept(ctx)
					Expect(err).To(MatchError("context canceled"))
					close(done)
				}()

				Consistently(done).ShouldNot(BeClosed())
				cancel()
				Eventually(done).Should(BeClosed())
			})

			It("accepts new sessions when the handshake completes", func() {
				sess := NewMockQuicSession(mockCtrl)

				done := make(chan struct{})
				go func() {
					defer GinkgoRecover()
					s, err := serv.Accept(context.Background())
					Expect(err).ToNot(HaveOccurred())
					Expect(s).To(Equal(sess))
					close(done)
				}()

				ctx, cancel := context.WithCancel(context.Background()) // handshake context
				serv.newSession = func(
					_ sendConn,
					runner sessionRunner,
					_ protocol.ConnectionID,
					_ *protocol.ConnectionID,
					_ protocol.ConnectionID,
					_ protocol.ConnectionID,
					_ protocol.ConnectionID,
					_ protocol.StatelessResetToken,
					_ *Config,
					_ *tls.Config,
					_ *handshake.TokenGenerator,
					_ bool,
					_ logging.ConnectionTracer,
					_ utils.Logger,
					_ protocol.VersionNumber,
				) quicSession {
					sess.EXPECT().HandshakeComplete().Return(ctx)
					sess.EXPECT().run().Do(func() {})
					sess.EXPECT().Context().Return(context.Background())
					return sess
				}
				phm.EXPECT().AddWithConnID(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(func(_, _ protocol.ConnectionID, fn func() packetHandler) bool {
					phm.EXPECT().GetStatelessResetToken(gomock.Any())
					fn()
					return true
				})
				tracer.EXPECT().TracerForConnection(protocol.PerspectiveServer, gomock.Any())
				serv.createNewSession(&net.UDPAddr{}, nil, nil, nil, nil, nil, protocol.VersionWhatever)
				Consistently(done).ShouldNot(BeClosed())
				cancel() // complete the handshake
				Eventually(done).Should(BeClosed())
			})
		})
	})

	Context("server accepting sessions that haven't completed the handshake", func() {
		var (
			serv *earlyServer
			phm  *MockPacketHandlerManager
		)

		BeforeEach(func() {
			ln, err := ListenEarly(conn, tlsConf, nil)
			Expect(err).ToNot(HaveOccurred())
			serv = ln.(*earlyServer)
			phm = NewMockPacketHandlerManager(mockCtrl)
			serv.sessionHandler = phm
		})

		AfterEach(func() {
			phm.EXPECT().CloseServer().MaxTimes(1)
			serv.Close()
		})

		It("accepts new sessions when they become ready", func() {
			sess := NewMockQuicSession(mockCtrl)

			done := make(chan struct{})
			go func() {
				defer GinkgoRecover()
				s, err := serv.Accept(context.Background())
				Expect(err).ToNot(HaveOccurred())
				Expect(s).To(Equal(sess))
				close(done)
			}()

			ready := make(chan struct{})
			serv.newSession = func(
				_ sendConn,
				runner sessionRunner,
				_ protocol.ConnectionID,
				_ *protocol.ConnectionID,
				_ protocol.ConnectionID,
				_ protocol.ConnectionID,
				_ protocol.ConnectionID,
				_ protocol.StatelessResetToken,
				_ *Config,
				_ *tls.Config,
				_ *handshake.TokenGenerator,
				enable0RTT bool,
				_ logging.ConnectionTracer,
				_ utils.Logger,
				_ protocol.VersionNumber,
			) quicSession {
				Expect(enable0RTT).To(BeTrue())
				sess.EXPECT().run().Do(func() {})
				sess.EXPECT().earlySessionReady().Return(ready)
				sess.EXPECT().Context().Return(context.Background())
				return sess
			}
			phm.EXPECT().AddWithConnID(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(func(_, _ protocol.ConnectionID, fn func() packetHandler) bool {
				phm.EXPECT().GetStatelessResetToken(gomock.Any())
				fn()
				return true
			})
			serv.createNewSession(&net.UDPAddr{}, nil, nil, nil, nil, nil, protocol.VersionWhatever)
			Consistently(done).ShouldNot(BeClosed())
			close(ready)
			Eventually(done).Should(BeClosed())
		})

		It("rejects new connection attempts if the accept queue is full", func() {
			serv.config.AcceptToken = func(_ net.Addr, _ *Token) bool { return true }
			senderAddr := &net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 42}

			serv.newSession = func(
				_ sendConn,
				runner sessionRunner,
				_ protocol.ConnectionID,
				_ *protocol.ConnectionID,
				_ protocol.ConnectionID,
				_ protocol.ConnectionID,
				_ protocol.ConnectionID,
				_ protocol.StatelessResetToken,
				_ *Config,
				_ *tls.Config,
				_ *handshake.TokenGenerator,
				_ bool,
				_ logging.ConnectionTracer,
				_ utils.Logger,
				_ protocol.VersionNumber,
			) quicSession {
				ready := make(chan struct{})
				close(ready)
				sess := NewMockQuicSession(mockCtrl)
				sess.EXPECT().handlePacket(gomock.Any())
				sess.EXPECT().run()
				sess.EXPECT().earlySessionReady().Return(ready)
				sess.EXPECT().Context().Return(context.Background())
				return sess
			}

			phm.EXPECT().AddWithConnID(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(func(_, _ protocol.ConnectionID, fn func() packetHandler) bool {
				phm.EXPECT().GetStatelessResetToken(gomock.Any())
				fn()
				return true
			}).Times(protocol.MaxAcceptQueueSize)
			for i := 0; i < protocol.MaxAcceptQueueSize; i++ {
				serv.handlePacket(getInitialWithRandomDestConnID())
			}

			Eventually(func() int32 { return atomic.LoadInt32(&serv.sessionQueueLen) }).Should(BeEquivalentTo(protocol.MaxAcceptQueueSize))
			// make sure there are no Write calls on the packet conn
			time.Sleep(50 * time.Millisecond)

			p := getInitialWithRandomDestConnID()
			hdr := parseLongHeaderHeader(p.data)
			done := make(chan struct{})
			conn.EXPECT().WriteTo(gomock.Any(), senderAddr).DoAndReturn(func(b []byte, _ net.Addr) (int, error) {
				defer close(done)
				rejectHdr := parseLongHeaderHeader(b)
				Expect(rejectHdr.Type).To(Equal(protocol.PacketTypeInitial))
				Expect(rejectHdr.Version).To(Equal(hdr.Version))
				Expect(rejectHdr.DestConnectionID).To(Equal(hdr.SrcConnectionID))
				Expect(rejectHdr.SrcConnectionID).To(Equal(hdr.DestConnectionID))
				return len(b), nil
			})
			serv.handlePacket(p)
			Eventually(done).Should(BeClosed())
		})

		It("doesn't accept new sessions if they were closed in the mean time", func() {
			serv.config.AcceptToken = func(_ net.Addr, _ *Token) bool { return true }

			p := getInitial(protocol.ConnectionID{1, 2, 3, 4, 5, 6, 7, 8, 9, 10})
			ctx, cancel := context.WithCancel(context.Background())
			sessionCreated := make(chan struct{})
			sess := NewMockQuicSession(mockCtrl)
			serv.newSession = func(
				_ sendConn,
				runner sessionRunner,
				_ protocol.ConnectionID,
				_ *protocol.ConnectionID,
				_ protocol.ConnectionID,
				_ protocol.ConnectionID,
				_ protocol.ConnectionID,
				_ protocol.StatelessResetToken,
				_ *Config,
				_ *tls.Config,
				_ *handshake.TokenGenerator,
				_ bool,
				_ logging.ConnectionTracer,
				_ utils.Logger,
				_ protocol.VersionNumber,
			) quicSession {
				sess.EXPECT().handlePacket(p)
				sess.EXPECT().run()
				sess.EXPECT().earlySessionReady()
				sess.EXPECT().Context().Return(ctx)
				close(sessionCreated)
				return sess
			}

			phm.EXPECT().AddWithConnID(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(func(_, _ protocol.ConnectionID, fn func() packetHandler) bool {
				phm.EXPECT().GetStatelessResetToken(gomock.Any())
				fn()
				return true
			})
			serv.handlePacket(p)
			// make sure there are no Write calls on the packet conn
			time.Sleep(50 * time.Millisecond)
			Eventually(sessionCreated).Should(BeClosed())
			cancel()
			time.Sleep(scaleDuration(200 * time.Millisecond))

			done := make(chan struct{})
			go func() {
				defer GinkgoRecover()
				serv.Accept(context.Background())
				close(done)
			}()
			Consistently(done).ShouldNot(BeClosed())

			// make the go routine return
			phm.EXPECT().CloseServer()
			sess.EXPECT().getPerspective().MaxTimes(2) // once for every conn ID
			Expect(serv.Close()).To(Succeed())
			Eventually(done).Should(BeClosed())
		})
	})
})

var _ = Describe("default source address verification", func() {
	It("accepts a token", func() {
		remoteAddr := &net.UDPAddr{IP: net.IPv4(192, 168, 0, 1)}
		token := &Token{
			IsRetryToken: true,
			RemoteAddr:   "192.168.0.1",
			SentTime:     time.Now().Add(-protocol.RetryTokenValidity).Add(time.Second), // will expire in 1 second
		}
		Expect(defaultAcceptToken(remoteAddr, token)).To(BeTrue())
	})

	It("requests verification if no token is provided", func() {
		remoteAddr := &net.UDPAddr{IP: net.IPv4(192, 168, 0, 1)}
		Expect(defaultAcceptToken(remoteAddr, nil)).To(BeFalse())
	})

	It("rejects a token if the address doesn't match", func() {
		remoteAddr := &net.UDPAddr{IP: net.IPv4(192, 168, 0, 1)}
		token := &Token{
			IsRetryToken: true,
			RemoteAddr:   "127.0.0.1",
			SentTime:     time.Now(),
		}
		Expect(defaultAcceptToken(remoteAddr, token)).To(BeFalse())
	})

	It("accepts a token for a remote address is not a UDP address", func() {
		remoteAddr := &net.TCPAddr{IP: net.IPv4(192, 168, 0, 1), Port: 1337}
		token := &Token{
			IsRetryToken: true,
			RemoteAddr:   "192.168.0.1:1337",
			SentTime:     time.Now(),
		}
		Expect(defaultAcceptToken(remoteAddr, token)).To(BeTrue())
	})

	It("rejects an invalid token for a remote address is not a UDP address", func() {
		remoteAddr := &net.TCPAddr{IP: net.IPv4(192, 168, 0, 1), Port: 1337}
		token := &Token{
			IsRetryToken: true,
			RemoteAddr:   "192.168.0.1:7331", // mismatching port
			SentTime:     time.Now(),
		}
		Expect(defaultAcceptToken(remoteAddr, token)).To(BeFalse())
	})

	It("rejects an expired token", func() {
		remoteAddr := &net.UDPAddr{IP: net.IPv4(192, 168, 0, 1)}
		token := &Token{
			IsRetryToken: true,
			RemoteAddr:   "192.168.0.1",
			SentTime:     time.Now().Add(-protocol.RetryTokenValidity).Add(-time.Second), // expired 1 second ago
		}
		Expect(defaultAcceptToken(remoteAddr, token)).To(BeFalse())
	})

	It("accepts a non-retry token", func() {
		Expect(protocol.RetryTokenValidity).To(BeNumerically("<", protocol.TokenValidity))
		remoteAddr := &net.UDPAddr{IP: net.IPv4(192, 168, 0, 1)}
		token := &Token{
			IsRetryToken: false,
			RemoteAddr:   "192.168.0.1",
			// if this was a retry token, it would have expired one second ago
			SentTime: time.Now().Add(-protocol.RetryTokenValidity).Add(-time.Second),
		}
		Expect(defaultAcceptToken(remoteAddr, token)).To(BeTrue())
	})
})
