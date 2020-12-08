package self_test

import (
	"bytes"
	"context"
	"fmt"
	"io/ioutil"
	"math"
	mrand "math/rand"
	"net"
	"sync/atomic"
	"time"

	quic "github.com/lucas-clemente/quic-go"
	quicproxy "github.com/lucas-clemente/quic-go/integrationtests/tools/proxy"
	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/qerr"
	"github.com/lucas-clemente/quic-go/internal/testutils"
	"github.com/lucas-clemente/quic-go/internal/wire"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("MITM test", func() {
	for _, v := range protocol.SupportedVersions {
		version := v

		Context(fmt.Sprintf("with QUIC version %s", version), func() {
			const connIDLen = 6 // explicitly set the connection ID length, so the proxy can parse it

			var (
				proxy                  *quicproxy.QuicProxy
				serverConn, clientConn *net.UDPConn
				serverSess             quic.Session
				serverConfig           *quic.Config
			)

			startServerAndProxy := func(delayCb quicproxy.DelayCallback, dropCb quicproxy.DropCallback) {
				addr, err := net.ResolveUDPAddr("udp", "localhost:0")
				Expect(err).ToNot(HaveOccurred())
				serverConn, err = net.ListenUDP("udp", addr)
				Expect(err).ToNot(HaveOccurred())
				ln, err := quic.Listen(serverConn, getTLSConfig(), serverConfig)
				Expect(err).ToNot(HaveOccurred())
				go func() {
					defer GinkgoRecover()
					var err error
					serverSess, err = ln.Accept(context.Background())
					Expect(err).ToNot(HaveOccurred())
					str, err := serverSess.OpenUniStream()
					Expect(err).ToNot(HaveOccurred())
					_, err = str.Write(PRData)
					Expect(err).ToNot(HaveOccurred())
					Expect(str.Close()).To(Succeed())
				}()
				serverPort := ln.Addr().(*net.UDPAddr).Port
				proxy, err = quicproxy.NewQuicProxy("localhost:0", &quicproxy.Opts{
					RemoteAddr:  fmt.Sprintf("localhost:%d", serverPort),
					DelayPacket: delayCb,
					DropPacket:  dropCb,
				})
				Expect(err).ToNot(HaveOccurred())
			}

			BeforeEach(func() {
				serverConfig = getQuicConfig(&quic.Config{
					Versions:           []protocol.VersionNumber{version},
					ConnectionIDLength: connIDLen,
				})
				addr, err := net.ResolveUDPAddr("udp", "localhost:0")
				Expect(err).ToNot(HaveOccurred())
				clientConn, err = net.ListenUDP("udp", addr)
				Expect(err).ToNot(HaveOccurred())
			})

			Context("unsuccessful attacks", func() {
				AfterEach(func() {
					Eventually(serverSess.Context().Done()).Should(BeClosed())
					// Test shutdown is tricky due to the proxy. Just wait for a bit.
					time.Sleep(50 * time.Millisecond)
					Expect(clientConn.Close()).To(Succeed())
					Expect(serverConn.Close()).To(Succeed())
					Expect(proxy.Close()).To(Succeed())
				})

				Context("injecting invalid packets", func() {
					const rtt = 20 * time.Millisecond

					sendRandomPacketsOfSameType := func(conn net.PacketConn, remoteAddr net.Addr, raw []byte) {
						defer GinkgoRecover()
						var replyHdr *wire.ExtendedHeader
						if wire.IsLongHeader(raw[0]) {
							hdr, _, _, err := wire.ParseLongHeaderPacket(raw)
							Expect(err).ToNot(HaveOccurred())
							replyHdr = &wire.ExtendedHeader{
								Header: wire.Header{
									IsLongHeader:     hdr.IsLongHeader,
									DestConnectionID: hdr.DestConnectionID,
									SrcConnectionID:  hdr.SrcConnectionID,
									Type:             hdr.Type,
									Version:          hdr.Version,
								},
								PacketNumber:    protocol.PacketNumber(mrand.Int31n(math.MaxInt32 / 4)),
								PacketNumberLen: protocol.PacketNumberLen(mrand.Int31n(4) + 1),
							}
						} else {
							destConnID, err := wire.ParseConnectionID(raw, connIDLen)
							Expect(err).ToNot(HaveOccurred())
							replyHdr = &wire.ExtendedHeader{
								Header: wire.Header{DestConnectionID: destConnID},
							}
						}

						const numPackets = 10
						ticker := time.NewTicker(rtt / numPackets)
						for i := 0; i < numPackets; i++ {
							payloadLen := mrand.Int31n(100)
							replyHdr.PacketNumber = protocol.PacketNumber(mrand.Int31())
							replyHdr.PacketNumberLen = protocol.PacketNumberLen(mrand.Int31n(4) + 1)
							replyHdr.Length = protocol.ByteCount(mrand.Int31n(payloadLen + 1))
							buf := &bytes.Buffer{}
							Expect(replyHdr.Write(buf, version)).To(Succeed())
							b := make([]byte, payloadLen)
							mrand.Read(b)
							buf.Write(b)
							if _, err := conn.WriteTo(buf.Bytes(), remoteAddr); err != nil {
								return
							}
							<-ticker.C
						}
					}

					runTest := func(delayCb quicproxy.DelayCallback) {
						startServerAndProxy(delayCb, nil)
						raddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("localhost:%d", proxy.LocalPort()))
						Expect(err).ToNot(HaveOccurred())
						sess, err := quic.Dial(
							clientConn,
							raddr,
							fmt.Sprintf("localhost:%d", proxy.LocalPort()),
							getTLSClientConfig(),
							getQuicConfig(&quic.Config{
								Versions:           []protocol.VersionNumber{version},
								ConnectionIDLength: connIDLen,
							}),
						)
						Expect(err).ToNot(HaveOccurred())
						str, err := sess.AcceptUniStream(context.Background())
						Expect(err).ToNot(HaveOccurred())
						data, err := ioutil.ReadAll(str)
						Expect(err).ToNot(HaveOccurred())
						Expect(data).To(Equal(PRData))
						Expect(sess.CloseWithError(0, "")).To(Succeed())
					}

					It("downloads a message when the packets are injected towards the server", func() {
						delayCb := func(dir quicproxy.Direction, raw []byte) time.Duration {
							if dir == quicproxy.DirectionIncoming {
								defer GinkgoRecover()
								go sendRandomPacketsOfSameType(clientConn, serverConn.LocalAddr(), raw)
							}
							return rtt / 2
						}
						runTest(delayCb)
					})

					It("downloads a message when the packets are injected towards the client", func() {
						delayCb := func(dir quicproxy.Direction, raw []byte) time.Duration {
							if dir == quicproxy.DirectionOutgoing {
								defer GinkgoRecover()
								go sendRandomPacketsOfSameType(serverConn, clientConn.LocalAddr(), raw)
							}
							return rtt / 2
						}
						runTest(delayCb)
					})
				})

				runTest := func(dropCb quicproxy.DropCallback) {
					startServerAndProxy(nil, dropCb)
					raddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("localhost:%d", proxy.LocalPort()))
					Expect(err).ToNot(HaveOccurred())
					sess, err := quic.Dial(
						clientConn,
						raddr,
						fmt.Sprintf("localhost:%d", proxy.LocalPort()),
						getTLSClientConfig(),
						getQuicConfig(&quic.Config{
							Versions:           []protocol.VersionNumber{version},
							ConnectionIDLength: connIDLen,
						}),
					)
					Expect(err).ToNot(HaveOccurred())
					str, err := sess.AcceptUniStream(context.Background())
					Expect(err).ToNot(HaveOccurred())
					data, err := ioutil.ReadAll(str)
					Expect(err).ToNot(HaveOccurred())
					Expect(data).To(Equal(PRData))
					Expect(sess.CloseWithError(0, "")).To(Succeed())
				}

				Context("duplicating packets", func() {
					It("downloads a message when packets are duplicated towards the server", func() {
						dropCb := func(dir quicproxy.Direction, raw []byte) bool {
							defer GinkgoRecover()
							if dir == quicproxy.DirectionIncoming {
								_, err := clientConn.WriteTo(raw, serverConn.LocalAddr())
								Expect(err).ToNot(HaveOccurred())
							}
							return false
						}
						runTest(dropCb)
					})

					It("downloads a message when packets are duplicated towards the client", func() {
						dropCb := func(dir quicproxy.Direction, raw []byte) bool {
							defer GinkgoRecover()
							if dir == quicproxy.DirectionOutgoing {
								_, err := serverConn.WriteTo(raw, clientConn.LocalAddr())
								Expect(err).ToNot(HaveOccurred())
							}
							return false
						}
						runTest(dropCb)
					})
				})

				Context("corrupting packets", func() {
					const interval = 10 // corrupt every 10th packet (stochastically)
					const idleTimeout = time.Second

					var numCorrupted int32

					BeforeEach(func() {
						numCorrupted = 0
						serverConfig.MaxIdleTimeout = idleTimeout
					})

					AfterEach(func() {
						num := atomic.LoadInt32(&numCorrupted)
						fmt.Fprintf(GinkgoWriter, "Corrupted %d packets.", num)
						Expect(num).To(BeNumerically(">=", 1))
						// If the packet containing the CONNECTION_CLOSE is corrupted,
						// we have to wait for the session to time out.
						Eventually(serverSess.Context().Done(), 3*idleTimeout).Should(BeClosed())
					})

					It("downloads a message when packet are corrupted towards the server", func() {
						dropCb := func(dir quicproxy.Direction, raw []byte) bool {
							defer GinkgoRecover()
							if dir == quicproxy.DirectionIncoming && mrand.Intn(interval) == 0 {
								pos := mrand.Intn(len(raw))
								raw[pos] = byte(mrand.Intn(256))
								_, err := clientConn.WriteTo(raw, serverConn.LocalAddr())
								Expect(err).ToNot(HaveOccurred())
								atomic.AddInt32(&numCorrupted, 1)
								return true
							}
							return false
						}
						runTest(dropCb)
					})

					It("downloads a message when packet are corrupted towards the client", func() {
						dropCb := func(dir quicproxy.Direction, raw []byte) bool {
							defer GinkgoRecover()
							if dir == quicproxy.DirectionOutgoing && mrand.Intn(interval) == 0 {
								pos := mrand.Intn(len(raw))
								raw[pos] = byte(mrand.Intn(256))
								_, err := serverConn.WriteTo(raw, clientConn.LocalAddr())
								Expect(err).ToNot(HaveOccurred())
								atomic.AddInt32(&numCorrupted, 1)
								return true
							}
							return false
						}
						runTest(dropCb)
					})
				})
			})

			Context("successful injection attacks", func() {
				// These tests demonstrate that the QUIC protocol is vulnerable to injection attacks before the handshake
				// finishes. In particular, an adversary who can intercept packets coming from one endpoint and send a reply
				// that arrives before the real reply can tear down the connection in multiple ways.

				const rtt = 20 * time.Millisecond

				// AfterEach closes the proxy, but each function is responsible
				// for closing client and server connections
				AfterEach(func() {
					// Test shutdown is tricky due to the proxy. Just wait for a bit.
					time.Sleep(50 * time.Millisecond)
					Expect(proxy.Close()).To(Succeed())
				})

				// sendForgedVersionNegotiationPacket sends a fake VN packet with no supported versions
				// from serverConn to client's remoteAddr
				// expects hdr from an Initial packet intercepted from client
				sendForgedVersionNegotationPacket := func(conn net.PacketConn, remoteAddr net.Addr, hdr *wire.Header) {
					// Create fake version negotiation packet with no supported versions
					versions := []protocol.VersionNumber{}
					packet, _ := wire.ComposeVersionNegotiation(hdr.SrcConnectionID, hdr.DestConnectionID, versions)

					// Send the packet
					_, err := conn.WriteTo(packet, remoteAddr)
					Expect(err).ToNot(HaveOccurred())
				}

				// sendForgedRetryPacket sends a fake Retry packet with a modified srcConnID
				// from serverConn to client's remoteAddr
				// expects hdr from an Initial packet intercepted from client
				sendForgedRetryPacket := func(conn net.PacketConn, remoteAddr net.Addr, hdr *wire.Header) {
					var x byte = 0x12
					fakeSrcConnID := protocol.ConnectionID{x, x, x, x, x, x, x, x}
					retryPacket := testutils.ComposeRetryPacket(fakeSrcConnID, hdr.SrcConnectionID, hdr.DestConnectionID, []byte("token"), hdr.Version)

					_, err := conn.WriteTo(retryPacket, remoteAddr)
					Expect(err).ToNot(HaveOccurred())
				}

				// Send a forged Initial packet with no frames to client
				// expects hdr from an Initial packet intercepted from client
				sendForgedInitialPacket := func(conn net.PacketConn, remoteAddr net.Addr, hdr *wire.Header) {
					initialPacket := testutils.ComposeInitialPacket(hdr.DestConnectionID, hdr.SrcConnectionID, hdr.Version, hdr.DestConnectionID, nil)
					_, err := conn.WriteTo(initialPacket, remoteAddr)
					Expect(err).ToNot(HaveOccurred())
				}

				// Send a forged Initial packet with ACK for random packet to client
				// expects hdr from an Initial packet intercepted from client
				sendForgedInitialPacketWithAck := func(conn net.PacketConn, remoteAddr net.Addr, hdr *wire.Header) {
					// Fake Initial with ACK for packet 2 (unsent)
					ackFrame := testutils.ComposeAckFrame(2, 2)
					initialPacket := testutils.ComposeInitialPacket(hdr.DestConnectionID, hdr.SrcConnectionID, hdr.Version, hdr.DestConnectionID, []wire.Frame{ackFrame})
					_, err := conn.WriteTo(initialPacket, remoteAddr)
					Expect(err).ToNot(HaveOccurred())
				}

				runTest := func(delayCb quicproxy.DelayCallback) error {
					startServerAndProxy(delayCb, nil)
					raddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("localhost:%d", proxy.LocalPort()))
					Expect(err).ToNot(HaveOccurred())
					_, err = quic.Dial(
						clientConn,
						raddr,
						fmt.Sprintf("localhost:%d", proxy.LocalPort()),
						getTLSClientConfig(),
						getQuicConfig(&quic.Config{
							Versions:           []protocol.VersionNumber{version},
							ConnectionIDLength: connIDLen,
							HandshakeTimeout:   2 * time.Second,
						}),
					)
					return err
				}

				// fails immediately because client connection closes when it can't find compatible version
				It("fails when a forged version negotiation packet is sent to client", func() {
					delayCb := func(dir quicproxy.Direction, raw []byte) time.Duration {
						if dir == quicproxy.DirectionIncoming {
							defer GinkgoRecover()

							if !wire.IsLongHeader(raw[0]) {
								return 0
							}
							hdr, _, _, err := wire.ParseLongHeaderPacket(raw)
							Expect(err).ToNot(HaveOccurred())
							if hdr.Type != protocol.PacketTypeInitial {
								return 0
							}

							sendForgedVersionNegotationPacket(serverConn, clientConn.LocalAddr(), hdr)
						}
						return rtt / 2
					}
					err := runTest(delayCb)
					Expect(err).To(HaveOccurred())
					Expect(err.Error()).To(ContainSubstring("No compatible QUIC version found."))
				})

				// times out, because client doesn't accept subsequent real retry packets from server
				// as it has already accepted a retry.
				// TODO: determine behavior when server does not send Retry packets
				It("fails when a forged Retry packet with modified srcConnID is sent to client", func() {
					var initialPacketIntercepted bool
					delayCb := func(dir quicproxy.Direction, raw []byte) time.Duration {
						if dir == quicproxy.DirectionIncoming && !initialPacketIntercepted {
							defer GinkgoRecover()

							if !wire.IsLongHeader(raw[0]) {
								return 0
							}
							hdr, _, _, err := wire.ParseLongHeaderPacket(raw)
							Expect(err).ToNot(HaveOccurred())
							if hdr.Type != protocol.PacketTypeInitial {
								return 0
							}

							initialPacketIntercepted = true
							sendForgedRetryPacket(serverConn, clientConn.LocalAddr(), hdr)
						}
						return rtt / 2
					}
					err := runTest(delayCb)
					Expect(err).To(HaveOccurred())
					Expect(err.(net.Error).Timeout()).To(BeTrue())
				})

				// times out, because client doesn't accept real retry packets from server because
				// it has already accepted an initial.
				// TODO: determine behavior when server does not send Retry packets
				It("fails when a forged initial packet is sent to client", func() {
					delayCb := func(dir quicproxy.Direction, raw []byte) time.Duration {
						if dir == quicproxy.DirectionIncoming {
							defer GinkgoRecover()

							if !wire.IsLongHeader(raw[0]) {
								return 0
							}
							hdr, _, _, err := wire.ParseLongHeaderPacket(raw)
							Expect(err).ToNot(HaveOccurred())
							if hdr.Type != protocol.PacketTypeInitial {
								return 0
							}

							sendForgedInitialPacket(serverConn, clientConn.LocalAddr(), hdr)
						}
						return rtt
					}
					err := runTest(delayCb)
					Expect(err).To(HaveOccurred())
					Expect(err.(net.Error).Timeout()).To(BeTrue())
				})

				// client connection closes immediately on receiving ack for unsent packet
				It("fails when a forged initial packet with ack for unsent packet is sent to client", func() {
					clientAddr := clientConn.LocalAddr()
					delayCb := func(dir quicproxy.Direction, raw []byte) time.Duration {
						if dir == quicproxy.DirectionIncoming {
							if !wire.IsLongHeader(raw[0]) {
								return 0
							}
							hdr, _, _, err := wire.ParseLongHeaderPacket(raw)
							Expect(err).ToNot(HaveOccurred())
							if hdr.Type != protocol.PacketTypeInitial {
								return 0
							}
							sendForgedInitialPacketWithAck(serverConn, clientAddr, hdr)
						}
						return rtt
					}
					err := runTest(delayCb)
					Expect(err).To(HaveOccurred())
					Expect(err).To(BeAssignableToTypeOf(&qerr.QuicError{}))
					Expect(err.(*qerr.QuicError).ErrorCode).To(Equal(qerr.ProtocolViolation))
					Expect(err.Error()).To(ContainSubstring("Received ACK for an unsent packet"))
				})
			})
		})
	}
})
