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
	"github.com/lucas-clemente/quic-go/integrationtests/tools/testserver"
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
					_, err = str.Write(testserver.PRData)
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
				serverConfig = &quic.Config{
					Versions:           []protocol.VersionNumber{version},
					ConnectionIDLength: connIDLen,
				}
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
						hdr, _, _, err := wire.ParsePacket(raw, connIDLen)
						Expect(err).ToNot(HaveOccurred())
						replyHdr := &wire.ExtendedHeader{
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

						const numPackets = 10
						ticker := time.NewTicker(rtt / numPackets)
						for i := 0; i < numPackets; i++ {
							payloadLen := mrand.Int31n(100)
							replyHdr.Length = protocol.ByteCount(mrand.Int31n(payloadLen + 1))
							buf := &bytes.Buffer{}
							Expect(replyHdr.Write(buf, v)).To(Succeed())
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
							&quic.Config{
								Versions:           []protocol.VersionNumber{version},
								ConnectionIDLength: connIDLen,
							},
						)
						Expect(err).ToNot(HaveOccurred())
						str, err := sess.AcceptUniStream(context.Background())
						Expect(err).ToNot(HaveOccurred())
						data, err := ioutil.ReadAll(str)
						Expect(err).ToNot(HaveOccurred())
						Expect(data).To(Equal(testserver.PRData))
						Expect(sess.Close()).To(Succeed())
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
						&quic.Config{
							Versions:           []protocol.VersionNumber{version},
							ConnectionIDLength: connIDLen,
						},
					)
					Expect(err).ToNot(HaveOccurred())
					str, err := sess.AcceptUniStream(context.Background())
					Expect(err).ToNot(HaveOccurred())
					data, err := ioutil.ReadAll(str)
					Expect(err).ToNot(HaveOccurred())
					Expect(data).To(Equal(testserver.PRData))
					Expect(sess.Close()).To(Succeed())
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
						serverConfig.IdleTimeout = idleTimeout
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
							isRetry := raw[0]&0xc0 == 0xc0 // don't corrupt Retry packets
							if dir == quicproxy.DirectionOutgoing && mrand.Intn(interval) == 0 && !isRetry {
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

			Context("early handshake injection attacks", func() {
				// These tests demonstrate that the QUIC protocol is vulnerable to injection attacks before the handshake
				// finishes. In particular, an adversary who can intercept packets coming from one endpoint and send a reply
				// that arrives before the real reply can tear down the connection in multiple ways.

				const rtt = 5 * time.Millisecond
				const mitigationOff time.Duration = -1
				const mitigationOn time.Duration = 500 * time.Millisecond

				var delayCb func(dir quicproxy.Direction, raw []byte) time.Duration
				var dropCb func(dir quicproxy.Direction, raw []byte) bool
				var generateForgery func(hdr *wire.Header) []byte
				var initialReceived bool

				// AfterEach closes the proxy, but each function is responsible
				// for closing client and server connections
				AfterEach(func() {
					// Test shutdown is tricky due to the proxy. Just wait for a bit.
					time.Sleep(50 * time.Millisecond)
					Expect(proxy.Close()).To(Succeed())
				})

				runTest := func(delayCb quicproxy.DelayCallback, dropCb quicproxy.DropCallback, attackTimeout time.Duration) error {
					startServerAndProxy(delayCb, dropCb)
					raddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("localhost:%d", proxy.LocalPort()))
					Expect(err).ToNot(HaveOccurred())
					sess, err := quic.Dial(
						clientConn,
						raddr,
						fmt.Sprintf("localhost:%d", proxy.LocalPort()),
						getTLSClientConfig(),
						&quic.Config{
							Versions:           []protocol.VersionNumber{version},
							ConnectionIDLength: connIDLen,
							AttackTimeout:      attackTimeout,
							HandshakeTimeout:   2 * time.Second,
						},
					)
					if err == nil {
						str, err := sess.AcceptUniStream(context.Background())
						Expect(err).ToNot(HaveOccurred())
						data, err := ioutil.ReadAll(str)
						Expect(err).ToNot(HaveOccurred())
						Expect(data).To(Equal(testserver.PRData))
						Expect(sess.Close()).To(Succeed())
					}
					return err
				}

				Context("intercept client Initial and reply with forged", func() {
					JustBeforeEach(func() {
						initialReceived = false
						delayCb = func(dir quicproxy.Direction, raw []byte) time.Duration {
							if dir == quicproxy.DirectionIncoming {
								defer GinkgoRecover()

								hdr, _, _, err := wire.ParsePacket(raw, connIDLen)
								Expect(err).ToNot(HaveOccurred())

								if hdr.Type != protocol.PacketTypeInitial || initialReceived {
									return 0
								}

								initialReceived = true
								forgedPacket := generateForgery(hdr)
								_, err = serverConn.WriteTo(forgedPacket, clientConn.LocalAddr())
								Expect(err).ToNot(HaveOccurred())
							}
							return rtt / 2
						}
						dropCb = func(dir quicproxy.Direction, raw []byte) bool {
							return false
						}
					})

					Context("version negotiation packet with unsupported versions", func() {
						BeforeEach(func() {
							generateForgery = func(hdr *wire.Header) []byte {
								versions := []protocol.VersionNumber{0x22334455, 0x33445566}
								packet, _ := wire.ComposeVersionNegotiation(hdr.SrcConnectionID, hdr.DestConnectionID, versions)
								return packet
							}
						})

						It("recovers when mitigation is enabled", func() {
							Expect(runTest(delayCb, dropCb, mitigationOn)).To(Succeed())
						})

						// fails immediately because client connection closes when it can't find compatible version
						It("fails when mitigation is disabled", func() {
							err := runTest(delayCb, dropCb, mitigationOff)
							Expect(err).To(HaveOccurred())
							Expect(err.Error()).To(ContainSubstring("No compatible QUIC version found."))
						})

						Context("when all all server packets are dropped", func() {
							var dropServerPackets func(dir quicproxy.Direction, raw []byte) bool
							BeforeEach(func() {
								dropServerPackets = func(dir quicproxy.Direction, raw []byte) bool {
									return dir == quicproxy.DirectionOutgoing
								}
							})

							It("times out when mitigation is enabled", func() {
								err := runTest(delayCb, dropServerPackets, mitigationOn)
								Expect(err).To(HaveOccurred())
								Expect(err.Error()).To(ContainSubstring("Timed out: No compatible QUIC version found."))
							})
						})
					})

					Context("retry packet with modified srcConnID", func() {
						BeforeEach(func() {
							generateForgery = func(hdr *wire.Header) []byte {
								var x byte = 0x12
								fakeSrcConnID := protocol.ConnectionID{x, x, x, x, x, x, x, x}
								return testutils.ComposeRetryPacket(fakeSrcConnID, hdr.SrcConnectionID, hdr.DestConnectionID, []byte("token"), hdr.Version)
							}
						})

						// times out, because client doesn't accept subsequent real retry packets from server
						// as it has already accepted a retry.
						It("times out when server always sends retry packets, and mitigation is disabled", func() {
							err := runTest(delayCb, dropCb, mitigationOff)
							Expect(err).To(HaveOccurred())
							Expect(err.(net.Error).Timeout()).To(BeTrue())
						})

						PIt("fails when server never sends retry packets", func() {
							serverConfig.AcceptToken = func(_ net.Addr, _ *quic.Token) bool {
								return true
							}
							err := runTest(delayCb, dropCb, mitigationOff)
							Expect(err).To(HaveOccurred())
						})

						PIt("recovers when mitigation is enabled", func() {
							Expect(runTest(delayCb, dropCb, mitigationOn)).To(Succeed())
						})
					})

					Context("empty initial packet", func() {
						BeforeEach(func() {
							generateForgery = func(hdr *wire.Header) []byte {
								return testutils.ComposeInitialByPayload(hdr.DestConnectionID, hdr.SrcConnectionID, hdr.Version, hdr.DestConnectionID, nil)
							}
						})

						// fails immediately because client closes when it receives an empty packet.
						It("fails when mitigation is disabled", func() {
							err := runTest(delayCb, dropCb, mitigationOff)
							Expect(err).To(HaveOccurred())
							Expect(err.Error()).To(ContainSubstring("empty packet"))
						})

						It("recovers when mitigation is enabled", func() {
							Expect(runTest(delayCb, dropCb, mitigationOn)).To(Succeed())
						})
					})

					Context("initial packet with only padding", func() {
						BeforeEach(func() {
							generateForgery = func(hdr *wire.Header) []byte {
								return testutils.ComposeInitialPacket(hdr.DestConnectionID, hdr.SrcConnectionID, hdr.Version, hdr.DestConnectionID, nil)
							}
						})

						// times out, because client doesn't accept real retry packets from server because
						// it has already accepted an initial.
						// TODO: determine behavior when server does not send Retry packets
						It("fails when mitigation is disabled", func() {
							err := runTest(delayCb, dropCb, mitigationOff)
							Expect(err).To(HaveOccurred())
							Expect(err.(net.Error).Timeout()).To(BeTrue())
						})

						PIt("recovers when mitigation is enabled", func() {
							Expect(runTest(delayCb, dropCb, mitigationOn)).To(Succeed())
						})
					})

					Context("initial packet with ack for unsent packet", func() {
						BeforeEach(func() {
							generateForgery = func(hdr *wire.Header) []byte {
								// Initial with ACK for packet 2 (unsent)
								ackFrame := testutils.ComposeAckFrame(2, 2)
								return testutils.ComposeInitialPacket(hdr.DestConnectionID, hdr.SrcConnectionID, hdr.Version, hdr.DestConnectionID, []wire.Frame{ackFrame})
							}
						})

						It("recovers when mitigation is enabled", func() {
							Expect(runTest(delayCb, dropCb, mitigationOn)).To(Succeed())
						})

						// client connection closes immediately on receiving ack for unsent packet
						It("fails when mitigation is disabled", func() {
							err := runTest(delayCb, dropCb, mitigationOff)
							Expect(err).To(HaveOccurred())
							Expect(err).To(BeAssignableToTypeOf(&qerr.QuicError{}))
							Expect(err.(*qerr.QuicError).ErrorCode).To(Equal(qerr.ProtocolViolation))
							Expect(err.Error()).To(ContainSubstring("Received ACK for an unsent packet"))
						})

					})

					Context("initial packet with nonsense frames", func() {
						BeforeEach(func() {
							generateForgery = func(hdr *wire.Header) []byte {
								// 42 is not a frame type
								payload := make([]byte, protocol.MinInitialPacketSize)
								payload[0] = byte(42)
								return testutils.ComposeInitialByPayload(hdr.DestConnectionID, hdr.SrcConnectionID, hdr.Version, hdr.DestConnectionID, payload)
							}
						})

						It("recovers when mitigation is enabled", func() {
							Expect(runTest(delayCb, dropCb, mitigationOn)).To(Succeed())
						})

						// client connection closes immediately on receiving unparseable frame
						It("fails when mitigation is disabled", func() {
							err := runTest(delayCb, dropCb, mitigationOff)
							Expect(err).To(HaveOccurred())
							Expect(err).To(BeAssignableToTypeOf(&qerr.QuicError{}))
							Expect(err.(*qerr.QuicError).ErrorCode).To(Equal(qerr.FrameEncodingError))
							Expect(err.Error()).To(ContainSubstring("unknown type byte"))
						})

					})

					Context("initial packet with illegal frame", func() {
						BeforeEach(func() {
							generateForgery = func(hdr *wire.Header) []byte {
								// ping frames are not allowed at Initial level
								return testutils.ComposeInitialPacket(hdr.DestConnectionID, hdr.SrcConnectionID, hdr.Version, hdr.DestConnectionID, []wire.Frame{&wire.PingFrame{}})
							}
						})

						It("recovers when mitigation is enabled", func() {
							Expect(runTest(delayCb, dropCb, mitigationOn)).To(Succeed())
						})

						// client connection closes immediately on receiving illegal frame
						It("fails when mitigation is disabled", func() {
							err := runTest(delayCb, dropCb, mitigationOff)
							Expect(err).To(HaveOccurred())
							Expect(err).To(BeAssignableToTypeOf(&qerr.QuicError{}))
							Expect(err.(*qerr.QuicError).ErrorCode).To(Equal(qerr.FrameEncodingError))
							Expect(err.Error()).To(ContainSubstring("PingFrame not allowed at encryption level Initial"))
						})

					})

					Context("initial packet with CONNECTION_CLOSE", func() {
						BeforeEach(func() {
							generateForgery = func(hdr *wire.Header) []byte {
								connCloseFrame := testutils.ComposeConnCloseFrame()
								return testutils.ComposeInitialPacket(hdr.DestConnectionID, hdr.SrcConnectionID, hdr.Version, hdr.DestConnectionID, []wire.Frame{connCloseFrame})
							}
						})

						// TODO: modify this test so Initial is sent after Retry
						PIt("recovers when mitigation is enabled", func() {
							Expect(runTest(delayCb, dropCb, mitigationOn)).To(Succeed())
						})

						// client connection closes immediately on receiving CONNECTION_CLOSE
						It("fails when mitigation is disabled", func() {
							err := runTest(delayCb, dropCb, mitigationOff)
							Expect(err).To(HaveOccurred())
							Expect(err).To(BeAssignableToTypeOf(&qerr.QuicError{}))
							Expect(err.(*qerr.QuicError).ErrorCode).To(Equal(qerr.ErrorCode(0)))
							Expect(err.Error()).To(ContainSubstring("mitm attacker"))
						})

					})
				})

			})
		})
	}
})
