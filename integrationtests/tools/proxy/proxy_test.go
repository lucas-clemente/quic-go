package quicproxy

import (
	"bytes"
	"fmt"
	"net"
	"runtime/pprof"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/wire"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

type packetData []byte

func isProxyRunning() bool {
	var b bytes.Buffer
	pprof.Lookup("goroutine").WriteTo(&b, 1)
	return strings.Contains(b.String(), "proxy.(*QuicProxy).runIncomingConnection") ||
		strings.Contains(b.String(), "proxy.(*QuicProxy).runOutgoingConnection")
}

var _ = Describe("QUIC Proxy", func() {
	makePacket := func(p protocol.PacketNumber, payload []byte) []byte {
		b := &bytes.Buffer{}
		hdr := wire.ExtendedHeader{
			Header: wire.Header{
				IsLongHeader:     true,
				Type:             protocol.PacketTypeInitial,
				Version:          protocol.VersionTLS,
				Length:           4 + protocol.ByteCount(len(payload)),
				DestConnectionID: protocol.ConnectionID{0xde, 0xad, 0xbe, 0xef, 0, 0, 0x13, 0x37},
				SrcConnectionID:  protocol.ConnectionID{0xde, 0xad, 0xbe, 0xef, 0, 0, 0x13, 0x37},
			},
			PacketNumber:    p,
			PacketNumberLen: protocol.PacketNumberLen4,
		}
		Expect(hdr.Write(b, protocol.VersionWhatever)).To(Succeed())
		raw := b.Bytes()
		raw = append(raw, payload...)
		return raw
	}

	readPacketNumber := func(b []byte) protocol.PacketNumber {
		Expect(wire.IsLongHeader(b[0])).To(BeTrue())
		hdr, data, _, err := wire.ParseLongHeaderPacket(b)
		ExpectWithOffset(1, err).ToNot(HaveOccurred())
		Expect(hdr.Type).To(Equal(protocol.PacketTypeInitial))
		extHdr, err := hdr.ParseExtended(bytes.NewReader(data), protocol.VersionTLS)
		ExpectWithOffset(1, err).ToNot(HaveOccurred())
		return extHdr.PacketNumber
	}

	AfterEach(func() {
		Eventually(isProxyRunning).Should(BeFalse())
	})

	Context("Proxy setup and teardown", func() {
		It("sets up the UDPProxy", func() {
			proxy, err := NewQuicProxy("localhost:0", nil)
			Expect(err).ToNot(HaveOccurred())
			Expect(proxy.clientDict).To(HaveLen(0))

			// check that the proxy port is in use
			addr, err := net.ResolveUDPAddr("udp", "localhost:"+strconv.Itoa(proxy.LocalPort()))
			Expect(err).ToNot(HaveOccurred())
			_, err = net.ListenUDP("udp", addr)
			Expect(err).To(MatchError(fmt.Sprintf("listen udp 127.0.0.1:%d: bind: address already in use", proxy.LocalPort())))
			Expect(proxy.Close()).To(Succeed()) // stopping is tested in the next test
		})

		It("stops the UDPProxy", func() {
			isProxyRunning := func() bool {
				var b bytes.Buffer
				pprof.Lookup("goroutine").WriteTo(&b, 1)
				return strings.Contains(b.String(), "proxy.(*QuicProxy).runProxy")
			}

			proxy, err := NewQuicProxy("localhost:0", nil)
			Expect(err).ToNot(HaveOccurred())
			port := proxy.LocalPort()
			Expect(isProxyRunning()).To(BeTrue())
			err = proxy.Close()
			Expect(err).ToNot(HaveOccurred())

			// check that the proxy port is not in use anymore
			addr, err := net.ResolveUDPAddr("udp", "localhost:"+strconv.Itoa(port))
			Expect(err).ToNot(HaveOccurred())
			// sometimes it takes a while for the OS to free the port
			Eventually(func() error {
				ln, err := net.ListenUDP("udp", addr)
				if err != nil {
					return err
				}
				ln.Close()
				return nil
			}).ShouldNot(HaveOccurred())
			Eventually(isProxyRunning).Should(BeFalse())
		})

		It("stops listening for proxied connections", func() {
			serverAddr, err := net.ResolveUDPAddr("udp", "localhost:0")
			Expect(err).ToNot(HaveOccurred())
			serverConn, err := net.ListenUDP("udp", serverAddr)
			Expect(err).ToNot(HaveOccurred())
			defer serverConn.Close()

			proxy, err := NewQuicProxy("localhost:0", &Opts{RemoteAddr: serverConn.LocalAddr().String()})
			Expect(err).ToNot(HaveOccurred())
			Expect(isProxyRunning()).To(BeFalse())

			// check that the proxy port is not in use anymore
			conn, err := net.DialUDP("udp", nil, proxy.LocalAddr().(*net.UDPAddr))
			Expect(err).ToNot(HaveOccurred())
			_, err = conn.Write(makePacket(1, []byte("foobar")))
			Expect(err).ToNot(HaveOccurred())
			Eventually(isProxyRunning).Should(BeTrue())
			Expect(proxy.Close()).To(Succeed())
			Eventually(isProxyRunning).Should(BeFalse())
		})

		It("has the correct LocalAddr and LocalPort", func() {
			proxy, err := NewQuicProxy("localhost:0", nil)
			Expect(err).ToNot(HaveOccurred())

			Expect(proxy.LocalAddr().String()).To(Equal("127.0.0.1:" + strconv.Itoa(proxy.LocalPort())))
			Expect(proxy.LocalPort()).ToNot(BeZero())

			Expect(proxy.Close()).To(Succeed())
		})
	})

	Context("Proxy tests", func() {
		var (
			serverConn            *net.UDPConn
			serverNumPacketsSent  int32
			serverReceivedPackets chan packetData
			clientConn            *net.UDPConn
			proxy                 *QuicProxy
			stoppedReading        chan struct{}
		)

		startProxy := func(opts *Opts) {
			var err error
			proxy, err = NewQuicProxy("localhost:0", opts)
			Expect(err).ToNot(HaveOccurred())
			clientConn, err = net.DialUDP("udp", nil, proxy.LocalAddr().(*net.UDPAddr))
			Expect(err).ToNot(HaveOccurred())
		}

		BeforeEach(func() {
			stoppedReading = make(chan struct{})
			serverReceivedPackets = make(chan packetData, 100)
			atomic.StoreInt32(&serverNumPacketsSent, 0)

			// setup a dump UDP server
			// in production this would be a QUIC server
			raddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
			Expect(err).ToNot(HaveOccurred())
			serverConn, err = net.ListenUDP("udp", raddr)
			Expect(err).ToNot(HaveOccurred())

			go func() {
				defer GinkgoRecover()
				defer close(stoppedReading)
				for {
					buf := make([]byte, protocol.MaxReceivePacketSize)
					// the ReadFromUDP will error as soon as the UDP conn is closed
					n, addr, err2 := serverConn.ReadFromUDP(buf)
					if err2 != nil {
						return
					}
					data := buf[0:n]
					serverReceivedPackets <- packetData(data)
					// echo the packet
					atomic.AddInt32(&serverNumPacketsSent, 1)
					serverConn.WriteToUDP(data, addr)
				}
			}()
		})

		AfterEach(func() {
			Expect(proxy.Close()).To(Succeed())
			Expect(serverConn.Close()).To(Succeed())
			Expect(clientConn.Close()).To(Succeed())
			Eventually(stoppedReading).Should(BeClosed())
		})

		Context("no packet drop", func() {
			It("relays packets from the client to the server", func() {
				startProxy(&Opts{RemoteAddr: serverConn.LocalAddr().String()})
				// send the first packet
				_, err := clientConn.Write(makePacket(1, []byte("foobar")))
				Expect(err).ToNot(HaveOccurred())

				// send the second packet
				_, err = clientConn.Write(makePacket(2, []byte("decafbad")))
				Expect(err).ToNot(HaveOccurred())

				Eventually(serverReceivedPackets).Should(HaveLen(2))
				Expect(string(<-serverReceivedPackets)).To(ContainSubstring("foobar"))
				Expect(string(<-serverReceivedPackets)).To(ContainSubstring("decafbad"))
			})

			It("relays packets from the server to the client", func() {
				startProxy(&Opts{RemoteAddr: serverConn.LocalAddr().String()})
				// send the first packet
				_, err := clientConn.Write(makePacket(1, []byte("foobar")))
				Expect(err).ToNot(HaveOccurred())

				// send the second packet
				_, err = clientConn.Write(makePacket(2, []byte("decafbad")))
				Expect(err).ToNot(HaveOccurred())

				clientReceivedPackets := make(chan packetData, 2)
				// receive the packets echoed by the server on client side
				go func() {
					for {
						buf := make([]byte, protocol.MaxReceivePacketSize)
						// the ReadFromUDP will error as soon as the UDP conn is closed
						n, _, err2 := clientConn.ReadFromUDP(buf)
						if err2 != nil {
							return
						}
						data := buf[0:n]
						clientReceivedPackets <- packetData(data)
					}
				}()

				Eventually(serverReceivedPackets).Should(HaveLen(2))
				Expect(atomic.LoadInt32(&serverNumPacketsSent)).To(BeEquivalentTo(2))
				Eventually(clientReceivedPackets).Should(HaveLen(2))
				Expect(string(<-clientReceivedPackets)).To(ContainSubstring("foobar"))
				Expect(string(<-clientReceivedPackets)).To(ContainSubstring("decafbad"))
			})
		})

		Context("Drop Callbacks", func() {
			It("drops incoming packets", func() {
				var counter int32
				opts := &Opts{
					RemoteAddr: serverConn.LocalAddr().String(),
					DropPacket: func(d Direction, _ []byte) bool {
						if d != DirectionIncoming {
							return false
						}
						return atomic.AddInt32(&counter, 1)%2 == 1
					},
				}
				startProxy(opts)

				for i := 1; i <= 6; i++ {
					_, err := clientConn.Write(makePacket(protocol.PacketNumber(i), []byte("foobar"+strconv.Itoa(i))))
					Expect(err).ToNot(HaveOccurred())
				}
				Eventually(serverReceivedPackets).Should(HaveLen(3))
				Consistently(serverReceivedPackets).Should(HaveLen(3))
			})

			It("drops outgoing packets", func() {
				const numPackets = 6
				var counter int32
				opts := &Opts{
					RemoteAddr: serverConn.LocalAddr().String(),
					DropPacket: func(d Direction, _ []byte) bool {
						if d != DirectionOutgoing {
							return false
						}
						return atomic.AddInt32(&counter, 1)%2 == 1
					},
				}
				startProxy(opts)

				clientReceivedPackets := make(chan packetData, numPackets)
				// receive the packets echoed by the server on client side
				go func() {
					for {
						buf := make([]byte, protocol.MaxReceivePacketSize)
						// the ReadFromUDP will error as soon as the UDP conn is closed
						n, _, err2 := clientConn.ReadFromUDP(buf)
						if err2 != nil {
							return
						}
						data := buf[0:n]
						clientReceivedPackets <- packetData(data)
					}
				}()

				for i := 1; i <= numPackets; i++ {
					_, err := clientConn.Write(makePacket(protocol.PacketNumber(i), []byte("foobar"+strconv.Itoa(i))))
					Expect(err).ToNot(HaveOccurred())
				}

				Eventually(clientReceivedPackets).Should(HaveLen(numPackets / 2))
				Consistently(clientReceivedPackets).Should(HaveLen(numPackets / 2))
			})
		})

		Context("Delay Callback", func() {
			const delay = 200 * time.Millisecond
			expectDelay := func(startTime time.Time, numRTTs int) {
				expectedReceiveTime := startTime.Add(time.Duration(numRTTs) * delay)
				Expect(time.Now()).To(SatisfyAll(
					BeTemporally(">=", expectedReceiveTime),
					BeTemporally("<", expectedReceiveTime.Add(delay/2)),
				))
			}

			It("delays incoming packets", func() {
				var counter int32
				opts := &Opts{
					RemoteAddr: serverConn.LocalAddr().String(),
					// delay packet 1 by 200 ms
					// delay packet 2 by 400 ms
					// ...
					DelayPacket: func(d Direction, _ []byte) time.Duration {
						if d == DirectionOutgoing {
							return 0
						}
						p := atomic.AddInt32(&counter, 1)
						return time.Duration(p) * delay
					},
				}
				startProxy(opts)

				// send 3 packets
				start := time.Now()
				for i := 1; i <= 3; i++ {
					_, err := clientConn.Write(makePacket(protocol.PacketNumber(i), []byte("foobar"+strconv.Itoa(i))))
					Expect(err).ToNot(HaveOccurred())
				}
				Eventually(serverReceivedPackets).Should(HaveLen(1))
				expectDelay(start, 1)
				Eventually(serverReceivedPackets).Should(HaveLen(2))
				expectDelay(start, 2)
				Eventually(serverReceivedPackets).Should(HaveLen(3))
				expectDelay(start, 3)
				Expect(readPacketNumber(<-serverReceivedPackets)).To(Equal(protocol.PacketNumber(1)))
				Expect(readPacketNumber(<-serverReceivedPackets)).To(Equal(protocol.PacketNumber(2)))
				Expect(readPacketNumber(<-serverReceivedPackets)).To(Equal(protocol.PacketNumber(3)))
			})

			It("handles reordered packets", func() {
				var counter int32
				opts := &Opts{
					RemoteAddr: serverConn.LocalAddr().String(),
					// delay packet 1 by 600 ms
					// delay packet 2 by 400 ms
					// delay packet 3 by 200 ms
					DelayPacket: func(d Direction, _ []byte) time.Duration {
						if d == DirectionOutgoing {
							return 0
						}
						p := atomic.AddInt32(&counter, 1)
						return 600*time.Millisecond - time.Duration(p-1)*delay
					},
				}
				startProxy(opts)

				// send 3 packets
				start := time.Now()
				for i := 1; i <= 3; i++ {
					_, err := clientConn.Write(makePacket(protocol.PacketNumber(i), []byte("foobar"+strconv.Itoa(i))))
					Expect(err).ToNot(HaveOccurred())
				}
				Eventually(serverReceivedPackets).Should(HaveLen(1))
				expectDelay(start, 1)
				Eventually(serverReceivedPackets).Should(HaveLen(2))
				expectDelay(start, 2)
				Eventually(serverReceivedPackets).Should(HaveLen(3))
				expectDelay(start, 3)
				Expect(readPacketNumber(<-serverReceivedPackets)).To(Equal(protocol.PacketNumber(3)))
				Expect(readPacketNumber(<-serverReceivedPackets)).To(Equal(protocol.PacketNumber(2)))
				Expect(readPacketNumber(<-serverReceivedPackets)).To(Equal(protocol.PacketNumber(1)))
			})

			It("doesn't reorder packets when a constant delay is used", func() {
				opts := &Opts{
					RemoteAddr: serverConn.LocalAddr().String(),
					DelayPacket: func(d Direction, _ []byte) time.Duration {
						if d == DirectionOutgoing {
							return 0
						}
						return 100 * time.Millisecond
					},
				}
				startProxy(opts)

				// send 100 packets
				for i := 0; i < 100; i++ {
					_, err := clientConn.Write(makePacket(protocol.PacketNumber(i), []byte("foobar"+strconv.Itoa(i))))
					Expect(err).ToNot(HaveOccurred())
				}
				Eventually(serverReceivedPackets).Should(HaveLen(100))
				for i := 0; i < 100; i++ {
					Expect(readPacketNumber(<-serverReceivedPackets)).To(Equal(protocol.PacketNumber(i)))
				}
			})

			It("delays outgoing packets", func() {
				const numPackets = 3
				var counter int32
				opts := &Opts{
					RemoteAddr: serverConn.LocalAddr().String(),
					// delay packet 1 by 200 ms
					// delay packet 2 by 400 ms
					// ...
					DelayPacket: func(d Direction, _ []byte) time.Duration {
						if d == DirectionIncoming {
							return 0
						}
						p := atomic.AddInt32(&counter, 1)
						return time.Duration(p) * delay
					},
				}
				startProxy(opts)

				clientReceivedPackets := make(chan packetData, numPackets)
				// receive the packets echoed by the server on client side
				go func() {
					for {
						buf := make([]byte, protocol.MaxReceivePacketSize)
						// the ReadFromUDP will error as soon as the UDP conn is closed
						n, _, err2 := clientConn.ReadFromUDP(buf)
						if err2 != nil {
							return
						}
						data := buf[0:n]
						clientReceivedPackets <- packetData(data)
					}
				}()

				start := time.Now()
				for i := 1; i <= numPackets; i++ {
					_, err := clientConn.Write(makePacket(protocol.PacketNumber(i), []byte("foobar"+strconv.Itoa(i))))
					Expect(err).ToNot(HaveOccurred())
				}
				// the packets should have arrived immediately at the server
				Eventually(serverReceivedPackets).Should(HaveLen(3))
				expectDelay(start, 0)
				Eventually(clientReceivedPackets).Should(HaveLen(1))
				expectDelay(start, 1)
				Eventually(clientReceivedPackets).Should(HaveLen(2))
				expectDelay(start, 2)
				Eventually(clientReceivedPackets).Should(HaveLen(3))
				expectDelay(start, 3)
				Expect(readPacketNumber(<-clientReceivedPackets)).To(Equal(protocol.PacketNumber(1)))
				Expect(readPacketNumber(<-clientReceivedPackets)).To(Equal(protocol.PacketNumber(2)))
				Expect(readPacketNumber(<-clientReceivedPackets)).To(Equal(protocol.PacketNumber(3)))
			})
		})
	})
})
