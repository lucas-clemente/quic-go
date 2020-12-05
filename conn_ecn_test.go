// +build !windows

package quic

import (
	"net"
	"syscall"
	"time"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Basic Conn Test", func() {
	Context("ECN conn", func() {
		runServer := func(network, address string) (*net.UDPConn, <-chan *receivedPacket) {
			addr, err := net.ResolveUDPAddr(network, address)
			Expect(err).ToNot(HaveOccurred())
			udpConn, err := net.ListenUDP(network, addr)
			Expect(err).ToNot(HaveOccurred())
			ecnConn, err := newConn(udpConn)
			Expect(err).ToNot(HaveOccurred())

			packetChan := make(chan *receivedPacket)
			go func() {
				defer GinkgoRecover()
				for {
					p, err := ecnConn.ReadPacket()
					if err != nil {
						return
					}
					packetChan <- p
				}
			}()

			return udpConn, packetChan
		}

		sendPacketWithECN := func(network string, addr *net.UDPAddr, setECN func(uintptr)) net.Addr {
			conn, err := net.DialUDP(network, nil, addr)
			ExpectWithOffset(1, err).ToNot(HaveOccurred())
			rawConn, err := conn.SyscallConn()
			ExpectWithOffset(1, err).ToNot(HaveOccurred())
			ExpectWithOffset(1, rawConn.Control(func(fd uintptr) {
				setECN(fd)
			})).To(Succeed())
			_, err = conn.Write([]byte("foobar"))
			ExpectWithOffset(1, err).ToNot(HaveOccurred())
			return conn.LocalAddr()
		}

		It("sets ECT0 on outgoing packets, for IPv4", func() {
			server, packetChan := runServer("udp4", "localhost:0")
			cl, err := net.DialUDP("udp4", nil, server.LocalAddr().(*net.UDPAddr))
			Expect(err).ToNot(HaveOccurred())
			conn, err := newConn(cl)
			Expect(err).ToNot(HaveOccurred())
			_, err = conn.Write([]byte("foobar"))
			Expect(err).ToNot(HaveOccurred())
			var p *receivedPacket
			Eventually(packetChan).Should(Receive(&p))
			Expect(p.ecn).To(Equal(protocol.ECT0))
		})

		It("sets ECT0 on outgoing packets, for IPv6", func() {
			server, packetChan := runServer("udp6", "[::]:0")
			cl, err := net.DialUDP("udp6", nil, server.LocalAddr().(*net.UDPAddr))
			Expect(err).ToNot(HaveOccurred())
			conn, err := newConn(cl)
			Expect(err).ToNot(HaveOccurred())
			_, err = conn.Write([]byte("foobar"))
			Expect(err).ToNot(HaveOccurred())
			var p *receivedPacket
			Eventually(packetChan).Should(Receive(&p))
			Expect(p.ecn).To(Equal(protocol.ECT0))
		})

		It("reads ECN flags on IPv4", func() {
			conn, packetChan := runServer("udp4", "localhost:0")
			defer conn.Close()

			sentFrom := sendPacketWithECN(
				"udp4",
				conn.LocalAddr().(*net.UDPAddr),
				func(fd uintptr) {
					Expect(syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_TOS, 2)).To(Succeed())
				},
			)

			var p *receivedPacket
			Eventually(packetChan).Should(Receive(&p))
			Expect(p.rcvTime).To(BeTemporally("~", time.Now(), scaleDuration(20*time.Millisecond)))
			Expect(p.data).To(Equal([]byte("foobar")))
			Expect(p.remoteAddr).To(Equal(sentFrom))
			Expect(p.ecn).To(Equal(protocol.ECT0))
		})

		It("reads ECN flags on IPv6", func() {
			conn, packetChan := runServer("udp6", "[::]:0")
			defer conn.Close()

			sentFrom := sendPacketWithECN(
				"udp6",
				conn.LocalAddr().(*net.UDPAddr),
				func(fd uintptr) {
					Expect(syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IPV6, syscall.IPV6_TCLASS, 3)).To(Succeed())
				},
			)

			var p *receivedPacket
			Eventually(packetChan).Should(Receive(&p))
			Expect(p.rcvTime).To(BeTemporally("~", time.Now(), scaleDuration(20*time.Millisecond)))
			Expect(p.data).To(Equal([]byte("foobar")))
			Expect(p.remoteAddr).To(Equal(sentFrom))
			Expect(p.ecn).To(Equal(protocol.ECNCE))
		})

		It("reads ECN flags on a connection that supports both IPv4 and IPv6", func() {
			conn, packetChan := runServer("udp", "0.0.0.0:0")
			defer conn.Close()
			port := conn.LocalAddr().(*net.UDPAddr).Port

			// IPv4
			sendPacketWithECN(
				"udp4",
				&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port},
				func(fd uintptr) {
					Expect(syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_TOS, 3)).To(Succeed())
				},
			)

			var p *receivedPacket
			Eventually(packetChan).Should(Receive(&p))
			Expect(utils.IsIPv4(p.remoteAddr.(*net.UDPAddr).IP)).To(BeTrue())
			Expect(p.ecn).To(Equal(protocol.ECNCE))

			// IPv6
			sendPacketWithECN(
				"udp6",
				&net.UDPAddr{IP: net.IPv6loopback, Port: port},
				func(fd uintptr) {
					Expect(syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IPV6, syscall.IPV6_TCLASS, 1)).To(Succeed())
				},
			)

			Eventually(packetChan).Should(Receive(&p))
			Expect(utils.IsIPv4(p.remoteAddr.(*net.UDPAddr).IP)).To(BeFalse())
			Expect(p.ecn).To(Equal(protocol.ECT1))
		})
	})
})
