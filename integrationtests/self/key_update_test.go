package self_test

import (
	"context"
	"fmt"
	"io/ioutil"
	"net"
	"time"

	quic "github.com/lucas-clemente/quic-go"
	"github.com/lucas-clemente/quic-go/internal/handshake"
	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/logging"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var (
	sentKeyPhases     []logging.KeyPhaseBit
	receivedKeyPhases []logging.KeyPhaseBit
)

func countKeyPhases() (sent, received int) {
	lastKeyPhase := protocol.KeyPhaseOne
	for _, keyPhase := range sentKeyPhases {
		if keyPhase != lastKeyPhase {
			sent++
			lastKeyPhase = keyPhase
		}
	}
	lastKeyPhase = protocol.KeyPhaseOne
	for _, keyPhase := range receivedKeyPhases {
		if keyPhase != lastKeyPhase {
			received++
			lastKeyPhase = keyPhase
		}
	}
	return
}

type simpleTracer struct{}

var _ logging.Tracer = &simpleTracer{}

func (t *simpleTracer) TracerForConnection(p logging.Perspective, odcid logging.ConnectionID) logging.ConnectionTracer {
	return &connTracer{}
}
func (t *simpleTracer) SentPacket(net.Addr, *logging.Header, logging.ByteCount, []logging.Frame) {}
func (t *simpleTracer) DroppedPacket(net.Addr, logging.PacketType, logging.ByteCount, logging.PacketDropReason) {
}

type connTracer struct{}

var _ logging.ConnectionTracer = &connTracer{}

func (t *connTracer) StartedConnection(local, remote net.Addr, version logging.VersionNumber, srcConnID, destConnID logging.ConnectionID) {
}
func (t *connTracer) ClosedConnection(logging.CloseReason)                     {}
func (t *connTracer) SentTransportParameters(*logging.TransportParameters)     {}
func (t *connTracer) ReceivedTransportParameters(*logging.TransportParameters) {}
func (t *connTracer) SentLongHeaderPacket(*logging.ExtendedHeader, logging.ByteCount, *logging.AckFrame, []logging.Frame) {
}

func (t *connTracer) SentShortHeaderPacket(_ logging.ConnectionID, _ logging.PacketNumber, kp logging.KeyPhaseBit, _ logging.ByteCount, _ *logging.AckFrame, _ []logging.Frame) {
	sentKeyPhases = append(sentKeyPhases, kp)
}
func (t *connTracer) ReceivedVersionNegotiationPacket(*logging.Header, []logging.VersionNumber) {}
func (t *connTracer) ReceivedRetry(*logging.Header)                                             {}
func (t *connTracer) ReceivedLongHeaderPacket(*logging.ExtendedHeader, logging.ByteCount, []logging.Frame) {
}

func (t *connTracer) ReceivedShortHeaderPacket(_ logging.ConnectionID, _ logging.PacketNumber, kp logging.KeyPhaseBit, _ logging.ByteCount, _ []logging.Frame) {
	receivedKeyPhases = append(receivedKeyPhases, kp)
}
func (t *connTracer) BufferedPacket(logging.PacketType)                                             {}
func (t *connTracer) DroppedPacket(logging.PacketType, logging.ByteCount, logging.PacketDropReason) {}
func (t *connTracer) UpdatedMetrics(rttStats *logging.RTTStats, cwnd, bytesInFlight logging.ByteCount, packetsInFlight int) {
}

func (t *connTracer) LostPacket(logging.EncryptionLevel, logging.PacketNumber, logging.PacketLossReason) {
}
func (t *connTracer) UpdatedCongestionState(logging.CongestionState)                     {}
func (t *connTracer) UpdatedPTOCount(value uint32)                                       {}
func (t *connTracer) UpdatedKeyFromTLS(logging.EncryptionLevel, logging.Perspective)     {}
func (t *connTracer) UpdatedKey(generation logging.KeyPhase, remote bool)                {}
func (t *connTracer) DroppedEncryptionLevel(logging.EncryptionLevel)                     {}
func (t *connTracer) DroppedKey(logging.KeyPhase)                                        {}
func (t *connTracer) SetLossTimer(logging.TimerType, logging.EncryptionLevel, time.Time) {}
func (t *connTracer) LossTimerExpired(logging.TimerType, logging.EncryptionLevel)        {}
func (t *connTracer) LossTimerCanceled()                                                 {}
func (t *connTracer) Debug(string, string)                                               {}
func (t *connTracer) Close()                                                             {}

var _ = Describe("Key Update tests", func() {
	var server quic.Listener

	runServer := func() {
		var err error
		server, err = quic.ListenAddr("localhost:0", getTLSConfig(), nil)
		Expect(err).ToNot(HaveOccurred())

		go func() {
			defer GinkgoRecover()
			sess, err := server.Accept(context.Background())
			Expect(err).ToNot(HaveOccurred())
			str, err := sess.OpenUniStream()
			Expect(err).ToNot(HaveOccurred())
			defer str.Close()
			_, err = str.Write(PRDataLong)
			Expect(err).ToNot(HaveOccurred())
		}()
	}

	It("downloads a large file", func() {
		origKeyUpdateInterval := handshake.KeyUpdateInterval
		defer func() { handshake.KeyUpdateInterval = origKeyUpdateInterval }()
		handshake.KeyUpdateInterval = 1 // update keys as frequently as possible

		runServer()
		sess, err := quic.DialAddr(
			fmt.Sprintf("localhost:%d", server.Addr().(*net.UDPAddr).Port),
			getTLSClientConfig(),
			&quic.Config{Tracer: &simpleTracer{}},
		)
		Expect(err).ToNot(HaveOccurred())
		str, err := sess.AcceptUniStream(context.Background())
		Expect(err).ToNot(HaveOccurred())
		data, err := ioutil.ReadAll(str)
		Expect(err).ToNot(HaveOccurred())
		Expect(data).To(Equal(PRDataLong))
		Expect(sess.CloseWithError(0, "")).To(Succeed())

		keyPhasesSent, keyPhasesReceived := countKeyPhases()
		fmt.Fprintf(GinkgoWriter, "Used %d key phases on outgoing and %d key phases on incoming packets.\n", keyPhasesSent, keyPhasesReceived)
		Expect(keyPhasesReceived).To(BeNumerically(">", 10))
		Expect(keyPhasesReceived).To(BeNumerically("~", keyPhasesSent, 1))
	})
})
