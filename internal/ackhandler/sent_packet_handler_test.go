package ackhandler

import (
	"fmt"
	"time"

	"github.com/golang/mock/gomock"

	"github.com/lucas-clemente/quic-go/internal/mocks"
	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/qerr"
	"github.com/lucas-clemente/quic-go/internal/utils"
	"github.com/lucas-clemente/quic-go/internal/wire"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("SentPacketHandler", func() {
	var (
		handler     *sentPacketHandler
		streamFrame wire.StreamFrame
		lostPackets []protocol.PacketNumber
		perspective protocol.Perspective
	)

	BeforeEach(func() { perspective = protocol.PerspectiveServer })

	JustBeforeEach(func() {
		lostPackets = nil
		rttStats := utils.NewRTTStats()
		handler = newSentPacketHandler(42, protocol.InitialPacketSizeIPv4, rttStats, perspective, nil, utils.DefaultLogger)
		streamFrame = wire.StreamFrame{
			StreamID: 5,
			Data:     []byte{0x13, 0x37},
		}
	})

	getPacket := func(pn protocol.PacketNumber, encLevel protocol.EncryptionLevel) *Packet {
		if el, ok := handler.getPacketNumberSpace(encLevel).history.packetMap[pn]; ok {
			return &el.Value
		}
		return nil
	}

	ackElicitingPacket := func(p *Packet) *Packet {
		if p.EncryptionLevel == 0 {
			p.EncryptionLevel = protocol.Encryption1RTT
		}
		if p.Length == 0 {
			p.Length = 1
		}
		if p.SendTime.IsZero() {
			p.SendTime = time.Now()
		}
		if len(p.Frames) == 0 {
			p.Frames = []Frame{
				{Frame: &wire.PingFrame{}, OnLost: func(wire.Frame) { lostPackets = append(lostPackets, p.PacketNumber) }},
			}
		}
		return p
	}

	nonAckElicitingPacket := func(p *Packet) *Packet {
		p = ackElicitingPacket(p)
		p.Frames = nil
		p.LargestAcked = 1
		return p
	}

	initialPacket := func(p *Packet) *Packet {
		p = ackElicitingPacket(p)
		p.EncryptionLevel = protocol.EncryptionInitial
		return p
	}

	handshakePacket := func(p *Packet) *Packet {
		p = ackElicitingPacket(p)
		p.EncryptionLevel = protocol.EncryptionHandshake
		return p
	}

	handshakePacketNonAckEliciting := func(p *Packet) *Packet {
		p = nonAckElicitingPacket(p)
		p.EncryptionLevel = protocol.EncryptionHandshake
		return p
	}

	expectInPacketHistory := func(expected []protocol.PacketNumber, encLevel protocol.EncryptionLevel) {
		pnSpace := handler.getPacketNumberSpace(encLevel)
		var length int
		pnSpace.history.Iterate(func(p *Packet) (bool, error) {
			if !p.declaredLost && !p.skippedPacket {
				length++
			}
			return true, nil
		})
		ExpectWithOffset(1, length).To(Equal(len(expected)))
		for _, p := range expected {
			ExpectWithOffset(2, pnSpace.history.packetMap).To(HaveKey(p))
		}
	}

	updateRTT := func(rtt time.Duration) {
		handler.rttStats.UpdateRTT(rtt, 0, time.Now())
		ExpectWithOffset(1, handler.rttStats.SmoothedRTT()).To(Equal(rtt))
	}

	Context("registering sent packets", func() {
		It("accepts two consecutive packets", func() {
			handler.SentPacket(ackElicitingPacket(&Packet{PacketNumber: 1, EncryptionLevel: protocol.EncryptionHandshake}))
			handler.SentPacket(ackElicitingPacket(&Packet{PacketNumber: 2, EncryptionLevel: protocol.EncryptionHandshake}))
			Expect(handler.handshakePackets.largestSent).To(Equal(protocol.PacketNumber(2)))
			expectInPacketHistory([]protocol.PacketNumber{1, 2}, protocol.EncryptionHandshake)
			Expect(handler.bytesInFlight).To(Equal(protocol.ByteCount(2)))
		})

		It("uses the same packet number space for 0-RTT and 1-RTT packets", func() {
			handler.SentPacket(ackElicitingPacket(&Packet{PacketNumber: 1, EncryptionLevel: protocol.Encryption0RTT}))
			handler.SentPacket(ackElicitingPacket(&Packet{PacketNumber: 2, EncryptionLevel: protocol.Encryption1RTT}))
			Expect(handler.appDataPackets.largestSent).To(Equal(protocol.PacketNumber(2)))
			Expect(handler.bytesInFlight).To(Equal(protocol.ByteCount(2)))
		})

		It("accepts packet number 0", func() {
			handler.SentPacket(ackElicitingPacket(&Packet{PacketNumber: 0, EncryptionLevel: protocol.Encryption1RTT}))
			Expect(handler.appDataPackets.largestSent).To(BeZero())
			handler.SentPacket(ackElicitingPacket(&Packet{PacketNumber: 1, EncryptionLevel: protocol.Encryption1RTT}))
			Expect(handler.appDataPackets.largestSent).To(Equal(protocol.PacketNumber(1)))
			expectInPacketHistory([]protocol.PacketNumber{0, 1}, protocol.Encryption1RTT)
			Expect(handler.bytesInFlight).To(Equal(protocol.ByteCount(2)))
		})

		It("stores the sent time", func() {
			sendTime := time.Now().Add(-time.Minute)
			handler.SentPacket(ackElicitingPacket(&Packet{PacketNumber: 1, SendTime: sendTime}))
			Expect(handler.appDataPackets.lastAckElicitingPacketTime).To(Equal(sendTime))
		})

		It("stores the sent time of Initial packets", func() {
			sendTime := time.Now().Add(-time.Minute)
			handler.SentPacket(ackElicitingPacket(&Packet{PacketNumber: 1, SendTime: sendTime, EncryptionLevel: protocol.EncryptionInitial}))
			handler.SentPacket(ackElicitingPacket(&Packet{PacketNumber: 2, SendTime: sendTime.Add(time.Hour), EncryptionLevel: protocol.Encryption1RTT}))
			Expect(handler.initialPackets.lastAckElicitingPacketTime).To(Equal(sendTime))
		})
	})

	Context("ACK processing", func() {
		JustBeforeEach(func() {
			for i := protocol.PacketNumber(0); i < 10; i++ {
				handler.SentPacket(ackElicitingPacket(&Packet{PacketNumber: i}))
			}
			// Increase RTT, because the tests would be flaky otherwise
			updateRTT(time.Hour)
			Expect(handler.bytesInFlight).To(Equal(protocol.ByteCount(10)))
		})

		Context("ACK processing", func() {
			It("accepts ACKs sent in packet 0", func() {
				ack := &wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: 0, Largest: 5}}}
				_, err := handler.ReceivedAck(ack, protocol.Encryption1RTT, time.Now())
				Expect(err).ToNot(HaveOccurred())
				Expect(handler.appDataPackets.largestAcked).To(Equal(protocol.PacketNumber(5)))
			})

			It("says if a 1-RTT packet was acknowledged", func() {
				handler.SentPacket(ackElicitingPacket(&Packet{PacketNumber: 100, EncryptionLevel: protocol.Encryption0RTT}))
				handler.SentPacket(ackElicitingPacket(&Packet{PacketNumber: 101, EncryptionLevel: protocol.Encryption0RTT}))
				handler.SentPacket(ackElicitingPacket(&Packet{PacketNumber: 102, EncryptionLevel: protocol.Encryption1RTT}))
				acked1RTT, err := handler.ReceivedAck(
					&wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: 100, Largest: 101}}},
					protocol.Encryption1RTT,
					time.Now(),
				)
				Expect(err).ToNot(HaveOccurred())
				Expect(acked1RTT).To(BeFalse())
				acked1RTT, err = handler.ReceivedAck(
					&wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: 101, Largest: 102}}},
					protocol.Encryption1RTT,
					time.Now(),
				)
				Expect(err).ToNot(HaveOccurred())
				Expect(acked1RTT).To(BeTrue())
			})

			It("accepts multiple ACKs sent in the same packet", func() {
				ack1 := &wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: 0, Largest: 3}}}
				ack2 := &wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: 0, Largest: 4}}}
				_, err := handler.ReceivedAck(ack1, protocol.Encryption1RTT, time.Now())
				Expect(err).ToNot(HaveOccurred())
				Expect(handler.appDataPackets.largestAcked).To(Equal(protocol.PacketNumber(3)))
				// this wouldn't happen in practice
				// for testing purposes, we pretend send a different ACK frame in a duplicated packet, to be able to verify that it actually doesn't get processed
				_, err = handler.ReceivedAck(ack2, protocol.Encryption1RTT, time.Now())
				Expect(err).ToNot(HaveOccurred())
				Expect(handler.appDataPackets.largestAcked).To(Equal(protocol.PacketNumber(4)))
			})

			It("rejects ACKs that acknowledge a skipped packet number", func() {
				handler.SentPacket(ackElicitingPacket(&Packet{PacketNumber: 100}))
				handler.SentPacket(ackElicitingPacket(&Packet{PacketNumber: 102}))
				ack := &wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: 100, Largest: 102}}}
				_, err := handler.ReceivedAck(ack, protocol.Encryption1RTT, time.Now())
				Expect(err).To(MatchError(&qerr.TransportError{
					ErrorCode:    qerr.ProtocolViolation,
					ErrorMessage: "received an ACK for skipped packet number: 101 (1-RTT)",
				}))
			})

			It("rejects ACKs with a too high LargestAcked packet number", func() {
				ack := &wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: 0, Largest: 9999}}}
				_, err := handler.ReceivedAck(ack, protocol.Encryption1RTT, time.Now())
				Expect(err).To(MatchError(&qerr.TransportError{
					ErrorCode:    qerr.ProtocolViolation,
					ErrorMessage: "received ACK for an unsent packet",
				}))
				Expect(handler.bytesInFlight).To(Equal(protocol.ByteCount(10)))
			})

			It("ignores repeated ACKs", func() {
				ack := &wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: 0, Largest: 3}}}
				_, err := handler.ReceivedAck(ack, protocol.Encryption1RTT, time.Now())
				Expect(err).ToNot(HaveOccurred())
				Expect(handler.bytesInFlight).To(Equal(protocol.ByteCount(6)))
				_, err = handler.ReceivedAck(ack, protocol.Encryption1RTT, time.Now())
				Expect(err).ToNot(HaveOccurred())
				Expect(handler.appDataPackets.largestAcked).To(Equal(protocol.PacketNumber(3)))
				Expect(handler.bytesInFlight).To(Equal(protocol.ByteCount(6)))
			})
		})

		Context("acks the right packets", func() {
			expectInPacketHistoryOrLost := func(expected []protocol.PacketNumber, encLevel protocol.EncryptionLevel) {
				pnSpace := handler.getPacketNumberSpace(encLevel)
				var length int
				pnSpace.history.Iterate(func(p *Packet) (bool, error) {
					if !p.declaredLost {
						length++
					}
					return true, nil
				})
				ExpectWithOffset(1, length+len(lostPackets)).To(Equal(len(expected)))
			expectedLoop:
				for _, p := range expected {
					if _, ok := pnSpace.history.packetMap[p]; ok {
						continue
					}
					for _, lostP := range lostPackets {
						if lostP == p {
							continue expectedLoop
						}
					}
					Fail(fmt.Sprintf("Packet %d not in packet history.", p))
				}
			}

			It("adjusts the LargestAcked, and adjusts the bytes in flight", func() {
				ack := &wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: 0, Largest: 5}}}
				_, err := handler.ReceivedAck(ack, protocol.Encryption1RTT, time.Now())
				Expect(err).ToNot(HaveOccurred())
				Expect(handler.appDataPackets.largestAcked).To(Equal(protocol.PacketNumber(5)))
				expectInPacketHistoryOrLost([]protocol.PacketNumber{6, 7, 8, 9}, protocol.Encryption1RTT)
				Expect(handler.bytesInFlight).To(Equal(protocol.ByteCount(4)))
			})

			It("acks packet 0", func() {
				ack := &wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: 0, Largest: 0}}}
				_, err := handler.ReceivedAck(ack, protocol.Encryption1RTT, time.Now())
				Expect(err).ToNot(HaveOccurred())
				Expect(getPacket(0, protocol.Encryption1RTT)).To(BeNil())
				expectInPacketHistoryOrLost([]protocol.PacketNumber{1, 2, 3, 4, 5, 6, 7, 8, 9}, protocol.Encryption1RTT)
			})

			It("calls the OnAcked callback", func() {
				var acked bool
				ping := &wire.PingFrame{}
				handler.SentPacket(ackElicitingPacket(&Packet{
					PacketNumber: 13,
					Frames: []Frame{{
						Frame: ping, OnAcked: func(f wire.Frame) {
							Expect(f).To(Equal(ping))
							acked = true
						},
					}},
				}))
				ack := &wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: 13, Largest: 13}}}
				_, err := handler.ReceivedAck(ack, protocol.Encryption1RTT, time.Now())
				Expect(err).ToNot(HaveOccurred())
				Expect(acked).To(BeTrue())
			})

			It("handles an ACK frame with one missing packet range", func() {
				ack := &wire.AckFrame{ // lose 4 and 5
					AckRanges: []wire.AckRange{
						{Smallest: 6, Largest: 9},
						{Smallest: 1, Largest: 3},
					},
				}
				_, err := handler.ReceivedAck(ack, protocol.Encryption1RTT, time.Now())
				Expect(err).ToNot(HaveOccurred())
				expectInPacketHistoryOrLost([]protocol.PacketNumber{0, 4, 5}, protocol.Encryption1RTT)
			})

			It("does not ack packets below the LowestAcked", func() {
				ack := &wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: 3, Largest: 8}}}
				_, err := handler.ReceivedAck(ack, protocol.Encryption1RTT, time.Now())
				Expect(err).ToNot(HaveOccurred())
				expectInPacketHistoryOrLost([]protocol.PacketNumber{0, 1, 2, 9}, protocol.Encryption1RTT)
			})

			It("handles an ACK with multiple missing packet ranges", func() {
				ack := &wire.AckFrame{ // packets 2, 4 and 5, and 8 were lost
					AckRanges: []wire.AckRange{
						{Smallest: 9, Largest: 9},
						{Smallest: 6, Largest: 7},
						{Smallest: 3, Largest: 3},
						{Smallest: 1, Largest: 1},
					},
				}
				_, err := handler.ReceivedAck(ack, protocol.Encryption1RTT, time.Now())
				Expect(err).ToNot(HaveOccurred())
				expectInPacketHistoryOrLost([]protocol.PacketNumber{0, 2, 4, 5, 8}, protocol.Encryption1RTT)
			})

			It("processes an ACK frame that would be sent after a late arrival of a packet", func() {
				ack1 := &wire.AckFrame{ // 5 lost
					AckRanges: []wire.AckRange{
						{Smallest: 6, Largest: 6},
						{Smallest: 1, Largest: 4},
					},
				}
				_, err := handler.ReceivedAck(ack1, protocol.Encryption1RTT, time.Now())
				Expect(err).ToNot(HaveOccurred())
				expectInPacketHistoryOrLost([]protocol.PacketNumber{0, 5, 7, 8, 9}, protocol.Encryption1RTT)
				ack2 := &wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: 1, Largest: 6}}} // now ack 5
				_, err = handler.ReceivedAck(ack2, protocol.Encryption1RTT, time.Now())
				Expect(err).ToNot(HaveOccurred())
				expectInPacketHistoryOrLost([]protocol.PacketNumber{0, 7, 8, 9}, protocol.Encryption1RTT)
			})

			It("processes an ACK that contains old ACK ranges", func() {
				ack1 := &wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: 1, Largest: 6}}}
				_, err := handler.ReceivedAck(ack1, protocol.Encryption1RTT, time.Now())
				Expect(err).ToNot(HaveOccurred())
				expectInPacketHistoryOrLost([]protocol.PacketNumber{0, 7, 8, 9}, protocol.Encryption1RTT)
				ack2 := &wire.AckFrame{
					AckRanges: []wire.AckRange{
						{Smallest: 8, Largest: 8},
						{Smallest: 3, Largest: 3},
						{Smallest: 1, Largest: 1},
					},
				}
				_, err = handler.ReceivedAck(ack2, protocol.Encryption1RTT, time.Now())
				Expect(err).ToNot(HaveOccurred())
				expectInPacketHistoryOrLost([]protocol.PacketNumber{0, 7, 9}, protocol.Encryption1RTT)
			})
		})

		Context("calculating RTT", func() {
			It("computes the RTT", func() {
				now := time.Now()
				// First, fake the sent times of the first, second and last packet
				getPacket(1, protocol.Encryption1RTT).SendTime = now.Add(-10 * time.Minute)
				getPacket(2, protocol.Encryption1RTT).SendTime = now.Add(-5 * time.Minute)
				getPacket(6, protocol.Encryption1RTT).SendTime = now.Add(-1 * time.Minute)
				// Now, check that the proper times are used when calculating the deltas
				ack := &wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: 1, Largest: 1}}}
				_, err := handler.ReceivedAck(ack, protocol.Encryption1RTT, time.Now())
				Expect(err).ToNot(HaveOccurred())
				Expect(handler.rttStats.LatestRTT()).To(BeNumerically("~", 10*time.Minute, 1*time.Second))
				ack = &wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: 1, Largest: 2}}}
				_, err = handler.ReceivedAck(ack, protocol.Encryption1RTT, time.Now())
				Expect(err).ToNot(HaveOccurred())
				Expect(handler.rttStats.LatestRTT()).To(BeNumerically("~", 5*time.Minute, 1*time.Second))
				ack = &wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: 1, Largest: 6}}}
				_, err = handler.ReceivedAck(ack, protocol.Encryption1RTT, time.Now())
				Expect(err).ToNot(HaveOccurred())
				Expect(handler.rttStats.LatestRTT()).To(BeNumerically("~", 1*time.Minute, 1*time.Second))
			})

			It("ignores the DelayTime for Initial and Handshake packets", func() {
				handler.SentPacket(initialPacket(&Packet{PacketNumber: 1}))
				handler.rttStats.SetMaxAckDelay(time.Hour)
				// make sure the rttStats have a min RTT, so that the delay is used
				handler.rttStats.UpdateRTT(5*time.Minute, 0, time.Now())
				getPacket(1, protocol.EncryptionInitial).SendTime = time.Now().Add(-10 * time.Minute)
				ack := &wire.AckFrame{
					AckRanges: []wire.AckRange{{Smallest: 1, Largest: 1}},
					DelayTime: 5 * time.Minute,
				}
				_, err := handler.ReceivedAck(ack, protocol.EncryptionInitial, time.Now())
				Expect(err).ToNot(HaveOccurred())
				Expect(handler.rttStats.LatestRTT()).To(BeNumerically("~", 10*time.Minute, 1*time.Second))
			})

			It("uses the DelayTime in the ACK frame", func() {
				handler.rttStats.SetMaxAckDelay(time.Hour)
				// make sure the rttStats have a min RTT, so that the delay is used
				handler.rttStats.UpdateRTT(5*time.Minute, 0, time.Now())
				getPacket(1, protocol.Encryption1RTT).SendTime = time.Now().Add(-10 * time.Minute)
				ack := &wire.AckFrame{
					AckRanges: []wire.AckRange{{Smallest: 1, Largest: 1}},
					DelayTime: 5 * time.Minute,
				}
				_, err := handler.ReceivedAck(ack, protocol.Encryption1RTT, time.Now())
				Expect(err).ToNot(HaveOccurred())
				Expect(handler.rttStats.LatestRTT()).To(BeNumerically("~", 5*time.Minute, 1*time.Second))
			})

			It("limits the DelayTime in the ACK frame to max_ack_delay", func() {
				handler.rttStats.SetMaxAckDelay(time.Minute)
				// make sure the rttStats have a min RTT, so that the delay is used
				handler.rttStats.UpdateRTT(5*time.Minute, 0, time.Now())
				getPacket(1, protocol.Encryption1RTT).SendTime = time.Now().Add(-10 * time.Minute)
				ack := &wire.AckFrame{
					AckRanges: []wire.AckRange{{Smallest: 1, Largest: 1}},
					DelayTime: 5 * time.Minute,
				}
				_, err := handler.ReceivedAck(ack, protocol.Encryption1RTT, time.Now())
				Expect(err).ToNot(HaveOccurred())
				Expect(handler.rttStats.LatestRTT()).To(BeNumerically("~", 9*time.Minute, 1*time.Second))
			})
		})

		Context("determining which ACKs we have received an ACK for", func() {
			JustBeforeEach(func() {
				morePackets := []*Packet{
					{
						PacketNumber:    13,
						LargestAcked:    100,
						Frames:          []Frame{{Frame: &streamFrame, OnLost: func(wire.Frame) {}}},
						Length:          1,
						EncryptionLevel: protocol.Encryption1RTT,
					},
					{
						PacketNumber:    14,
						LargestAcked:    200,
						Frames:          []Frame{{Frame: &streamFrame, OnLost: func(wire.Frame) {}}},
						Length:          1,
						EncryptionLevel: protocol.Encryption1RTT,
					},
					{
						PacketNumber:    15,
						Frames:          []Frame{{Frame: &streamFrame, OnLost: func(wire.Frame) {}}},
						Length:          1,
						EncryptionLevel: protocol.Encryption1RTT,
					},
				}
				for _, packet := range morePackets {
					handler.SentPacket(packet)
				}
			})

			It("determines which ACK we have received an ACK for", func() {
				ack := &wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: 13, Largest: 15}}}
				_, err := handler.ReceivedAck(ack, protocol.Encryption1RTT, time.Now())
				Expect(err).ToNot(HaveOccurred())
				Expect(handler.GetLowestPacketNotConfirmedAcked()).To(Equal(protocol.PacketNumber(201)))
			})

			It("doesn't do anything when the acked packet didn't contain an ACK", func() {
				ack1 := &wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: 13, Largest: 13}}}
				ack2 := &wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: 15, Largest: 15}}}
				_, err := handler.ReceivedAck(ack1, protocol.Encryption1RTT, time.Now())
				Expect(err).ToNot(HaveOccurred())
				Expect(handler.GetLowestPacketNotConfirmedAcked()).To(Equal(protocol.PacketNumber(101)))
				_, err = handler.ReceivedAck(ack2, protocol.Encryption1RTT, time.Now())
				Expect(err).ToNot(HaveOccurred())
				Expect(handler.GetLowestPacketNotConfirmedAcked()).To(Equal(protocol.PacketNumber(101)))
			})

			It("doesn't decrease the value", func() {
				ack1 := &wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: 14, Largest: 14}}}
				ack2 := &wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: 13, Largest: 13}}}
				_, err := handler.ReceivedAck(ack1, protocol.Encryption1RTT, time.Now())
				Expect(err).ToNot(HaveOccurred())
				Expect(handler.GetLowestPacketNotConfirmedAcked()).To(Equal(protocol.PacketNumber(201)))
				_, err = handler.ReceivedAck(ack2, protocol.Encryption1RTT, time.Now())
				Expect(err).ToNot(HaveOccurred())
				Expect(handler.GetLowestPacketNotConfirmedAcked()).To(Equal(protocol.PacketNumber(201)))
			})
		})
	})

	Context("congestion", func() {
		var cong *mocks.MockSendAlgorithmWithDebugInfos

		JustBeforeEach(func() {
			cong = mocks.NewMockSendAlgorithmWithDebugInfos(mockCtrl)
			handler.congestion = cong
		})

		It("should call OnSent", func() {
			cong.EXPECT().OnPacketSent(
				gomock.Any(),
				protocol.ByteCount(42),
				protocol.PacketNumber(1),
				protocol.ByteCount(42),
				true,
			)
			handler.SentPacket(&Packet{
				PacketNumber:    1,
				Length:          42,
				Frames:          []Frame{{Frame: &wire.PingFrame{}, OnLost: func(wire.Frame) {}}},
				EncryptionLevel: protocol.Encryption1RTT,
			})
		})

		It("should call MaybeExitSlowStart and OnPacketAcked", func() {
			rcvTime := time.Now().Add(-5 * time.Second)
			cong.EXPECT().OnPacketSent(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Times(3)
			gomock.InOrder(
				cong.EXPECT().MaybeExitSlowStart(), // must be called before packets are acked
				cong.EXPECT().OnPacketAcked(protocol.PacketNumber(1), protocol.ByteCount(1), protocol.ByteCount(3), rcvTime),
				cong.EXPECT().OnPacketAcked(protocol.PacketNumber(2), protocol.ByteCount(1), protocol.ByteCount(3), rcvTime),
			)
			handler.SentPacket(ackElicitingPacket(&Packet{PacketNumber: 1}))
			handler.SentPacket(ackElicitingPacket(&Packet{PacketNumber: 2}))
			handler.SentPacket(ackElicitingPacket(&Packet{PacketNumber: 3}))
			ack := &wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: 1, Largest: 2}}}
			_, err := handler.ReceivedAck(ack, protocol.Encryption1RTT, rcvTime)
			Expect(err).ToNot(HaveOccurred())
		})

		It("doesn't call OnPacketAcked when a retransmitted packet is acked", func() {
			cong.EXPECT().OnPacketSent(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Times(2)
			handler.SentPacket(ackElicitingPacket(&Packet{PacketNumber: 1, SendTime: time.Now().Add(-time.Hour)}))
			handler.SentPacket(ackElicitingPacket(&Packet{PacketNumber: 2}))
			// lose packet 1
			gomock.InOrder(
				cong.EXPECT().MaybeExitSlowStart(),
				cong.EXPECT().OnPacketLost(protocol.PacketNumber(1), protocol.ByteCount(1), protocol.ByteCount(2)),
				cong.EXPECT().OnPacketAcked(protocol.PacketNumber(2), protocol.ByteCount(1), protocol.ByteCount(2), gomock.Any()),
			)
			ack := &wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: 2, Largest: 2}}}
			_, err := handler.ReceivedAck(ack, protocol.Encryption1RTT, time.Now())
			Expect(err).ToNot(HaveOccurred())
			// don't EXPECT any further calls to the congestion controller
			ack = &wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: 1, Largest: 2}}}
			_, err = handler.ReceivedAck(ack, protocol.Encryption1RTT, time.Now())
			Expect(err).ToNot(HaveOccurred())
		})

		It("doesn't call OnPacketLost when a Path MTU probe packet is lost", func() {
			cong.EXPECT().OnPacketSent(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Times(2)
			var mtuPacketDeclaredLost bool
			handler.SentPacket(ackElicitingPacket(&Packet{
				PacketNumber:         1,
				SendTime:             time.Now().Add(-time.Hour),
				IsPathMTUProbePacket: true,
				Frames:               []Frame{{Frame: &wire.PingFrame{}, OnLost: func(wire.Frame) { mtuPacketDeclaredLost = true }}},
			}))
			handler.SentPacket(ackElicitingPacket(&Packet{PacketNumber: 2}))
			// lose packet 1, but don't EXPECT any calls to OnPacketLost()
			gomock.InOrder(
				cong.EXPECT().MaybeExitSlowStart(),
				cong.EXPECT().OnPacketAcked(protocol.PacketNumber(2), protocol.ByteCount(1), protocol.ByteCount(2), gomock.Any()),
			)
			ack := &wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: 2, Largest: 2}}}
			_, err := handler.ReceivedAck(ack, protocol.Encryption1RTT, time.Now())
			Expect(err).ToNot(HaveOccurred())
			Expect(mtuPacketDeclaredLost).To(BeTrue())
			Expect(handler.bytesInFlight).To(BeZero())
		})

		It("calls OnPacketAcked and OnPacketLost with the right bytes_in_flight value", func() {
			cong.EXPECT().OnPacketSent(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Times(4)
			handler.SentPacket(ackElicitingPacket(&Packet{PacketNumber: 1, SendTime: time.Now().Add(-time.Hour)}))
			handler.SentPacket(ackElicitingPacket(&Packet{PacketNumber: 2, SendTime: time.Now().Add(-30 * time.Minute)}))
			handler.SentPacket(ackElicitingPacket(&Packet{PacketNumber: 3, SendTime: time.Now().Add(-30 * time.Minute)}))
			handler.SentPacket(ackElicitingPacket(&Packet{PacketNumber: 4, SendTime: time.Now()}))
			// receive the first ACK
			gomock.InOrder(
				cong.EXPECT().MaybeExitSlowStart(),
				cong.EXPECT().OnPacketLost(protocol.PacketNumber(1), protocol.ByteCount(1), protocol.ByteCount(4)),
				cong.EXPECT().OnPacketAcked(protocol.PacketNumber(2), protocol.ByteCount(1), protocol.ByteCount(4), gomock.Any()),
			)
			ack := &wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: 2, Largest: 2}}}
			_, err := handler.ReceivedAck(ack, protocol.Encryption1RTT, time.Now().Add(-30*time.Minute))
			Expect(err).ToNot(HaveOccurred())
			// receive the second ACK
			gomock.InOrder(
				cong.EXPECT().MaybeExitSlowStart(),
				cong.EXPECT().OnPacketLost(protocol.PacketNumber(3), protocol.ByteCount(1), protocol.ByteCount(2)),
				cong.EXPECT().OnPacketAcked(protocol.PacketNumber(4), protocol.ByteCount(1), protocol.ByteCount(2), gomock.Any()),
			)
			ack = &wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: 4, Largest: 4}}}
			_, err = handler.ReceivedAck(ack, protocol.Encryption1RTT, time.Now())
			Expect(err).ToNot(HaveOccurred())
		})

		It("passes the bytes in flight to the congestion controller", func() {
			handler.ReceivedPacket(protocol.EncryptionHandshake)
			cong.EXPECT().OnPacketSent(gomock.Any(), protocol.ByteCount(42), gomock.Any(), protocol.ByteCount(42), true)
			handler.SentPacket(&Packet{
				Length:          42,
				EncryptionLevel: protocol.EncryptionInitial,
				Frames:          []Frame{{Frame: &wire.PingFrame{}}},
				SendTime:        time.Now(),
			})
			cong.EXPECT().CanSend(protocol.ByteCount(42)).Return(true)
			handler.SendMode()
		})

		It("allows sending of ACKs when congestion limited", func() {
			handler.ReceivedPacket(protocol.EncryptionHandshake)
			cong.EXPECT().CanSend(gomock.Any()).Return(true)
			Expect(handler.SendMode()).To(Equal(SendAny))
			cong.EXPECT().CanSend(gomock.Any()).Return(false)
			Expect(handler.SendMode()).To(Equal(SendAck))
		})

		It("allows sending of ACKs when we're keeping track of MaxOutstandingSentPackets packets", func() {
			handler.ReceivedPacket(protocol.EncryptionHandshake)
			cong.EXPECT().CanSend(gomock.Any()).Return(true).AnyTimes()
			cong.EXPECT().OnPacketSent(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes()
			for i := protocol.PacketNumber(0); i < protocol.MaxOutstandingSentPackets; i++ {
				Expect(handler.SendMode()).To(Equal(SendAny))
				handler.SentPacket(ackElicitingPacket(&Packet{PacketNumber: i}))
			}
			Expect(handler.SendMode()).To(Equal(SendAck))
		})

		It("allows PTOs, even when congestion limited", func() {
			handler.ReceivedPacket(protocol.EncryptionHandshake)
			// note that we don't EXPECT a call to GetCongestionWindow
			// that means retransmissions are sent without considering the congestion window
			handler.numProbesToSend = 1
			handler.ptoMode = SendPTOHandshake
			Expect(handler.SendMode()).To(Equal(SendPTOHandshake))
		})

		It("says if it has pacing budget", func() {
			cong.EXPECT().HasPacingBudget().Return(true)
			Expect(handler.HasPacingBudget()).To(BeTrue())
			cong.EXPECT().HasPacingBudget().Return(false)
			Expect(handler.HasPacingBudget()).To(BeFalse())
		})

		It("returns the pacing delay", func() {
			t := time.Now()
			cong.EXPECT().TimeUntilSend(gomock.Any()).Return(t)
			Expect(handler.TimeUntilSend()).To(Equal(t))
		})
	})

	It("doesn't set an alarm if there are no outstanding packets", func() {
		handler.ReceivedPacket(protocol.EncryptionHandshake)
		handler.SentPacket(ackElicitingPacket(&Packet{PacketNumber: 10}))
		handler.SentPacket(ackElicitingPacket(&Packet{PacketNumber: 11}))
		ack := &wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: 10, Largest: 11}}}
		_, err := handler.ReceivedAck(ack, protocol.Encryption1RTT, time.Now())
		Expect(err).ToNot(HaveOccurred())
		Expect(handler.GetLossDetectionTimeout()).To(BeZero())
	})

	It("does nothing on OnAlarm if there are no outstanding packets", func() {
		handler.ReceivedPacket(protocol.EncryptionHandshake)
		Expect(handler.OnLossDetectionTimeout()).To(Succeed())
		Expect(handler.SendMode()).To(Equal(SendAny))
	})

	Context("probe packets", func() {
		It("queues a probe packet", func() {
			handler.SentPacket(ackElicitingPacket(&Packet{PacketNumber: 10}))
			handler.SentPacket(ackElicitingPacket(&Packet{PacketNumber: 11}))
			queued := handler.QueueProbePacket(protocol.Encryption1RTT)
			Expect(queued).To(BeTrue())
			Expect(lostPackets).To(Equal([]protocol.PacketNumber{10}))
		})

		It("says when it can't queue a probe packet", func() {
			queued := handler.QueueProbePacket(protocol.Encryption1RTT)
			Expect(queued).To(BeFalse())
		})

		It("implements exponential backoff", func() {
			handler.peerAddressValidated = true
			handler.SetHandshakeConfirmed()
			sendTime := time.Now().Add(-time.Hour)
			handler.SentPacket(ackElicitingPacket(&Packet{PacketNumber: 1, SendTime: sendTime}))
			timeout := handler.GetLossDetectionTimeout().Sub(sendTime)
			Expect(handler.GetLossDetectionTimeout().Sub(sendTime)).To(Equal(timeout))
			handler.ptoCount = 1
			handler.setLossDetectionTimer()
			Expect(handler.GetLossDetectionTimeout().Sub(sendTime)).To(Equal(2 * timeout))
			handler.ptoCount = 2
			handler.setLossDetectionTimer()
			Expect(handler.GetLossDetectionTimeout().Sub(sendTime)).To(Equal(4 * timeout))
		})

		It("reset the PTO count when receiving an ACK", func() {
			handler.ReceivedPacket(protocol.EncryptionHandshake)
			now := time.Now()
			handler.SetHandshakeConfirmed()
			handler.SentPacket(ackElicitingPacket(&Packet{PacketNumber: 1, SendTime: now.Add(-time.Minute)}))
			handler.SentPacket(ackElicitingPacket(&Packet{PacketNumber: 2, SendTime: now.Add(-time.Minute)}))
			Expect(handler.GetLossDetectionTimeout()).To(BeTemporally("~", now.Add(-time.Minute), time.Second))
			Expect(handler.OnLossDetectionTimeout()).To(Succeed())
			Expect(handler.SendMode()).To(Equal(SendPTOAppData))
			Expect(handler.ptoCount).To(BeEquivalentTo(1))
			_, err := handler.ReceivedAck(&wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: 1, Largest: 1}}}, protocol.Encryption1RTT, time.Now())
			Expect(err).ToNot(HaveOccurred())
			Expect(handler.ptoCount).To(BeZero())
		})

		It("resets the PTO mode and PTO count when a packet number space is dropped", func() {
			handler.ReceivedPacket(protocol.EncryptionHandshake)

			now := time.Now()
			handler.rttStats.UpdateRTT(time.Second/2, 0, now)
			Expect(handler.rttStats.SmoothedRTT()).To(Equal(time.Second / 2))
			Expect(handler.rttStats.PTO(true)).To(And(
				BeNumerically(">", time.Second),
				BeNumerically("<", 2*time.Second),
			))
			sendTimeHandshake := now.Add(-2 * time.Minute)
			sendTimeAppData := now.Add(-time.Minute)

			handler.SentPacket(ackElicitingPacket(&Packet{
				PacketNumber:    1,
				EncryptionLevel: protocol.EncryptionHandshake,
				SendTime:        sendTimeHandshake,
			}))
			handler.SentPacket(ackElicitingPacket(&Packet{
				PacketNumber: 2,
				SendTime:     sendTimeAppData,
			}))

			// PTO timer based on the Handshake packet
			Expect(handler.OnLossDetectionTimeout()).To(Succeed())
			Expect(handler.ptoCount).To(BeEquivalentTo(1))
			Expect(handler.SendMode()).To(Equal(SendPTOHandshake))
			Expect(handler.GetLossDetectionTimeout()).To(Equal(sendTimeHandshake.Add(handler.rttStats.PTO(false) << 1)))
			handler.SetHandshakeConfirmed()
			handler.DropPackets(protocol.EncryptionHandshake)
			// PTO timer based on the 1-RTT packet
			Expect(handler.GetLossDetectionTimeout()).To(Equal(sendTimeAppData.Add(handler.rttStats.PTO(true)))) // no backoff. PTO count = 0
			Expect(handler.SendMode()).ToNot(Equal(SendPTOHandshake))
			Expect(handler.ptoCount).To(BeZero())
		})

		It("allows two 1-RTT PTOs", func() {
			handler.ReceivedPacket(protocol.EncryptionHandshake)
			handler.SetHandshakeConfirmed()
			var lostPackets []protocol.PacketNumber
			handler.SentPacket(ackElicitingPacket(&Packet{
				PacketNumber: 1,
				SendTime:     time.Now().Add(-time.Hour),
				Frames: []Frame{
					{Frame: &wire.PingFrame{}, OnLost: func(wire.Frame) { lostPackets = append(lostPackets, 1) }},
				},
			}))
			Expect(handler.OnLossDetectionTimeout()).To(Succeed())
			Expect(handler.SendMode()).To(Equal(SendPTOAppData))
			handler.SentPacket(ackElicitingPacket(&Packet{PacketNumber: 2}))
			Expect(handler.SendMode()).To(Equal(SendPTOAppData))
			handler.SentPacket(ackElicitingPacket(&Packet{PacketNumber: 3}))
			Expect(handler.SendMode()).ToNot(Equal(SendPTOAppData))
		})

		It("skips a packet number for 1-RTT PTOs", func() {
			handler.ReceivedPacket(protocol.EncryptionHandshake)
			handler.SetHandshakeConfirmed()
			var lostPackets []protocol.PacketNumber
			pn := handler.PopPacketNumber(protocol.Encryption1RTT)
			handler.SentPacket(ackElicitingPacket(&Packet{
				PacketNumber: pn,
				SendTime:     time.Now().Add(-time.Hour),
				Frames: []Frame{
					{Frame: &wire.PingFrame{}, OnLost: func(wire.Frame) { lostPackets = append(lostPackets, 1) }},
				},
			}))
			Expect(handler.OnLossDetectionTimeout()).To(Succeed())
			Expect(handler.SendMode()).To(Equal(SendPTOAppData))
			// The packet number generator might have introduced another skipped a packet number.
			Expect(handler.PopPacketNumber(protocol.Encryption1RTT)).To(BeNumerically(">=", pn+2))
		})

		It("only counts ack-eliciting packets as probe packets", func() {
			handler.ReceivedPacket(protocol.EncryptionHandshake)
			handler.SetHandshakeConfirmed()
			handler.SentPacket(ackElicitingPacket(&Packet{PacketNumber: 1, SendTime: time.Now().Add(-time.Hour)}))
			Expect(handler.OnLossDetectionTimeout()).To(Succeed())
			Expect(handler.SendMode()).To(Equal(SendPTOAppData))
			handler.SentPacket(ackElicitingPacket(&Packet{PacketNumber: 2}))
			Expect(handler.SendMode()).To(Equal(SendPTOAppData))
			for p := protocol.PacketNumber(3); p < 30; p++ {
				handler.SentPacket(nonAckElicitingPacket(&Packet{PacketNumber: p}))
				Expect(handler.SendMode()).To(Equal(SendPTOAppData))
			}
			handler.SentPacket(ackElicitingPacket(&Packet{PacketNumber: 30}))
			Expect(handler.SendMode()).ToNot(Equal(SendPTOAppData))
		})

		It("gets two probe packets if PTO expires", func() {
			handler.ReceivedPacket(protocol.EncryptionHandshake)
			handler.SetHandshakeConfirmed()
			handler.SentPacket(ackElicitingPacket(&Packet{PacketNumber: 1}))
			handler.SentPacket(ackElicitingPacket(&Packet{PacketNumber: 2}))

			updateRTT(time.Hour)
			Expect(handler.appDataPackets.lossTime.IsZero()).To(BeTrue())

			Expect(handler.OnLossDetectionTimeout()).To(Succeed()) // TLP
			Expect(handler.ptoCount).To(BeEquivalentTo(1))
			Expect(handler.SendMode()).To(Equal(SendPTOAppData))
			handler.SentPacket(ackElicitingPacket(&Packet{PacketNumber: 3}))
			Expect(handler.SendMode()).To(Equal(SendPTOAppData))
			handler.SentPacket(ackElicitingPacket(&Packet{PacketNumber: 4}))

			Expect(handler.OnLossDetectionTimeout()).To(Succeed()) // PTO
			Expect(handler.ptoCount).To(BeEquivalentTo(2))
			Expect(handler.SendMode()).To(Equal(SendPTOAppData))
			handler.SentPacket(ackElicitingPacket(&Packet{PacketNumber: 5}))
			Expect(handler.SendMode()).To(Equal(SendPTOAppData))
			handler.SentPacket(ackElicitingPacket(&Packet{PacketNumber: 6}))

			Expect(handler.SendMode()).To(Equal(SendAny))
		})

		It("gets two probe packets if PTO expires, for Handshake packets", func() {
			handler.ReceivedPacket(protocol.EncryptionHandshake)
			handler.SentPacket(initialPacket(&Packet{PacketNumber: 1}))
			handler.SentPacket(initialPacket(&Packet{PacketNumber: 2}))

			updateRTT(time.Hour)
			Expect(handler.initialPackets.lossTime.IsZero()).To(BeTrue())

			Expect(handler.OnLossDetectionTimeout()).To(Succeed())
			Expect(handler.SendMode()).To(Equal(SendPTOInitial))
			handler.SentPacket(initialPacket(&Packet{PacketNumber: 3}))
			Expect(handler.SendMode()).To(Equal(SendPTOInitial))
			handler.SentPacket(initialPacket(&Packet{PacketNumber: 4}))

			Expect(handler.SendMode()).To(Equal(SendAny))
		})

		It("doesn't send 1-RTT probe packets before the handshake completes", func() {
			handler.ReceivedPacket(protocol.EncryptionHandshake)
			handler.SentPacket(ackElicitingPacket(&Packet{PacketNumber: 1}))
			updateRTT(time.Hour)
			Expect(handler.OnLossDetectionTimeout()).To(Succeed())
			Expect(handler.GetLossDetectionTimeout()).To(BeZero())
			Expect(handler.SendMode()).To(Equal(SendAny))
			handler.SetHandshakeConfirmed()
			Expect(handler.GetLossDetectionTimeout()).ToNot(BeZero())
			Expect(handler.OnLossDetectionTimeout()).To(Succeed())
			Expect(handler.SendMode()).To(Equal(SendPTOAppData))
		})

		It("resets the send mode when it receives an acknowledgement after queueing probe packets", func() {
			handler.ReceivedPacket(protocol.EncryptionHandshake)
			handler.SetHandshakeConfirmed()
			handler.SentPacket(ackElicitingPacket(&Packet{PacketNumber: 1, SendTime: time.Now().Add(-time.Hour)}))
			updateRTT(time.Second)
			Expect(handler.OnLossDetectionTimeout()).To(Succeed())
			Expect(handler.SendMode()).To(Equal(SendPTOAppData))
			ack := &wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: 1, Largest: 1}}}
			_, err := handler.ReceivedAck(ack, protocol.Encryption1RTT, time.Now())
			Expect(err).ToNot(HaveOccurred())
			Expect(handler.SendMode()).To(Equal(SendAny))
		})

		It("handles ACKs for the original packet", func() {
			handler.ReceivedPacket(protocol.EncryptionHandshake)
			handler.SentPacket(ackElicitingPacket(&Packet{PacketNumber: 5, SendTime: time.Now().Add(-time.Hour)}))
			updateRTT(time.Second)
			Expect(handler.OnLossDetectionTimeout()).To(Succeed())
			Expect(handler.OnLossDetectionTimeout()).To(Succeed())
		})

		It("doesn't set the PTO timer for Path MTU probe packets", func() {
			handler.ReceivedPacket(protocol.EncryptionHandshake)
			handler.SetHandshakeConfirmed()
			updateRTT(time.Second)
			handler.SentPacket(ackElicitingPacket(&Packet{PacketNumber: 5, SendTime: time.Now(), IsPathMTUProbePacket: true}))
			Expect(handler.GetLossDetectionTimeout()).To(BeZero())
		})
	})

	Context("amplification limit, for the server", func() {
		It("limits the window to 3x the bytes received, to avoid amplification attacks", func() {
			handler.ReceivedPacket(protocol.EncryptionInitial) // receiving an Initial packet doesn't validate the client's address
			handler.ReceivedBytes(200)
			handler.SentPacket(&Packet{
				PacketNumber:    1,
				Length:          599,
				EncryptionLevel: protocol.EncryptionInitial,
				Frames:          []Frame{{Frame: &wire.PingFrame{}}},
				SendTime:        time.Now(),
			})
			Expect(handler.SendMode()).To(Equal(SendAny))
			handler.SentPacket(&Packet{
				PacketNumber:    2,
				Length:          1,
				EncryptionLevel: protocol.EncryptionInitial,
				Frames:          []Frame{{Frame: &wire.PingFrame{}}},
				SendTime:        time.Now(),
			})
			Expect(handler.SendMode()).To(Equal(SendNone))
		})

		It("cancels the loss detection timer when it is amplification limited, and resets it when becoming unblocked", func() {
			handler.ReceivedBytes(300)
			handler.SentPacket(&Packet{
				PacketNumber:    1,
				Length:          900,
				EncryptionLevel: protocol.EncryptionInitial,
				Frames:          []Frame{{Frame: &wire.PingFrame{}}},
				SendTime:        time.Now(),
			})
			// Amplification limited. We don't need to set a timer now.
			Expect(handler.GetLossDetectionTimeout()).To(BeZero())
			// Unblock the server. Now we should fire up the timer.
			handler.ReceivedBytes(1)
			Expect(handler.GetLossDetectionTimeout()).ToNot(BeZero())
		})

		It("resets the loss detection timer when the client's address is validated", func() {
			handler.ReceivedBytes(300)
			handler.SentPacket(&Packet{
				PacketNumber:    1,
				Length:          900,
				EncryptionLevel: protocol.EncryptionHandshake,
				Frames:          []Frame{{Frame: &wire.PingFrame{}}},
				SendTime:        time.Now(),
			})
			// Amplification limited. We don't need to set a timer now.
			Expect(handler.GetLossDetectionTimeout()).To(BeZero())
			handler.ReceivedPacket(protocol.EncryptionHandshake)
			Expect(handler.GetLossDetectionTimeout()).ToNot(BeZero())
		})

		It("cancels the loss detection alarm when all Handshake packets are acknowledged", func() {
			t := time.Now().Add(-time.Second)
			handler.ReceivedBytes(99999)
			handler.SentPacket(ackElicitingPacket(&Packet{PacketNumber: 2, SendTime: t}))
			handler.SentPacket(handshakePacket(&Packet{PacketNumber: 3, SendTime: t}))
			handler.SentPacket(handshakePacket(&Packet{PacketNumber: 4, SendTime: t}))
			Expect(handler.GetLossDetectionTimeout()).ToNot(BeZero())
			handler.ReceivedAck(&wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: 3, Largest: 4}}}, protocol.EncryptionHandshake, time.Now())
			Expect(handler.GetLossDetectionTimeout()).To(BeZero())
		})
	})

	Context("amplification limit, for the client", func() {
		BeforeEach(func() {
			perspective = protocol.PerspectiveClient
		})

		It("sends an Initial packet to unblock the server", func() {
			handler.SentPacket(initialPacket(&Packet{PacketNumber: 1}))
			_, err := handler.ReceivedAck(
				&wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: 1, Largest: 1}}},
				protocol.EncryptionInitial,
				time.Now(),
			)
			Expect(err).ToNot(HaveOccurred())
			// No packets are outstanding at this point.
			// Make sure that a probe packet is sent.
			Expect(handler.GetLossDetectionTimeout()).ToNot(BeZero())
			Expect(handler.OnLossDetectionTimeout()).To(Succeed())
			Expect(handler.SendMode()).To(Equal(SendPTOInitial))

			// send a single packet to unblock the server
			handler.SentPacket(initialPacket(&Packet{PacketNumber: 2}))
			Expect(handler.SendMode()).To(Equal(SendAny))

			// Now receive an ACK for a Handshake packet.
			// This tells the client that the server completed address validation.
			handler.SentPacket(handshakePacket(&Packet{PacketNumber: 1}))
			_, err = handler.ReceivedAck(
				&wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: 1, Largest: 1}}},
				protocol.EncryptionHandshake,
				time.Now(),
			)
			Expect(err).ToNot(HaveOccurred())
			// Make sure that no timer is set at this point.
			Expect(handler.GetLossDetectionTimeout()).To(BeZero())
		})

		It("sends a Handshake packet to unblock the server, if Initial keys were already dropped", func() {
			handler.SentPacket(initialPacket(&Packet{PacketNumber: 1}))
			_, err := handler.ReceivedAck(
				&wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: 1, Largest: 1}}},
				protocol.EncryptionInitial,
				time.Now(),
			)
			Expect(err).ToNot(HaveOccurred())

			handler.SentPacket(handshakePacketNonAckEliciting(&Packet{PacketNumber: 1})) // also drops Initial packets
			Expect(handler.GetLossDetectionTimeout()).ToNot(BeZero())
			Expect(handler.OnLossDetectionTimeout()).To(Succeed())
			Expect(handler.SendMode()).To(Equal(SendPTOHandshake))

			// Now receive an ACK for this packet, and send another one.
			_, err = handler.ReceivedAck(
				&wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: 1, Largest: 1}}},
				protocol.EncryptionHandshake,
				time.Now(),
			)
			Expect(err).ToNot(HaveOccurred())
			handler.SentPacket(handshakePacketNonAckEliciting(&Packet{PacketNumber: 2}))
			Expect(handler.GetLossDetectionTimeout()).To(BeZero())
		})

		It("doesn't send a packet to unblock the server after handshake confirmation, even if no Handshake ACK was received", func() {
			handler.SentPacket(handshakePacket(&Packet{PacketNumber: 1}))
			Expect(handler.GetLossDetectionTimeout()).ToNot(BeZero())
			Expect(handler.OnLossDetectionTimeout()).To(Succeed())
			Expect(handler.SendMode()).To(Equal(SendPTOHandshake))
			// confirm the handshake
			handler.DropPackets(protocol.EncryptionHandshake)
			Expect(handler.GetLossDetectionTimeout()).To(BeZero())
		})

		It("correctly sets the timer after the Initial packet number space has been dropped", func() {
			handler.SentPacket(initialPacket(&Packet{PacketNumber: 1, SendTime: time.Now().Add(-42 * time.Second)}))
			_, err := handler.ReceivedAck(
				&wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: 1, Largest: 1}}},
				protocol.EncryptionInitial,
				time.Now(),
			)
			Expect(err).ToNot(HaveOccurred())
			handler.SentPacket(handshakePacketNonAckEliciting(&Packet{PacketNumber: 1, SendTime: time.Now()}))
			Expect(handler.initialPackets).To(BeNil())

			pto := handler.rttStats.PTO(false)
			Expect(pto).ToNot(BeZero())
			Expect(handler.GetLossDetectionTimeout()).To(BeTemporally("~", time.Now().Add(pto), 10*time.Millisecond))
		})

		It("doesn't reset the PTO count when receiving an ACK", func() {
			now := time.Now()
			handler.SentPacket(initialPacket(&Packet{PacketNumber: 1, SendTime: now.Add(-time.Minute)}))
			handler.SentPacket(initialPacket(&Packet{PacketNumber: 2, SendTime: now.Add(-time.Minute)}))
			Expect(handler.GetLossDetectionTimeout()).To(BeTemporally("~", now.Add(-time.Minute), time.Second))
			Expect(handler.OnLossDetectionTimeout()).To(Succeed())
			Expect(handler.SendMode()).To(Equal(SendPTOInitial))
			Expect(handler.ptoCount).To(BeEquivalentTo(1))
			_, err := handler.ReceivedAck(&wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: 1, Largest: 1}}}, protocol.EncryptionInitial, time.Now())
			Expect(err).ToNot(HaveOccurred())
			Expect(handler.ptoCount).To(BeEquivalentTo(1))
		})
	})

	Context("Packet-based loss detection", func() {
		It("declares packet below the packet loss threshold as lost", func() {
			now := time.Now()
			for i := protocol.PacketNumber(1); i <= 6; i++ {
				handler.SentPacket(ackElicitingPacket(&Packet{PacketNumber: i}))
			}
			ack := &wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: 6, Largest: 6}}}
			_, err := handler.ReceivedAck(ack, protocol.Encryption1RTT, now)
			Expect(err).ToNot(HaveOccurred())
			expectInPacketHistory([]protocol.PacketNumber{4, 5}, protocol.Encryption1RTT)
			Expect(lostPackets).To(Equal([]protocol.PacketNumber{1, 2, 3}))
		})
	})

	Context("Delay-based loss detection", func() {
		It("immediately detects old packets as lost when receiving an ACK", func() {
			now := time.Now()
			handler.SentPacket(ackElicitingPacket(&Packet{PacketNumber: 1, SendTime: now.Add(-time.Hour)}))
			handler.SentPacket(ackElicitingPacket(&Packet{PacketNumber: 2, SendTime: now.Add(-time.Second)}))
			Expect(handler.appDataPackets.lossTime.IsZero()).To(BeTrue())

			ack := &wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: 2, Largest: 2}}}
			_, err := handler.ReceivedAck(ack, protocol.Encryption1RTT, now)
			Expect(err).ToNot(HaveOccurred())
			// no need to set an alarm, since packet 1 was already declared lost
			Expect(handler.appDataPackets.lossTime.IsZero()).To(BeTrue())
			Expect(handler.bytesInFlight).To(BeZero())
		})

		It("sets the early retransmit alarm", func() {
			handler.ReceivedPacket(protocol.EncryptionHandshake)
			handler.handshakeConfirmed = true
			now := time.Now()
			handler.SentPacket(ackElicitingPacket(&Packet{PacketNumber: 1, SendTime: now.Add(-2 * time.Second)}))
			handler.SentPacket(ackElicitingPacket(&Packet{PacketNumber: 2, SendTime: now.Add(-2 * time.Second)}))
			handler.SentPacket(ackElicitingPacket(&Packet{PacketNumber: 3, SendTime: now}))
			Expect(handler.appDataPackets.lossTime.IsZero()).To(BeTrue())

			ack := &wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: 2, Largest: 2}}}
			_, err := handler.ReceivedAck(ack, protocol.Encryption1RTT, now.Add(-time.Second))
			Expect(err).ToNot(HaveOccurred())
			Expect(handler.rttStats.SmoothedRTT()).To(Equal(time.Second))

			// Packet 1 should be considered lost (1+1/8) RTTs after it was sent.
			Expect(handler.GetLossDetectionTimeout().Sub(getPacket(1, protocol.Encryption1RTT).SendTime)).To(Equal(time.Second * 9 / 8))
			Expect(handler.SendMode()).To(Equal(SendAny))

			expectInPacketHistory([]protocol.PacketNumber{1, 3}, protocol.Encryption1RTT)
			Expect(handler.OnLossDetectionTimeout()).To(Succeed())
			expectInPacketHistory([]protocol.PacketNumber{3}, protocol.Encryption1RTT)
			Expect(handler.SendMode()).To(Equal(SendAny))
		})

		It("sets the early retransmit alarm for crypto packets", func() {
			handler.ReceivedBytes(1000)
			now := time.Now()
			handler.SentPacket(initialPacket(&Packet{PacketNumber: 1, SendTime: now.Add(-2 * time.Second)}))
			handler.SentPacket(initialPacket(&Packet{PacketNumber: 2, SendTime: now.Add(-2 * time.Second)}))
			handler.SentPacket(initialPacket(&Packet{PacketNumber: 3, SendTime: now}))
			Expect(handler.initialPackets.lossTime.IsZero()).To(BeTrue())

			ack := &wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: 2, Largest: 2}}}
			_, err := handler.ReceivedAck(ack, protocol.EncryptionInitial, now.Add(-time.Second))
			Expect(err).ToNot(HaveOccurred())
			Expect(handler.rttStats.SmoothedRTT()).To(Equal(time.Second))

			// Packet 1 should be considered lost (1+1/8) RTTs after it was sent.
			Expect(handler.GetLossDetectionTimeout().Sub(getPacket(1, protocol.EncryptionInitial).SendTime)).To(Equal(time.Second * 9 / 8))
			Expect(handler.SendMode()).To(Equal(SendAny))

			expectInPacketHistory([]protocol.PacketNumber{1, 3}, protocol.EncryptionInitial)
			Expect(handler.OnLossDetectionTimeout()).To(Succeed())
			expectInPacketHistory([]protocol.PacketNumber{3}, protocol.EncryptionInitial)
			Expect(handler.SendMode()).To(Equal(SendAny))
		})

		It("sets the early retransmit alarm for Path MTU probe packets", func() {
			var mtuPacketDeclaredLost bool
			now := time.Now()
			handler.SentPacket(ackElicitingPacket(&Packet{
				PacketNumber:         1,
				SendTime:             now.Add(-3 * time.Second),
				IsPathMTUProbePacket: true,
				Frames:               []Frame{{Frame: &wire.PingFrame{}, OnLost: func(wire.Frame) { mtuPacketDeclaredLost = true }}},
			}))
			handler.SentPacket(ackElicitingPacket(&Packet{PacketNumber: 2, SendTime: now.Add(-3 * time.Second)}))
			ack := &wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: 2, Largest: 2}}}
			_, err := handler.ReceivedAck(ack, protocol.Encryption1RTT, now.Add(-time.Second))
			Expect(err).ToNot(HaveOccurred())
			Expect(mtuPacketDeclaredLost).To(BeFalse())
			Expect(handler.GetLossDetectionTimeout()).ToNot(BeZero())
			Expect(handler.OnLossDetectionTimeout()).To(Succeed())
			Expect(mtuPacketDeclaredLost).To(BeTrue())
			Expect(handler.GetLossDetectionTimeout()).To(BeZero())
		})
	})

	Context("crypto packets", func() {
		It("rejects an ACK that acks packets with a higher encryption level", func() {
			handler.SentPacket(ackElicitingPacket(&Packet{
				PacketNumber:    13,
				EncryptionLevel: protocol.Encryption1RTT,
			}))
			ack := &wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: 13, Largest: 13}}}
			_, err := handler.ReceivedAck(ack, protocol.EncryptionHandshake, time.Now())
			Expect(err).To(MatchError(&qerr.TransportError{
				ErrorCode:    qerr.ProtocolViolation,
				ErrorMessage: "received ACK for an unsent packet",
			}))
		})

		It("deletes Initial packets, as a server", func() {
			for i := protocol.PacketNumber(0); i < 6; i++ {
				handler.SentPacket(ackElicitingPacket(&Packet{
					PacketNumber:    i,
					EncryptionLevel: protocol.EncryptionInitial,
				}))
			}
			for i := protocol.PacketNumber(0); i < 10; i++ {
				handler.SentPacket(ackElicitingPacket(&Packet{
					PacketNumber:    i,
					EncryptionLevel: protocol.EncryptionHandshake,
				}))
			}
			Expect(handler.bytesInFlight).To(Equal(protocol.ByteCount(16)))
			handler.DropPackets(protocol.EncryptionInitial)
			Expect(lostPackets).To(BeEmpty()) // frames must not be queued for retransmission
			Expect(handler.bytesInFlight).To(Equal(protocol.ByteCount(10)))
			Expect(handler.initialPackets).To(BeNil())
			Expect(handler.handshakePackets.history.Len()).ToNot(BeZero())
		})

		Context("deleting Initials", func() {
			BeforeEach(func() { perspective = protocol.PerspectiveClient })

			It("deletes Initials, as a client", func() {
				for i := protocol.PacketNumber(0); i < 6; i++ {
					handler.SentPacket(ackElicitingPacket(&Packet{
						PacketNumber:    i,
						EncryptionLevel: protocol.EncryptionInitial,
					}))
				}
				Expect(handler.bytesInFlight).To(Equal(protocol.ByteCount(6)))
				handler.DropPackets(protocol.EncryptionInitial)
				// DropPackets should be ignored for clients and the Initial packet number space.
				// It has to be possible to send another Initial packets after this function was called.
				handler.SentPacket(ackElicitingPacket(&Packet{
					PacketNumber:    10,
					EncryptionLevel: protocol.EncryptionInitial,
				}))
				Expect(handler.bytesInFlight).To(Equal(protocol.ByteCount(7)))
				// Sending a Handshake packet triggers dropping of Initials.
				handler.SentPacket(ackElicitingPacket(&Packet{
					PacketNumber:    1,
					EncryptionLevel: protocol.EncryptionHandshake,
				}))
				Expect(handler.bytesInFlight).To(Equal(protocol.ByteCount(1)))
				Expect(lostPackets).To(BeEmpty()) // frames must not be queued for retransmission
				Expect(handler.initialPackets).To(BeNil())
				Expect(handler.handshakePackets.history.Len()).ToNot(BeZero())
			})
		})

		It("deletes Handshake packets", func() {
			for i := protocol.PacketNumber(0); i < 6; i++ {
				handler.SentPacket(ackElicitingPacket(&Packet{
					PacketNumber:    i,
					EncryptionLevel: protocol.EncryptionHandshake,
				}))
			}
			for i := protocol.PacketNumber(0); i < 10; i++ {
				handler.SentPacket(ackElicitingPacket(&Packet{
					PacketNumber:    i,
					EncryptionLevel: protocol.Encryption1RTT,
				}))
			}
			Expect(handler.bytesInFlight).To(Equal(protocol.ByteCount(16)))
			handler.DropPackets(protocol.EncryptionHandshake)
			Expect(lostPackets).To(BeEmpty()) // frames must not be queued for retransmission
			Expect(handler.bytesInFlight).To(Equal(protocol.ByteCount(10)))
			Expect(handler.handshakePackets).To(BeNil())
		})

		It("doesn't retransmit 0-RTT packets when 0-RTT keys are dropped", func() {
			for i := protocol.PacketNumber(0); i < 6; i++ {
				if i == 3 {
					continue
				}
				handler.SentPacket(ackElicitingPacket(&Packet{
					PacketNumber:    i,
					EncryptionLevel: protocol.Encryption0RTT,
				}))
			}
			for i := protocol.PacketNumber(6); i < 12; i++ {
				handler.SentPacket(ackElicitingPacket(&Packet{PacketNumber: i}))
			}
			Expect(handler.bytesInFlight).To(Equal(protocol.ByteCount(11)))
			handler.DropPackets(protocol.Encryption0RTT)
			Expect(lostPackets).To(BeEmpty())
			Expect(handler.bytesInFlight).To(Equal(protocol.ByteCount(6)))
		})

		It("cancels the PTO when dropping a packet number space", func() {
			handler.ReceivedPacket(protocol.EncryptionHandshake)
			now := time.Now()
			handler.SentPacket(handshakePacket(&Packet{PacketNumber: 1, SendTime: now.Add(-time.Minute)}))
			handler.SentPacket(handshakePacket(&Packet{PacketNumber: 2, SendTime: now.Add(-time.Minute)}))
			Expect(handler.GetLossDetectionTimeout()).To(BeTemporally("~", now.Add(-time.Minute), time.Second))
			Expect(handler.OnLossDetectionTimeout()).To(Succeed())
			Expect(handler.SendMode()).To(Equal(SendPTOHandshake))
			Expect(handler.ptoCount).To(BeEquivalentTo(1))
			handler.DropPackets(protocol.EncryptionHandshake)
			Expect(handler.ptoCount).To(BeZero())
			Expect(handler.SendMode()).To(Equal(SendAny))
		})
	})

	Context("peeking and popping packet number", func() {
		It("peeks and pops the initial packet number", func() {
			pn, _ := handler.PeekPacketNumber(protocol.EncryptionInitial)
			Expect(pn).To(Equal(protocol.PacketNumber(42)))
			Expect(handler.PopPacketNumber(protocol.EncryptionInitial)).To(Equal(protocol.PacketNumber(42)))
		})

		It("peeks and pops beyond the initial packet number", func() {
			Expect(handler.PopPacketNumber(protocol.EncryptionInitial)).To(Equal(protocol.PacketNumber(42)))
			Expect(handler.PopPacketNumber(protocol.EncryptionInitial)).To(BeNumerically(">", 42))
		})

		It("starts at 0 for handshake and application-data packet number space", func() {
			pn, _ := handler.PeekPacketNumber(protocol.EncryptionHandshake)
			Expect(pn).To(BeZero())
			Expect(handler.PopPacketNumber(protocol.EncryptionHandshake)).To(BeZero())
			pn, _ = handler.PeekPacketNumber(protocol.Encryption1RTT)
			Expect(pn).To(BeZero())
			Expect(handler.PopPacketNumber(protocol.Encryption1RTT)).To(BeZero())
		})
	})

	Context("for the client", func() {
		BeforeEach(func() {
			perspective = protocol.PerspectiveClient
		})

		It("considers the server's address validated right away", func() {
		})

		It("queues outstanding packets for retransmission, cancels alarms and resets PTO count when receiving a Retry", func() {
			handler.SentPacket(initialPacket(&Packet{PacketNumber: 42}))
			Expect(handler.GetLossDetectionTimeout()).ToNot(BeZero())
			Expect(handler.bytesInFlight).ToNot(BeZero())
			Expect(handler.SendMode()).To(Equal(SendAny))
			// now receive a Retry
			Expect(handler.ResetForRetry()).To(Succeed())
			Expect(lostPackets).To(Equal([]protocol.PacketNumber{42}))
			Expect(handler.bytesInFlight).To(BeZero())
			Expect(handler.GetLossDetectionTimeout()).To(BeZero())
			Expect(handler.SendMode()).To(Equal(SendAny))
			Expect(handler.ptoCount).To(BeZero())
		})

		It("queues outstanding frames for retransmission and cancels alarms when receiving a Retry", func() {
			var lostInitial, lost0RTT bool
			handler.SentPacket(&Packet{
				PacketNumber:    13,
				EncryptionLevel: protocol.EncryptionInitial,
				Frames: []Frame{
					{Frame: &wire.CryptoFrame{Data: []byte("foobar")}, OnLost: func(wire.Frame) { lostInitial = true }},
				},
				Length: 100,
			})
			pn := handler.PopPacketNumber(protocol.Encryption0RTT)
			handler.SentPacket(&Packet{
				PacketNumber:    pn,
				EncryptionLevel: protocol.Encryption0RTT,
				Frames: []Frame{
					{Frame: &wire.StreamFrame{Data: []byte("foobar")}, OnLost: func(wire.Frame) { lost0RTT = true }},
				},
				Length: 999,
			})
			Expect(handler.bytesInFlight).ToNot(BeZero())
			// now receive a Retry
			Expect(handler.ResetForRetry()).To(Succeed())
			Expect(handler.bytesInFlight).To(BeZero())
			Expect(lostInitial).To(BeTrue())
			Expect(lost0RTT).To(BeTrue())

			// make sure we keep increasing the packet number for 0-RTT packets
			Expect(handler.PopPacketNumber(protocol.Encryption0RTT)).To(BeNumerically(">", pn))
		})

		It("uses a Retry for an RTT estimate, if it was not retransmitted", func() {
			handler.SentPacket(ackElicitingPacket(&Packet{
				PacketNumber:    42,
				EncryptionLevel: protocol.EncryptionInitial,
				SendTime:        time.Now().Add(-500 * time.Millisecond),
			}))
			handler.SentPacket(ackElicitingPacket(&Packet{
				PacketNumber:    43,
				EncryptionLevel: protocol.EncryptionInitial,
				SendTime:        time.Now().Add(-10 * time.Millisecond),
			}))
			Expect(handler.ResetForRetry()).To(Succeed())
			Expect(handler.rttStats.SmoothedRTT()).To(BeNumerically("~", 500*time.Millisecond, 100*time.Millisecond))
		})

		It("uses a Retry for an RTT estimate, but doesn't set the RTT to a value lower than 5ms", func() {
			handler.SentPacket(ackElicitingPacket(&Packet{
				PacketNumber:    42,
				EncryptionLevel: protocol.EncryptionInitial,
				SendTime:        time.Now().Add(-500 * time.Microsecond),
			}))
			handler.SentPacket(ackElicitingPacket(&Packet{
				PacketNumber:    43,
				EncryptionLevel: protocol.EncryptionInitial,
				SendTime:        time.Now().Add(-10 * time.Microsecond),
			}))
			Expect(handler.ResetForRetry()).To(Succeed())
			Expect(handler.rttStats.SmoothedRTT()).To(Equal(minRTTAfterRetry))
		})

		It("doesn't use a Retry for an RTT estimate, if it was not retransmitted", func() {
			handler.SentPacket(ackElicitingPacket(&Packet{
				PacketNumber:    42,
				EncryptionLevel: protocol.EncryptionInitial,
				SendTime:        time.Now().Add(-800 * time.Millisecond),
			}))
			Expect(handler.OnLossDetectionTimeout()).To(Succeed())
			Expect(handler.SendMode()).To(Equal(SendPTOInitial))
			handler.SentPacket(ackElicitingPacket(&Packet{
				PacketNumber:    43,
				EncryptionLevel: protocol.EncryptionInitial,
				SendTime:        time.Now().Add(-100 * time.Millisecond),
			}))
			Expect(handler.ResetForRetry()).To(Succeed())
			Expect(handler.rttStats.SmoothedRTT()).To(BeZero())
		})
	})
})
