package metrics

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/lucas-clemente/quic-go/internal/utils"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/logging"

	"go.opencensus.io/stats"
	"go.opencensus.io/stats/view"
	"go.opencensus.io/tag"
)

// Measures
var (
	connections = stats.Int64("quic-go/connections", "number of QUIC connections", stats.UnitDimensionless)
	lostPackets = stats.Int64("quic-go/lost-packets", "number of packets declared lost", stats.UnitDimensionless)
	sentPackets = stats.Int64("quic-go/sent-packets", "number of packets sent", stats.UnitDimensionless)
	ptos        = stats.Int64("quic-go/ptos", "number of times the PTO timer fired", stats.UnitDimensionless)
	closes      = stats.Int64("quic-go/close", "number of connections closed", stats.UnitDimensionless)
)

// Tags
var (
	keyPerspective, _      = tag.NewKey("perspective")
	keyIPVersion, _        = tag.NewKey("ip_version")
	keyEncryptionLevel, _  = tag.NewKey("encryption_level")
	keyPacketLossReason, _ = tag.NewKey("packet_loss_reason")
	keyPacketType, _       = tag.NewKey("packet_type")
	keyCloseReason, _      = tag.NewKey("close_reason")
	keyCloseRemote, _      = tag.NewKey("close_remote")
	keyErrorCode, _        = tag.NewKey("error_code")
	keyHandshakePhase, _   = tag.NewKey("handshake_phase")
)

// Views
var (
	ConnectionsView = &view.View{
		Measure:     connections,
		TagKeys:     []tag.Key{keyPerspective, keyIPVersion},
		Aggregation: view.Count(),
	}
	LostPacketsView = &view.View{
		Measure:     lostPackets,
		TagKeys:     []tag.Key{keyEncryptionLevel, keyPacketLossReason},
		Aggregation: view.Count(),
	}
	SentPacketsView = &view.View{
		Measure:     sentPackets,
		TagKeys:     []tag.Key{keyPacketType},
		Aggregation: view.Count(),
	}
	PTOView = &view.View{
		Measure:     ptos,
		TagKeys:     []tag.Key{keyHandshakePhase},
		Aggregation: view.Count(),
	}
	CloseView = &view.View{
		Measure:     closes,
		TagKeys:     []tag.Key{keyCloseReason, keyErrorCode},
		Aggregation: view.Count(),
	}
)

// DefaultViews collects all OpenCensus views for metric gathering purposes
var DefaultViews = []*view.View{
	ConnectionsView,
	LostPacketsView,
	SentPacketsView,
	CloseView,
}

type tracer struct{}

var _ logging.Tracer = &tracer{}

// NewTracer creates a new metrics tracer.
func NewTracer() logging.Tracer { return &tracer{} }

func (t *tracer) TracerForConnection(p logging.Perspective, _ logging.ConnectionID) logging.ConnectionTracer {
	return newConnTracer(t, p)
}

func (t *tracer) SentPacket(_ net.Addr, hdr *logging.Header, _ protocol.ByteCount, _ []logging.Frame) {
	stats.RecordWithTags(
		context.Background(),
		[]tag.Mutator{
			tag.Upsert(keyPacketType, packetType(logging.PacketTypeFromHeader(hdr)).String()),
		},
		sentPackets.M(1),
	)
}

func (t *tracer) DroppedPacket(net.Addr, logging.PacketType, logging.ByteCount, logging.PacketDropReason) {
}

type connTracer struct {
	perspective logging.Perspective
	tracer      logging.Tracer

	handshakeComplete bool
}

func newConnTracer(tracer logging.Tracer, perspective logging.Perspective) logging.ConnectionTracer {
	return &connTracer{
		perspective: perspective,
		tracer:      tracer,
	}
}

var _ logging.ConnectionTracer = &connTracer{}

func (t *connTracer) StartedConnection(local, _ net.Addr, _ logging.VersionNumber, _, _ logging.ConnectionID) {
	perspectiveTag := tag.Upsert(keyPerspective, perspective(t.perspective).String())

	var ipVersionTag tag.Mutator
	if udpAddr, ok := local.(*net.UDPAddr); ok {
		if utils.IsIPv4(udpAddr.IP) {
			ipVersionTag = tag.Upsert(keyIPVersion, "IPv4")
		} else {
			ipVersionTag = tag.Upsert(keyIPVersion, "IPv6")
		}
	} else {
		ipVersionTag = tag.Upsert(keyIPVersion, "unknown")
	}

	stats.RecordWithTags(
		context.Background(),
		[]tag.Mutator{perspectiveTag, ipVersionTag},
		connections.M(1),
	)
}

func (t *connTracer) ClosedConnection(r logging.CloseReason) {
	var tags []tag.Mutator
	if timeout, ok := r.Timeout(); ok {
		tags = []tag.Mutator{
			tag.Upsert(keyCloseReason, timeoutReason(timeout).String()),
			tag.Upsert(keyCloseRemote, "false"),
		}
	} else if _, ok := r.StatelessReset(); ok {
		tags = []tag.Mutator{
			tag.Upsert(keyCloseReason, "stateless_reset"),
			tag.Upsert(keyCloseRemote, "true"),
		}
	} else if errorCode, remote, ok := r.ApplicationError(); ok {
		tags = []tag.Mutator{
			tag.Upsert(keyCloseReason, "application_error"),
			tag.Upsert(keyErrorCode, errorCode.String()),
			tag.Upsert(keyCloseRemote, fmt.Sprintf("%t", remote)),
		}
	} else if errorCode, remote, ok := r.TransportError(); ok {
		tags = []tag.Mutator{
			tag.Upsert(keyCloseReason, "transport_error"),
			tag.Upsert(keyErrorCode, errorCode.String()),
			tag.Upsert(keyCloseRemote, fmt.Sprintf("%t", remote)),
		}
	}
	stats.RecordWithTags(context.Background(), tags, closes.M(1))
}
func (t *connTracer) SentTransportParameters(*logging.TransportParameters)     {}
func (t *connTracer) ReceivedTransportParameters(*logging.TransportParameters) {}
func (t *connTracer) SentLongHeaderPacket(hdr *logging.ExtendedHeader, _ logging.ByteCount, _ *logging.AckFrame, _ []logging.Frame) {
	typ := logging.PacketTypeFromHeader(&hdr.Header)

	stats.RecordWithTags(
		context.Background(),
		[]tag.Mutator{
			tag.Upsert(keyPacketType, packetType(typ).String()),
		},
		sentPackets.M(1),
	)
}

func (t *connTracer) SentShortHeaderPacket(logging.ConnectionID, logging.PacketNumber, logging.KeyPhaseBit, logging.ByteCount, *logging.AckFrame, []logging.Frame) {
	t.handshakeComplete = true
	stats.RecordWithTags(
		context.Background(),
		[]tag.Mutator{
			tag.Upsert(keyPacketType, packetType(logging.PacketType1RTT).String()),
		},
		sentPackets.M(1),
	)
}
func (t *connTracer) ReceivedVersionNegotiationPacket(*logging.Header, []logging.VersionNumber) {}
func (t *connTracer) ReceivedRetry(*logging.Header)                                             {}
func (t *connTracer) ReceivedLongHeaderPacket(*logging.ExtendedHeader, logging.ByteCount, []logging.Frame) {
}

func (t *connTracer) ReceivedShortHeaderPacket(logging.ConnectionID, logging.PacketNumber, logging.KeyPhaseBit, logging.ByteCount, []logging.Frame) {
}
func (t *connTracer) BufferedPacket(logging.PacketType)                                             {}
func (t *connTracer) DroppedPacket(logging.PacketType, logging.ByteCount, logging.PacketDropReason) {}
func (t *connTracer) UpdatedCongestionState(logging.CongestionState)                                {}
func (t *connTracer) UpdatedMetrics(*logging.RTTStats, logging.ByteCount, logging.ByteCount, int)   {}
func (t *connTracer) LostPacket(encLevel logging.EncryptionLevel, _ logging.PacketNumber, reason logging.PacketLossReason) {
	stats.RecordWithTags(
		context.Background(),
		[]tag.Mutator{
			tag.Upsert(keyEncryptionLevel, encryptionLevel(encLevel).String()),
			tag.Upsert(keyPacketLossReason, packetLossReason(reason).String()),
		},
		lostPackets.M(1),
	)
}

func (t *connTracer) UpdatedPTOCount(value uint32) {
	if value == 0 {
		return
	}
	phase := "during_handshake"
	if t.handshakeComplete {
		phase = "after_handshake"
	}
	stats.RecordWithTags(
		context.Background(),
		[]tag.Mutator{tag.Upsert(keyHandshakePhase, phase)},
		ptos.M(1),
	)
}
func (t *connTracer) UpdatedKeyFromTLS(logging.EncryptionLevel, logging.Perspective)     {}
func (t *connTracer) UpdatedKey(logging.KeyPhase, bool)                                  {}
func (t *connTracer) DroppedEncryptionLevel(logging.EncryptionLevel)                     {}
func (t *connTracer) DroppedKey(logging.KeyPhase)                                        {}
func (t *connTracer) SetLossTimer(logging.TimerType, logging.EncryptionLevel, time.Time) {}
func (t *connTracer) LossTimerExpired(logging.TimerType, logging.EncryptionLevel)        {}
func (t *connTracer) LossTimerCanceled()                                                 {}
func (t *connTracer) Debug(string, string)                                               {}
func (t *connTracer) Close()                                                             {}
