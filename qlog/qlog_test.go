package qlog

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"os"
	"time"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/qerr"
	"github.com/lucas-clemente/quic-go/internal/utils"
	"github.com/lucas-clemente/quic-go/logging"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

type nopWriteCloserImpl struct{ io.Writer }

func (nopWriteCloserImpl) Close() error { return nil }

func nopWriteCloser(w io.Writer) io.WriteCloser {
	return &nopWriteCloserImpl{Writer: w}
}

type limitedWriter struct {
	io.WriteCloser
	N       int
	written int
}

func (w *limitedWriter) Write(p []byte) (int, error) {
	if w.written+len(p) > w.N {
		return 0, errors.New("writer full")
	}
	n, err := w.WriteCloser.Write(p)
	w.written += n
	return n, err
}

type entry struct {
	Time  time.Time
	Name  string
	Event map[string]interface{}
}

var _ = Describe("Tracing", func() {
	Context("tracer", func() {
		It("returns nil when there's no io.WriteCloser", func() {
			t := NewTracer(func(logging.Perspective, []byte) io.WriteCloser { return nil })
			Expect(t.TracerForConnection(logging.PerspectiveClient, logging.ConnectionID{1, 2, 3, 4})).To(BeNil())
		})
	})

	It("stops writing when encountering an error", func() {
		buf := &bytes.Buffer{}
		t := newConnectionTracer(
			&limitedWriter{WriteCloser: nopWriteCloser(buf), N: 250},
			protocol.PerspectiveServer,
			protocol.ConnectionID{0xde, 0xad, 0xbe, 0xef},
		)
		for i := uint32(0); i < 1000; i++ {
			t.UpdatedPTOCount(i)
		}

		b := &bytes.Buffer{}
		log.SetOutput(b)
		defer log.SetOutput(os.Stdout)
		t.Close()
		Expect(b.String()).To(ContainSubstring("writer full"))
	})

	Context("connection tracer", func() {
		var (
			tracer logging.ConnectionTracer
			buf    *bytes.Buffer
		)

		BeforeEach(func() {
			buf = &bytes.Buffer{}
			t := NewTracer(func(logging.Perspective, []byte) io.WriteCloser { return nopWriteCloser(buf) })
			tracer = t.TracerForConnection(logging.PerspectiveServer, logging.ConnectionID{0xde, 0xad, 0xbe, 0xef})
		})

		It("exports a trace that has the right metadata", func() {
			tracer.Close()

			m := make(map[string]interface{})
			Expect(json.Unmarshal(buf.Bytes(), &m)).To(Succeed())
			Expect(m).To(HaveKeyWithValue("qlog_version", "draft-02"))
			Expect(m).To(HaveKey("title"))
			Expect(m).To(HaveKey("trace"))
			trace := m["trace"].(map[string]interface{})
			Expect(trace).To(HaveKey(("common_fields")))
			commonFields := trace["common_fields"].(map[string]interface{})
			Expect(commonFields).To(HaveKeyWithValue("ODCID", "deadbeef"))
			Expect(commonFields).To(HaveKeyWithValue("group_id", "deadbeef"))
			Expect(commonFields).To(HaveKey("reference_time"))
			referenceTime := time.Unix(0, int64(commonFields["reference_time"].(float64)*1e6))
			Expect(referenceTime).To(BeTemporally("~", time.Now(), scaleDuration(10*time.Millisecond)))
			Expect(trace).To(HaveKey("vantage_point"))
			vantagePoint := trace["vantage_point"].(map[string]interface{})
			Expect(vantagePoint).To(HaveKeyWithValue("type", "server"))
		})

		Context("Events", func() {
			exportAndParse := func() []entry {
				tracer.Close()

				m := make(map[string]interface{})
				line, err := buf.ReadBytes('\n')
				Expect(err).ToNot(HaveOccurred())
				Expect(json.Unmarshal(line, &m)).To(Succeed())
				Expect(m).To(HaveKey("trace"))
				var entries []entry
				trace := m["trace"].(map[string]interface{})
				Expect(trace).To(HaveKey("common_fields"))
				commonFields := trace["common_fields"].(map[string]interface{})
				Expect(commonFields).To(HaveKey("reference_time"))
				referenceTime := time.Unix(0, int64(commonFields["reference_time"].(float64)*1e6))
				Expect(trace).ToNot(HaveKey("events"))

				for buf.Len() > 0 {
					line, err := buf.ReadBytes('\n')
					Expect(err).ToNot(HaveOccurred())
					ev := make(map[string]interface{})
					Expect(json.Unmarshal(line, &ev)).To(Succeed())
					Expect(ev).To(HaveLen(3))
					Expect(ev).To(HaveKey("time"))
					Expect(ev).To(HaveKey("name"))
					Expect(ev).To(HaveKey("data"))
					entries = append(entries, entry{
						Time:  referenceTime.Add(time.Duration(ev["time"].(float64)*1e6) * time.Nanosecond),
						Name:  ev["name"].(string),
						Event: ev["data"].(map[string]interface{}),
					})
				}
				return entries
			}

			exportAndParseSingle := func() entry {
				entries := exportAndParse()
				Expect(entries).To(HaveLen(1))
				return entries[0]
			}

			It("records connection starts", func() {
				tracer.StartedConnection(
					&net.UDPAddr{IP: net.IPv4(192, 168, 13, 37), Port: 42},
					&net.UDPAddr{IP: net.IPv4(192, 168, 12, 34), Port: 24},
					0xdeadbeef,
					protocol.ConnectionID{1, 2, 3, 4},
					protocol.ConnectionID{5, 6, 7, 8},
				)
				entry := exportAndParseSingle()
				Expect(entry.Time).To(BeTemporally("~", time.Now(), scaleDuration(10*time.Millisecond)))
				Expect(entry.Name).To(Equal("transport:connection_started"))
				ev := entry.Event
				Expect(ev).To(HaveKeyWithValue("ip_version", "ipv4"))
				Expect(ev).To(HaveKeyWithValue("src_ip", "192.168.13.37"))
				Expect(ev).To(HaveKeyWithValue("src_port", float64(42)))
				Expect(ev).To(HaveKeyWithValue("dst_ip", "192.168.12.34"))
				Expect(ev).To(HaveKeyWithValue("dst_port", float64(24)))
				Expect(ev).To(HaveKeyWithValue("quic_version", "deadbeef"))
				Expect(ev).To(HaveKeyWithValue("src_cid", "01020304"))
				Expect(ev).To(HaveKeyWithValue("dst_cid", "05060708"))
			})

			It("records idle timeouts", func() {
				tracer.ClosedConnection(logging.NewTimeoutCloseReason(logging.TimeoutReasonIdle))
				entry := exportAndParseSingle()
				Expect(entry.Time).To(BeTemporally("~", time.Now(), scaleDuration(10*time.Millisecond)))
				Expect(entry.Name).To(Equal("transport:connection_closed"))
				ev := entry.Event
				Expect(ev).To(HaveLen(2))
				Expect(ev).To(HaveKeyWithValue("owner", "local"))
				Expect(ev).To(HaveKeyWithValue("trigger", "idle_timeout"))
			})

			It("records handshake timeouts", func() {
				tracer.ClosedConnection(logging.NewTimeoutCloseReason(logging.TimeoutReasonHandshake))
				entry := exportAndParseSingle()
				Expect(entry.Time).To(BeTemporally("~", time.Now(), scaleDuration(10*time.Millisecond)))
				Expect(entry.Name).To(Equal("transport:connection_closed"))
				ev := entry.Event
				Expect(ev).To(HaveLen(2))
				Expect(ev).To(HaveKeyWithValue("owner", "local"))
				Expect(ev).To(HaveKeyWithValue("trigger", "handshake_timeout"))
			})

			It("records a received stateless reset packet", func() {
				tracer.ClosedConnection(logging.NewStatelessResetCloseReason(logging.StatelessResetToken{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}))
				entry := exportAndParseSingle()
				Expect(entry.Time).To(BeTemporally("~", time.Now(), scaleDuration(10*time.Millisecond)))
				Expect(entry.Name).To(Equal("transport:connection_closed"))
				ev := entry.Event
				Expect(ev).To(HaveLen(3))
				Expect(ev).To(HaveKeyWithValue("owner", "remote"))
				Expect(ev).To(HaveKeyWithValue("trigger", "stateless_reset"))
				Expect(ev).To(HaveKeyWithValue("stateless_reset_token", "00112233445566778899aabbccddeeff"))
			})

			It("records application errors", func() {
				tracer.ClosedConnection(logging.NewApplicationCloseReason(1337, true))
				entry := exportAndParseSingle()
				Expect(entry.Time).To(BeTemporally("~", time.Now(), scaleDuration(10*time.Millisecond)))
				Expect(entry.Name).To(Equal("transport:connection_closed"))
				ev := entry.Event
				Expect(ev).To(HaveLen(2))
				Expect(ev).To(HaveKeyWithValue("owner", "remote"))
				Expect(ev).To(HaveKeyWithValue("application_code", float64(1337)))
			})

			It("records transport errors", func() {
				tracer.ClosedConnection(logging.NewTransportCloseReason(qerr.AEADLimitReached, false))
				entry := exportAndParseSingle()
				Expect(entry.Time).To(BeTemporally("~", time.Now(), scaleDuration(10*time.Millisecond)))
				Expect(entry.Name).To(Equal("transport:connection_closed"))
				ev := entry.Event
				Expect(ev).To(HaveLen(2))
				Expect(ev).To(HaveKeyWithValue("owner", "local"))
				Expect(ev).To(HaveKeyWithValue("connection_code", "aead_limit_reached"))
			})

			It("records sent transport parameters", func() {
				tracer.SentTransportParameters(&logging.TransportParameters{
					InitialMaxStreamDataBidiLocal:   1000,
					InitialMaxStreamDataBidiRemote:  2000,
					InitialMaxStreamDataUni:         3000,
					InitialMaxData:                  4000,
					MaxBidiStreamNum:                10,
					MaxUniStreamNum:                 20,
					MaxAckDelay:                     123 * time.Millisecond,
					AckDelayExponent:                12,
					DisableActiveMigration:          true,
					MaxUDPPayloadSize:               1234,
					MaxIdleTimeout:                  321 * time.Millisecond,
					StatelessResetToken:             &protocol.StatelessResetToken{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00},
					OriginalDestinationConnectionID: protocol.ConnectionID{0xde, 0xad, 0xc0, 0xde},
					InitialSourceConnectionID:       protocol.ConnectionID{0xde, 0xad, 0xbe, 0xef},
					RetrySourceConnectionID:         &protocol.ConnectionID{0xde, 0xca, 0xfb, 0xad},
					ActiveConnectionIDLimit:         7,
				})
				entry := exportAndParseSingle()
				Expect(entry.Time).To(BeTemporally("~", time.Now(), scaleDuration(10*time.Millisecond)))
				Expect(entry.Name).To(Equal("transport:parameters_set"))
				ev := entry.Event
				Expect(ev).To(HaveKeyWithValue("owner", "local"))
				Expect(ev).To(HaveKeyWithValue("original_destination_connection_id", "deadc0de"))
				Expect(ev).To(HaveKeyWithValue("initial_source_connection_id", "deadbeef"))
				Expect(ev).To(HaveKeyWithValue("retry_source_connection_id", "decafbad"))
				Expect(ev).To(HaveKeyWithValue("stateless_reset_token", "112233445566778899aabbccddeeff00"))
				Expect(ev).To(HaveKeyWithValue("max_idle_timeout", float64(321)))
				Expect(ev).To(HaveKeyWithValue("max_udp_payload_size", float64(1234)))
				Expect(ev).To(HaveKeyWithValue("ack_delay_exponent", float64(12)))
				Expect(ev).To(HaveKeyWithValue("active_connection_id_limit", float64(7)))
				Expect(ev).To(HaveKeyWithValue("initial_max_data", float64(4000)))
				Expect(ev).To(HaveKeyWithValue("initial_max_stream_data_bidi_local", float64(1000)))
				Expect(ev).To(HaveKeyWithValue("initial_max_stream_data_bidi_remote", float64(2000)))
				Expect(ev).To(HaveKeyWithValue("initial_max_stream_data_uni", float64(3000)))
				Expect(ev).To(HaveKeyWithValue("initial_max_streams_bidi", float64(10)))
				Expect(ev).To(HaveKeyWithValue("initial_max_streams_uni", float64(20)))
				Expect(ev).ToNot(HaveKey("preferred_address"))
			})

			It("records the server's transport parameters, without a stateless reset token", func() {
				tracer.SentTransportParameters(&logging.TransportParameters{
					OriginalDestinationConnectionID: protocol.ConnectionID{0xde, 0xad, 0xc0, 0xde},
					ActiveConnectionIDLimit:         7,
				})
				entry := exportAndParseSingle()
				Expect(entry.Time).To(BeTemporally("~", time.Now(), scaleDuration(10*time.Millisecond)))
				Expect(entry.Name).To(Equal("transport:parameters_set"))
				ev := entry.Event
				Expect(ev).ToNot(HaveKey("stateless_reset_token"))
			})

			It("records transport parameters without retry_source_connection_id", func() {
				tracer.SentTransportParameters(&logging.TransportParameters{
					StatelessResetToken: &protocol.StatelessResetToken{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00},
				})
				entry := exportAndParseSingle()
				Expect(entry.Time).To(BeTemporally("~", time.Now(), scaleDuration(10*time.Millisecond)))
				Expect(entry.Name).To(Equal("transport:parameters_set"))
				ev := entry.Event
				Expect(ev).To(HaveKeyWithValue("owner", "local"))
				Expect(ev).ToNot(HaveKey("retry_source_connection_id"))
			})

			It("records transport parameters with a preferred address", func() {
				tracer.SentTransportParameters(&logging.TransportParameters{
					PreferredAddress: &logging.PreferredAddress{
						IPv4:                net.IPv4(12, 34, 56, 78),
						IPv4Port:            123,
						IPv6:                net.IP{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
						IPv6Port:            456,
						ConnectionID:        protocol.ConnectionID{8, 7, 6, 5, 4, 3, 2, 1},
						StatelessResetToken: protocol.StatelessResetToken{15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0},
					},
				})
				entry := exportAndParseSingle()
				Expect(entry.Time).To(BeTemporally("~", time.Now(), scaleDuration(10*time.Millisecond)))
				Expect(entry.Name).To(Equal("transport:parameters_set"))
				ev := entry.Event
				Expect(ev).To(HaveKeyWithValue("owner", "local"))
				Expect(ev).To(HaveKey("preferred_address"))
				pa := ev["preferred_address"].(map[string]interface{})
				Expect(pa).To(HaveKeyWithValue("ip_v4", "12.34.56.78"))
				Expect(pa).To(HaveKeyWithValue("port_v4", float64(123)))
				Expect(pa).To(HaveKeyWithValue("ip_v6", "102:304:506:708:90a:b0c:d0e:f10"))
				Expect(pa).To(HaveKeyWithValue("port_v6", float64(456)))
				Expect(pa).To(HaveKeyWithValue("connection_id", "0807060504030201"))
				Expect(pa).To(HaveKeyWithValue("stateless_reset_token", "0f0e0d0c0b0a09080706050403020100"))
			})

			It("records received transport parameters", func() {
				tracer.ReceivedTransportParameters(&logging.TransportParameters{})
				entry := exportAndParseSingle()
				Expect(entry.Time).To(BeTemporally("~", time.Now(), scaleDuration(10*time.Millisecond)))
				Expect(entry.Name).To(Equal("transport:parameters_set"))
				ev := entry.Event
				Expect(ev).To(HaveKeyWithValue("owner", "remote"))
				Expect(ev).ToNot(HaveKey("original_destination_connection_id"))
			})

			It("records a sent long header packet, without an ACK", func() {
				tracer.SentLongHeaderPacket(
					&logging.ExtendedHeader{
						Header: logging.Header{
							IsLongHeader:     true,
							Type:             protocol.PacketTypeHandshake,
							DestConnectionID: protocol.ConnectionID{1, 2, 3, 4, 5, 6, 7, 8},
							SrcConnectionID:  protocol.ConnectionID{4, 3, 2, 1},
							Version:          protocol.VersionTLS,
						},
						PacketNumber: 1337,
					},
					987,
					nil,
					[]logging.Frame{
						&logging.MaxStreamDataFrame{StreamID: 42, MaximumStreamData: 987},
						&logging.StreamFrame{StreamID: 123, Offset: 1234, Length: 6, Fin: true},
					},
				)
				entry := exportAndParseSingle()
				Expect(entry.Time).To(BeTemporally("~", time.Now(), scaleDuration(10*time.Millisecond)))
				Expect(entry.Name).To(Equal("transport:packet_sent"))
				ev := entry.Event
				Expect(ev).To(HaveKey("header"))
				hdr := ev["header"].(map[string]interface{})
				Expect(hdr).To(HaveKeyWithValue("packet_type", "handshake"))
				Expect(hdr).To(HaveKeyWithValue("packet_size", float64(987)))
				Expect(hdr).To(HaveKeyWithValue("packet_number", float64(1337)))
				Expect(hdr).To(HaveKeyWithValue("scid", "04030201"))
				Expect(ev).To(HaveKey("frames"))
				frames := ev["frames"].([]interface{})
				Expect(frames).To(HaveLen(2))
				Expect(frames[0].(map[string]interface{})).To(HaveKeyWithValue("frame_type", "max_stream_data"))
				Expect(frames[1].(map[string]interface{})).To(HaveKeyWithValue("frame_type", "stream"))
			})

			It("records a sent long header packet, containing an ACK", func() {
				tracer.SentLongHeaderPacket(
					&logging.ExtendedHeader{
						Header: logging.Header{
							IsLongHeader:     true,
							Type:             protocol.PacketTypeInitial,
							DestConnectionID: protocol.ConnectionID{1, 2, 3, 4},
							Version:          protocol.VersionTLS,
						},
						PacketNumber: 1337,
					},
					123,
					&logging.AckFrame{AckRanges: []logging.AckRange{{Smallest: 1, Largest: 10}}},
					[]logging.Frame{&logging.MaxDataFrame{MaximumData: 987}},
				)
				entry := exportAndParseSingle()
				ev := entry.Event
				Expect(ev).To(HaveKey("header"))
				Expect(ev).To(HaveKey("frames"))
				frames := ev["frames"].([]interface{})
				Expect(frames).To(HaveLen(2))
				Expect(frames[0].(map[string]interface{})).To(HaveKeyWithValue("frame_type", "ack"))
				Expect(frames[1].(map[string]interface{})).To(HaveKeyWithValue("frame_type", "max_data"))
			})

			It("records a sent short header packet, without an ACK", func() {
				tracer.SentShortHeaderPacket(
					protocol.ConnectionID{1, 2, 3, 4, 5, 6, 7, 8},
					1337,
					logging.KeyPhaseOne,
					987,
					nil,
					[]logging.Frame{
						&logging.MaxStreamDataFrame{StreamID: 42, MaximumStreamData: 987},
						&logging.StreamFrame{StreamID: 123, Offset: 1234, Length: 6, Fin: true},
					},
				)
				entry := exportAndParseSingle()
				Expect(entry.Time).To(BeTemporally("~", time.Now(), scaleDuration(10*time.Millisecond)))
				Expect(entry.Name).To(Equal("transport:packet_sent"))
				ev := entry.Event
				Expect(ev).To(HaveKey("header"))
				hdr := ev["header"].(map[string]interface{})
				Expect(hdr).To(HaveKeyWithValue("packet_type", "1RTT"))
				Expect(hdr).To(HaveKeyWithValue("packet_size", float64(987)))
				Expect(hdr).To(HaveKeyWithValue("packet_number", float64(1337)))
				Expect(hdr).To(HaveKeyWithValue("key_phase_bit", "1"))
				Expect(hdr).ToNot(HaveKey("scid"))
				Expect(ev).To(HaveKey("frames"))
				frames := ev["frames"].([]interface{})
				Expect(frames).To(HaveLen(2))
				Expect(frames[0].(map[string]interface{})).To(HaveKeyWithValue("frame_type", "max_stream_data"))
				Expect(frames[1].(map[string]interface{})).To(HaveKeyWithValue("frame_type", "stream"))
			})

			It("records a sent short header packet, containing an ACK", func() {
				tracer.SentShortHeaderPacket(
					protocol.ConnectionID{1, 2, 3, 4},
					1337,
					logging.KeyPhaseOne,
					123,
					&logging.AckFrame{AckRanges: []logging.AckRange{{Smallest: 1, Largest: 10}}},
					[]logging.Frame{&logging.MaxDataFrame{MaximumData: 987}},
				)
				entry := exportAndParseSingle()
				ev := entry.Event
				Expect(ev).To(HaveKey("header"))
				hdr := ev["header"].(map[string]interface{})
				Expect(hdr).To(HaveKeyWithValue("packet_type", "1RTT"))
				Expect(hdr).To(HaveKeyWithValue("packet_number", float64(1337)))
				Expect(ev).To(HaveKey("frames"))
				frames := ev["frames"].([]interface{})
				Expect(frames).To(HaveLen(2))
				Expect(frames[0].(map[string]interface{})).To(HaveKeyWithValue("frame_type", "ack"))
				Expect(frames[1].(map[string]interface{})).To(HaveKeyWithValue("frame_type", "max_data"))
			})

			It("records a received long header packet", func() {
				tracer.ReceivedLongHeaderPacket(
					&logging.ExtendedHeader{
						Header: logging.Header{
							IsLongHeader:     true,
							Type:             protocol.PacketTypeInitial,
							DestConnectionID: protocol.ConnectionID{1, 2, 3, 4, 5, 6, 7, 8},
							SrcConnectionID:  protocol.ConnectionID{4, 3, 2, 1},
							Token:            []byte{0xde, 0xad, 0xbe, 0xef},
							Version:          protocol.VersionTLS,
						},
						PacketNumber: 1337,
					},
					789,
					[]logging.Frame{
						&logging.MaxStreamDataFrame{StreamID: 42, MaximumStreamData: 987},
						&logging.StreamFrame{StreamID: 123, Offset: 1234, Length: 6, Fin: true},
					},
				)
				entry := exportAndParseSingle()
				Expect(entry.Time).To(BeTemporally("~", time.Now(), scaleDuration(10*time.Millisecond)))
				Expect(entry.Name).To(Equal("transport:packet_received"))
				ev := entry.Event
				Expect(ev).To(HaveKey("header"))
				hdr := ev["header"].(map[string]interface{})
				Expect(hdr).To(HaveKeyWithValue("packet_type", "initial"))
				Expect(hdr).To(HaveKeyWithValue("packet_size", float64(789)))
				Expect(hdr).To(HaveKeyWithValue("packet_number", float64(1337)))
				Expect(hdr).To(HaveKeyWithValue("scid", "04030201"))
				Expect(hdr).To(HaveKey("token"))
				token := hdr["token"].(map[string]interface{})
				Expect(token).To(HaveKeyWithValue("data", "deadbeef"))
				Expect(ev).To(HaveKey("frames"))
				Expect(ev["frames"].([]interface{})).To(HaveLen(2))
			})

			It("records a received short header packet", func() {
				tracer.ReceivedShortHeaderPacket(
					protocol.ConnectionID{1, 2, 3, 4, 5, 6, 7, 8},
					1337,
					logging.KeyPhaseOne,
					789,
					[]logging.Frame{
						&logging.MaxStreamDataFrame{StreamID: 42, MaximumStreamData: 987},
						&logging.StreamFrame{StreamID: 123, Offset: 1234, Length: 6, Fin: true},
					},
				)
				entry := exportAndParseSingle()
				Expect(entry.Time).To(BeTemporally("~", time.Now(), scaleDuration(10*time.Millisecond)))
				Expect(entry.Name).To(Equal("transport:packet_received"))
				ev := entry.Event
				Expect(ev).To(HaveKey("header"))
				hdr := ev["header"].(map[string]interface{})
				Expect(hdr).To(HaveKeyWithValue("packet_type", "1RTT"))
				Expect(hdr).To(HaveKeyWithValue("packet_size", float64(789)))
				Expect(hdr).To(HaveKeyWithValue("packet_number", float64(1337)))
				Expect(hdr).To(HaveKeyWithValue("key_phase_bit", "1"))
				Expect(hdr).ToNot(HaveKey("scid"))
				Expect(ev).To(HaveKey("frames"))
				Expect(ev["frames"].([]interface{})).To(HaveLen(2))
			})

			It("records a received Retry packet", func() {
				tracer.ReceivedRetry(
					&logging.Header{
						IsLongHeader:     true,
						Type:             protocol.PacketTypeRetry,
						DestConnectionID: protocol.ConnectionID{1, 2, 3, 4, 5, 6, 7, 8},
						SrcConnectionID:  protocol.ConnectionID{4, 3, 2, 1},
						Token:            []byte{0xde, 0xad, 0xbe, 0xef},
						Version:          protocol.VersionTLS,
					},
				)
				entry := exportAndParseSingle()
				Expect(entry.Time).To(BeTemporally("~", time.Now(), scaleDuration(10*time.Millisecond)))
				Expect(entry.Name).To(Equal("transport:packet_received"))
				ev := entry.Event
				Expect(ev).To(HaveKey("header"))
				header := ev["header"].(map[string]interface{})
				Expect(header).To(HaveKeyWithValue("packet_type", "retry"))
				Expect(header).ToNot(HaveKey("packet_number"))
				Expect(header).To(HaveKey("version"))
				Expect(header).To(HaveKey("dcid"))
				Expect(header).To(HaveKey("scid"))
				Expect(header).To(HaveKey("token"))
				token := header["token"].(map[string]interface{})
				Expect(token).To(HaveKeyWithValue("data", "deadbeef"))
				Expect(ev).ToNot(HaveKey("frames"))
			})

			It("records a received Version Negotiation packet", func() {
				tracer.ReceivedVersionNegotiationPacket(
					&logging.Header{
						IsLongHeader:     true,
						Type:             protocol.PacketTypeRetry,
						DestConnectionID: protocol.ConnectionID{1, 2, 3, 4, 5, 6, 7, 8},
						SrcConnectionID:  protocol.ConnectionID{4, 3, 2, 1},
					},
					[]protocol.VersionNumber{0xdeadbeef, 0xdecafbad},
				)
				entry := exportAndParseSingle()
				Expect(entry.Time).To(BeTemporally("~", time.Now(), scaleDuration(10*time.Millisecond)))
				Expect(entry.Name).To(Equal("transport:packet_received"))
				ev := entry.Event
				Expect(ev).To(HaveKey("header"))
				Expect(ev).ToNot(HaveKey("frames"))
				Expect(ev).To(HaveKey("supported_versions"))
				Expect(ev["supported_versions"].([]interface{})).To(Equal([]interface{}{"deadbeef", "decafbad"}))
				header := ev["header"]
				Expect(header).To(HaveKeyWithValue("packet_type", "version_negotiation"))
				Expect(header).ToNot(HaveKey("packet_number"))
				Expect(header).ToNot(HaveKey("version"))
				Expect(header).To(HaveKey("dcid"))
				Expect(header).To(HaveKey("scid"))
			})

			It("records buffered packets", func() {
				tracer.BufferedPacket(logging.PacketTypeHandshake)
				entry := exportAndParseSingle()
				Expect(entry.Time).To(BeTemporally("~", time.Now(), scaleDuration(10*time.Millisecond)))
				Expect(entry.Name).To(Equal("transport:packet_buffered"))
				ev := entry.Event
				Expect(ev).To(HaveKeyWithValue("packet_type", "handshake"))
				Expect(ev).To(HaveKeyWithValue("trigger", "keys_unavailable"))
			})

			It("records dropped packets", func() {
				tracer.DroppedPacket(logging.PacketTypeHandshake, 1337, logging.PacketDropPayloadDecryptError)
				entry := exportAndParseSingle()
				Expect(entry.Time).To(BeTemporally("~", time.Now(), scaleDuration(10*time.Millisecond)))
				Expect(entry.Name).To(Equal("transport:packet_dropped"))
				ev := entry.Event
				Expect(ev).To(HaveKeyWithValue("packet_type", "handshake"))
				Expect(ev).To(HaveKeyWithValue("packet_size", float64(1337)))
				Expect(ev).To(HaveKeyWithValue("trigger", "payload_decrypt_error"))
			})

			It("records metrics updates", func() {
				now := time.Now()
				rttStats := utils.NewRTTStats()
				rttStats.UpdateRTT(15*time.Millisecond, 0, now)
				rttStats.UpdateRTT(20*time.Millisecond, 0, now)
				rttStats.UpdateRTT(25*time.Millisecond, 0, now)
				Expect(rttStats.MinRTT()).To(Equal(15 * time.Millisecond))
				Expect(rttStats.SmoothedRTT()).To(And(
					BeNumerically(">", 15*time.Millisecond),
					BeNumerically("<", 25*time.Millisecond),
				))
				Expect(rttStats.LatestRTT()).To(Equal(25 * time.Millisecond))
				tracer.UpdatedMetrics(
					rttStats,
					4321,
					1234,
					42,
				)
				entry := exportAndParseSingle()
				Expect(entry.Time).To(BeTemporally("~", time.Now(), scaleDuration(10*time.Millisecond)))
				Expect(entry.Name).To(Equal("recovery:metrics_updated"))
				ev := entry.Event
				Expect(ev).To(HaveKeyWithValue("min_rtt", float64(15)))
				Expect(ev).To(HaveKeyWithValue("latest_rtt", float64(25)))
				Expect(ev).To(HaveKey("smoothed_rtt"))
				Expect(time.Duration(ev["smoothed_rtt"].(float64)) * time.Millisecond).To(BeNumerically("~", rttStats.SmoothedRTT(), time.Millisecond))
				Expect(ev).To(HaveKey("rtt_variance"))
				Expect(time.Duration(ev["rtt_variance"].(float64)) * time.Millisecond).To(BeNumerically("~", rttStats.MeanDeviation(), time.Millisecond))
				Expect(ev).To(HaveKeyWithValue("congestion_window", float64(4321)))
				Expect(ev).To(HaveKeyWithValue("bytes_in_flight", float64(1234)))
				Expect(ev).To(HaveKeyWithValue("packets_in_flight", float64(42)))
			})

			It("only logs the diff between two metrics updates", func() {
				now := time.Now()
				rttStats := utils.NewRTTStats()
				rttStats.UpdateRTT(15*time.Millisecond, 0, now)
				rttStats.UpdateRTT(20*time.Millisecond, 0, now)
				rttStats.UpdateRTT(25*time.Millisecond, 0, now)
				Expect(rttStats.MinRTT()).To(Equal(15 * time.Millisecond))

				rttStats2 := utils.NewRTTStats()
				rttStats2.UpdateRTT(15*time.Millisecond, 0, now)
				rttStats2.UpdateRTT(15*time.Millisecond, 0, now)
				rttStats2.UpdateRTT(15*time.Millisecond, 0, now)
				Expect(rttStats2.MinRTT()).To(Equal(15 * time.Millisecond))

				Expect(rttStats.LatestRTT()).To(Equal(25 * time.Millisecond))
				tracer.UpdatedMetrics(
					rttStats,
					4321,
					1234,
					42,
				)
				tracer.UpdatedMetrics(
					rttStats2,
					4321,
					12345, // changed
					42,
				)
				entries := exportAndParse()
				Expect(entries).To(HaveLen(2))
				Expect(entries[0].Time).To(BeTemporally("~", time.Now(), scaleDuration(10*time.Millisecond)))
				Expect(entries[0].Name).To(Equal("recovery:metrics_updated"))
				Expect(entries[0].Event).To(HaveLen(7))
				Expect(entries[1].Time).To(BeTemporally("~", time.Now(), scaleDuration(10*time.Millisecond)))
				Expect(entries[1].Name).To(Equal("recovery:metrics_updated"))
				ev := entries[1].Event
				Expect(ev).ToNot(HaveKey("min_rtt"))
				Expect(ev).ToNot(HaveKey("congestion_window"))
				Expect(ev).ToNot(HaveKey("packets_in_flight"))
				Expect(ev).To(HaveKeyWithValue("bytes_in_flight", float64(12345)))
				Expect(ev).To(HaveKeyWithValue("smoothed_rtt", float64(15)))
			})

			It("records lost packets", func() {
				tracer.LostPacket(protocol.EncryptionHandshake, 42, logging.PacketLossReorderingThreshold)
				entry := exportAndParseSingle()
				Expect(entry.Time).To(BeTemporally("~", time.Now(), scaleDuration(10*time.Millisecond)))
				Expect(entry.Name).To(Equal("recovery:packet_lost"))
				ev := entry.Event
				Expect(ev).To(HaveKeyWithValue("packet_type", "handshake"))
				Expect(ev).To(HaveKeyWithValue("packet_number", float64(42)))
				Expect(ev).To(HaveKeyWithValue("trigger", "reordering_threshold"))
			})

			It("records congestion state updates", func() {
				tracer.UpdatedCongestionState(logging.CongestionStateCongestionAvoidance)
				entry := exportAndParseSingle()
				Expect(entry.Time).To(BeTemporally("~", time.Now(), scaleDuration(10*time.Millisecond)))
				Expect(entry.Name).To(Equal("recovery:congestion_state_updated"))
				ev := entry.Event
				Expect(ev).To(HaveKeyWithValue("new", "congestion_avoidance"))
			})

			It("records PTO changes", func() {
				tracer.UpdatedPTOCount(42)
				entry := exportAndParseSingle()
				Expect(entry.Time).To(BeTemporally("~", time.Now(), scaleDuration(10*time.Millisecond)))
				Expect(entry.Name).To(Equal("recovery:metrics_updated"))
				Expect(entry.Event).To(HaveKeyWithValue("pto_count", float64(42)))
			})

			It("records TLS key updates", func() {
				tracer.UpdatedKeyFromTLS(protocol.EncryptionHandshake, protocol.PerspectiveClient)
				entry := exportAndParseSingle()
				Expect(entry.Time).To(BeTemporally("~", time.Now(), scaleDuration(10*time.Millisecond)))
				Expect(entry.Name).To(Equal("security:key_updated"))
				ev := entry.Event
				Expect(ev).To(HaveKeyWithValue("key_type", "client_handshake_secret"))
				Expect(ev).To(HaveKeyWithValue("trigger", "tls"))
				Expect(ev).ToNot(HaveKey("generation"))
				Expect(ev).ToNot(HaveKey("old"))
				Expect(ev).ToNot(HaveKey("new"))
			})

			It("records TLS key updates, for 1-RTT keys", func() {
				tracer.UpdatedKeyFromTLS(protocol.Encryption1RTT, protocol.PerspectiveServer)
				entry := exportAndParseSingle()
				Expect(entry.Time).To(BeTemporally("~", time.Now(), scaleDuration(10*time.Millisecond)))
				Expect(entry.Name).To(Equal("security:key_updated"))
				ev := entry.Event
				Expect(ev).To(HaveKeyWithValue("key_type", "server_1rtt_secret"))
				Expect(ev).To(HaveKeyWithValue("trigger", "tls"))
				Expect(ev).To(HaveKeyWithValue("generation", float64(0)))
				Expect(ev).ToNot(HaveKey("old"))
				Expect(ev).ToNot(HaveKey("new"))
			})

			It("records QUIC key updates", func() {
				tracer.UpdatedKey(1337, true)
				entries := exportAndParse()
				Expect(entries).To(HaveLen(2))
				var keyTypes []string
				for _, entry := range entries {
					Expect(entry.Time).To(BeTemporally("~", time.Now(), scaleDuration(10*time.Millisecond)))
					Expect(entry.Name).To(Equal("security:key_updated"))
					ev := entry.Event
					Expect(ev).To(HaveKeyWithValue("generation", float64(1337)))
					Expect(ev).To(HaveKeyWithValue("trigger", "remote_update"))
					Expect(ev).To(HaveKey("key_type"))
					keyTypes = append(keyTypes, ev["key_type"].(string))
				}
				Expect(keyTypes).To(ContainElement("server_1rtt_secret"))
				Expect(keyTypes).To(ContainElement("client_1rtt_secret"))
			})

			It("records dropped encryption levels", func() {
				tracer.DroppedEncryptionLevel(protocol.EncryptionInitial)
				entries := exportAndParse()
				Expect(entries).To(HaveLen(2))
				var keyTypes []string
				for _, entry := range entries {
					Expect(entry.Time).To(BeTemporally("~", time.Now(), scaleDuration(10*time.Millisecond)))
					Expect(entry.Name).To(Equal("security:key_retired"))
					ev := entry.Event
					Expect(ev).To(HaveKeyWithValue("trigger", "tls"))
					Expect(ev).To(HaveKey("key_type"))
					keyTypes = append(keyTypes, ev["key_type"].(string))
				}
				Expect(keyTypes).To(ContainElement("server_initial_secret"))
				Expect(keyTypes).To(ContainElement("client_initial_secret"))
			})

			It("records dropped keys", func() {
				tracer.DroppedKey(42)
				entries := exportAndParse()
				Expect(entries).To(HaveLen(2))
				var keyTypes []string
				for _, entry := range entries {
					Expect(entry.Time).To(BeTemporally("~", time.Now(), scaleDuration(10*time.Millisecond)))
					Expect(entry.Name).To(Equal("security:key_retired"))
					ev := entry.Event
					Expect(ev).To(HaveKeyWithValue("generation", float64(42)))
					Expect(ev).ToNot(HaveKey("trigger"))
					Expect(ev).To(HaveKey("key_type"))
					keyTypes = append(keyTypes, ev["key_type"].(string))
				}
				Expect(keyTypes).To(ContainElement("server_1rtt_secret"))
				Expect(keyTypes).To(ContainElement("client_1rtt_secret"))
			})

			It("records when the timer is set", func() {
				timeout := time.Now().Add(137 * time.Millisecond)
				tracer.SetLossTimer(logging.TimerTypePTO, protocol.EncryptionHandshake, timeout)
				entry := exportAndParseSingle()
				Expect(entry.Time).To(BeTemporally("~", time.Now(), scaleDuration(10*time.Millisecond)))
				Expect(entry.Name).To(Equal("recovery:loss_timer_updated"))
				ev := entry.Event
				Expect(ev).To(HaveLen(4))
				Expect(ev).To(HaveKeyWithValue("event_type", "set"))
				Expect(ev).To(HaveKeyWithValue("timer_type", "pto"))
				Expect(ev).To(HaveKeyWithValue("packet_number_space", "handshake"))
				Expect(ev).To(HaveKey("delta"))
				delta := time.Duration(ev["delta"].(float64)*1e6) * time.Nanosecond
				Expect(entry.Time.Add(delta)).To(BeTemporally("~", timeout, 10*time.Microsecond))
			})

			It("records when the loss timer expires", func() {
				tracer.LossTimerExpired(logging.TimerTypeACK, protocol.Encryption1RTT)
				entry := exportAndParseSingle()
				Expect(entry.Time).To(BeTemporally("~", time.Now(), scaleDuration(10*time.Millisecond)))
				Expect(entry.Name).To(Equal("recovery:loss_timer_updated"))
				ev := entry.Event
				Expect(ev).To(HaveLen(3))
				Expect(ev).To(HaveKeyWithValue("event_type", "expired"))
				Expect(ev).To(HaveKeyWithValue("timer_type", "ack"))
				Expect(ev).To(HaveKeyWithValue("packet_number_space", "application_data"))
			})

			It("records when the timer is canceled", func() {
				tracer.LossTimerCanceled()
				entry := exportAndParseSingle()
				Expect(entry.Time).To(BeTemporally("~", time.Now(), scaleDuration(10*time.Millisecond)))
				Expect(entry.Name).To(Equal("recovery:loss_timer_updated"))
				ev := entry.Event
				Expect(ev).To(HaveLen(1))
				Expect(ev).To(HaveKeyWithValue("event_type", "cancelled"))
			})

			It("records a generic event", func() {
				tracer.Debug("foo", "bar")
				entry := exportAndParseSingle()
				Expect(entry.Time).To(BeTemporally("~", time.Now(), scaleDuration(10*time.Millisecond)))
				Expect(entry.Name).To(Equal("transport:foo"))
				ev := entry.Event
				Expect(ev).To(HaveLen(1))
				Expect(ev).To(HaveKeyWithValue("details", "bar"))
			})
		})
	})
})
