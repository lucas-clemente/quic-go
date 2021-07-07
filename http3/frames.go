package http3

import (
	"bytes"
	"fmt"
	"io"
	"io/ioutil"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/quicvarint"
)

type byteReader interface {
	io.ByteReader
	io.Reader
}

type byteReaderImpl struct{ io.Reader }

func (br *byteReaderImpl) ReadByte() (byte, error) {
	b := make([]byte, 1)
	if _, err := br.Reader.Read(b); err != nil {
		return 0, err
	}
	return b[0], nil
}

const (
	frameTypeData               = 0x0
	frameTypeHeaders            = 0x1
	frameTypeSettings           = 0x4
	frameTypeWebTransportStream = 0x41 // Client-initiated bidirectional stream
)

type frame interface{}

func parseNextFrame(b io.Reader) (frame, error) {
	br, ok := b.(byteReader)
	if !ok {
		br = &byteReaderImpl{b}
	}
	t, err := quicvarint.Read(br)
	if err != nil {
		return nil, err
	}
	l, err := quicvarint.Read(br)
	if err != nil {
		return nil, err
	}

	switch t {
	case frameTypeData:
		return &dataFrame{Length: l}, nil
	case frameTypeHeaders:
		return &headersFrame{Length: l}, nil
	case frameTypeSettings:
		return parseSettingsFrame(br, l)
	case frameTypeWebTransportStream: // WEBTRANSPORT_STREAM
		return &webTransportStreamFrame{StreamID: protocol.StreamID(l)}, nil
	case 0x3: // CANCEL_PUSH
		fallthrough
	case 0x5: // PUSH_PROMISE
		fallthrough
	case 0x7: // GOAWAY
		fallthrough
	case 0xd: // MAX_PUSH_ID
		fallthrough
	case 0xe: // DUPLICATE_PUSH
		fallthrough
	default:
		// skip over unknown frames
		if _, err := io.CopyN(ioutil.Discard, br, int64(l)); err != nil {
			return nil, err
		}
		return parseNextFrame(b)
	}
}

type dataFrame struct {
	Length uint64
}

func (f *dataFrame) Write(b *bytes.Buffer) {
	quicvarint.Write(b, frameTypeData)
	quicvarint.Write(b, f.Length)
}

type headersFrame struct {
	Length uint64
}

func (f *headersFrame) Write(b *bytes.Buffer) {
	quicvarint.Write(b, frameTypeHeaders)
	quicvarint.Write(b, f.Length)
}

const (
	settingDatagram = 0x276

	// https://datatracker.ietf.org/doc/html/draft-ietf-webtrans-http3#section-7.2
	settingWebTransport = 0x2b603742
)

type settingsFrame struct {
	Datagram     bool
	WebTransport bool
	other        map[uint64]uint64 // all settings that we don't explicitly recognize
}

func parseSettingsFrame(r io.Reader, l uint64) (*settingsFrame, error) {
	if l > 8*(1<<10) {
		return nil, fmt.Errorf("unexpected size for SETTINGS frame: %d", l)
	}
	buf := make([]byte, l)
	if _, err := io.ReadFull(r, buf); err != nil {
		if err == io.ErrUnexpectedEOF {
			return nil, io.EOF
		}
		return nil, err
	}
	frame := &settingsFrame{}
	b := bytes.NewReader(buf)
	var readDatagram, readWebTransport bool
	for b.Len() > 0 {
		id, err := quicvarint.Read(b)
		if err != nil { // should not happen. We allocated the whole frame already.
			return nil, err
		}
		val, err := quicvarint.Read(b)
		if err != nil { // should not happen. We allocated the whole frame already.
			return nil, err
		}

		switch id {
		case settingDatagram:
			if readDatagram {
				return nil, fmt.Errorf("duplicate setting: %d", id)
			}
			readDatagram = true
			if val != 0 && val != 1 {
				return nil, fmt.Errorf("invalid value for H3_DATAGRAM: %d", val)
			}
			frame.Datagram = val == 1
		case settingWebTransport:
			if readWebTransport {
				return nil, fmt.Errorf("duplicate setting: %d", id)
			}
			readWebTransport = true
			if val != 0 && val != 1 {
				return nil, fmt.Errorf("invalid value for ENABLE_WEBTRANSPORT: %d", val)
			}
			frame.WebTransport = val == 1
		default:
			// Ignore reserved setting IDs of the form 0x1f * N + 0x21.
			// https://datatracker.ietf.org/doc/html/draft-ietf-quic-http-34#section-7.2.4.1
			if (id-0x21)%0x1f == 0 {
				continue
			}
			if _, ok := frame.other[id]; ok {
				return nil, fmt.Errorf("duplicate setting: %d", id)
			}
			if frame.other == nil {
				frame.other = make(map[uint64]uint64)
			}
			frame.other[id] = val
		}
	}
	return frame, nil
}

func (f *settingsFrame) Write(b *bytes.Buffer) {
	quicvarint.Write(b, frameTypeSettings)
	var l protocol.ByteCount
	for id, val := range f.other {
		l += quicvarint.Len(id) + quicvarint.Len(val)
	}
	if f.Datagram {
		l += quicvarint.Len(settingDatagram) + quicvarint.Len(1)
	}
	if f.WebTransport {
		l += quicvarint.Len(settingWebTransport) + quicvarint.Len(1)
	}
	quicvarint.Write(b, uint64(l))
	if f.Datagram {
		quicvarint.Write(b, settingDatagram)
		quicvarint.Write(b, 1)
	}
	if f.WebTransport {
		quicvarint.Write(b, settingWebTransport)
		quicvarint.Write(b, 1)
	}
	for id, val := range f.other {
		quicvarint.Write(b, id)
		quicvarint.Write(b, val)
	}
}

// https://tools.ietf.org/id/draft-vvv-webtransport-http3-03.html#name-client-initiated-bidirectio
type webTransportStreamFrame struct {
	StreamID protocol.StreamID
}

func (f *webTransportStreamFrame) Write(b *bytes.Buffer) {
	quicvarint.Write(b, frameTypeWebTransportStream)
	quicvarint.Write(b, uint64(f.StreamID))
}
