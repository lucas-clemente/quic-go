package wire

import (
	"bytes"
	"errors"
	"fmt"
	"io"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"
)

// IsLongHeader says if a packet is a long header packet.
func IsLongHeader(firstByte byte) bool {
	return firstByte&0x80 > 0
}

// ParseConnectionID parses the destination connection ID of a packet.
// It uses the data slice for the connection ID.
// That means that the connection ID must not be used after the packet buffer is released.
func ParseConnectionID(data []byte, shortHeaderConnIDLen int) (protocol.ConnectionID, error) {
	if len(data) == 0 {
		return nil, io.EOF
	}
	isLongHeader := data[0]&0x80 > 0
	if !isLongHeader {
		if len(data) < shortHeaderConnIDLen+1 {
			return nil, io.EOF
		}
		return protocol.ConnectionID(data[1 : 1+shortHeaderConnIDLen]), nil
	}
	if len(data) < 6 {
		return nil, io.EOF
	}
	destConnIDLen := int(data[5])
	if len(data) < 6+destConnIDLen {
		return nil, io.EOF
	}
	return protocol.ConnectionID(data[6 : 6+destConnIDLen]), nil
}

// IsVersionNegotiationPacket says if this is a version negotiation packet
func IsVersionNegotiationPacket(b []byte) bool {
	if len(b) < 5 {
		return false
	}
	return b[0]&0x80 > 0 && b[1] == 0 && b[2] == 0 && b[3] == 0 && b[4] == 0
}

var ErrUnsupportedVersion = errors.New("unsupported version")

// The Header is the version independent part of the header
type Header struct {
	IsLongHeader bool // TODO: remove. Currently only needed for logging.
	typeByte     byte
	Type         protocol.PacketType

	Version          protocol.VersionNumber
	SrcConnectionID  protocol.ConnectionID
	DestConnectionID protocol.ConnectionID

	Length protocol.ByteCount

	Token []byte

	parsedLen protocol.ByteCount // how many bytes were read while parsing this header
}

// ParseLongHeaderPacket parses a long header packet.
// If the packet has a long header, the packet is cut according to the length field.
// If we understand the version, the packet is header up unto the packet number.
// Otherwise, only the invariant part of the header is parsed.
func ParseLongHeaderPacket(data []byte) (*Header, []byte /* packet data */, []byte /* rest */, error) {
	hdr, err := parseLongHeader(bytes.NewReader(data))
	if err != nil {
		if err == ErrUnsupportedVersion {
			return hdr, nil, nil, ErrUnsupportedVersion
		}
		return nil, nil, nil, err
	}
	if protocol.ByteCount(len(data)) < hdr.ParsedLen()+hdr.Length {
		return nil, nil, nil, fmt.Errorf("packet length (%d bytes) is smaller than the expected length (%d bytes)", len(data)-int(hdr.ParsedLen()), hdr.Length)
	}
	packetLen := int(hdr.ParsedLen() + hdr.Length)
	rest := data[packetLen:]
	data = data[:packetLen]
	return hdr, data, rest, nil
}

// parseHeader parses the Long Header.
// * if we understand the version: up to the packet number
// * if not, only the invariant part of the header
func parseLongHeader(b *bytes.Reader) (*Header, error) {
	startLen := b.Len()
	typeByte, err := b.ReadByte()
	if err != nil {
		return nil, err
	}
	h := &Header{
		typeByte:     typeByte,
		IsLongHeader: true,
	}
	if err := h.parseLongHeader(b); err != nil {
		return h, err
	}
	h.parsedLen = protocol.ByteCount(startLen - b.Len())
	return h, err
}

func (h *Header) parseLongHeader(b *bytes.Reader) error {
	v, err := utils.BigEndian.ReadUint32(b)
	if err != nil {
		return err
	}
	h.Version = protocol.VersionNumber(v)
	if h.Version != 0 && h.typeByte&0x40 == 0 {
		return errors.New("not a QUIC packet")
	}
	destConnIDLen, err := b.ReadByte()
	if err != nil {
		return err
	}
	h.DestConnectionID, err = protocol.ReadConnectionID(b, int(destConnIDLen))
	if err != nil {
		return err
	}
	srcConnIDLen, err := b.ReadByte()
	if err != nil {
		return err
	}
	h.SrcConnectionID, err = protocol.ReadConnectionID(b, int(srcConnIDLen))
	if err != nil {
		return err
	}
	if h.Version == 0 { // version negotiation packet
		return nil
	}
	// If we don't understand the version, we have no idea how to interpret the rest of the bytes
	if !protocol.IsSupportedVersion(protocol.SupportedVersions, h.Version) {
		return ErrUnsupportedVersion
	}

	switch (h.typeByte & 0x30) >> 4 {
	case 0x0:
		h.Type = protocol.PacketTypeInitial
	case 0x1:
		h.Type = protocol.PacketType0RTT
	case 0x2:
		h.Type = protocol.PacketTypeHandshake
	case 0x3:
		h.Type = protocol.PacketTypeRetry
	}

	if h.Type == protocol.PacketTypeRetry {
		tokenLen := b.Len() - 16
		if tokenLen <= 0 {
			return io.EOF
		}
		h.Token = make([]byte, tokenLen)
		if _, err := io.ReadFull(b, h.Token); err != nil {
			return err
		}
		_, err := b.Seek(16, io.SeekCurrent)
		return err
	}

	if h.Type == protocol.PacketTypeInitial {
		tokenLen, err := utils.ReadVarInt(b)
		if err != nil {
			return err
		}
		if tokenLen > uint64(b.Len()) {
			return io.EOF
		}
		h.Token = make([]byte, tokenLen)
		if _, err := io.ReadFull(b, h.Token); err != nil {
			return err
		}
	}

	pl, err := utils.ReadVarInt(b)
	if err != nil {
		return err
	}
	h.Length = protocol.ByteCount(pl)
	return nil
}

// ParsedLen returns the number of bytes that were consumed when parsing the header
func (h *Header) ParsedLen() protocol.ByteCount {
	return h.parsedLen
}

// ParseExtended parses the version dependent part of the header.
// The Reader has to be set such that it points to the first byte of the header.
func (h *Header) ParseExtended(b *bytes.Reader, ver protocol.VersionNumber) (*ExtendedHeader, error) {
	extHdr := h.toExtendedHeader()
	reservedBitsValid, err := extHdr.parse(b, ver)
	if err != nil {
		return nil, err
	}
	if !reservedBitsValid {
		return extHdr, ErrInvalidReservedBits
	}
	return extHdr, nil
}

func (h *Header) toExtendedHeader() *ExtendedHeader {
	return &ExtendedHeader{Header: *h}
}

// PacketType is the type of the packet, for logging purposes
func (h *Header) PacketType() string {
	if h.IsLongHeader {
		return h.Type.String()
	}
	return "1-RTT"
}
