package http3

import (
	"context"
	"errors"
	"sync"

	"github.com/lucas-clemente/quic-go"
	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"
	"github.com/marten-seemann/qpack"
)

type SessionID = protocol.StreamID

const (
	maxBufferedStreams   = 4
	maxBufferedDatagrams = 4
)

// ErrStreamBufferFull is returned when a incoming stream buffer is full.
var ErrStreamBufferFull = errors.New("stream buffer full")

// ErrDatagramBufferFull is returned when a datagram buffer is full.
var ErrDatagramBufferFull = errors.New("datagram buffer full")

type serverConn struct {
	quic.EarlySession
	decoder *qpack.Decoder

	// Incoming bidirectional HTTP/3 streams (e.g. WebTransport)
	streamMutex     sync.Mutex
	incomingStreams map[SessionID]chan quic.Stream

	// Incoming unidirectional HTTP/3 streams (e.g. WebTransport)
	uniStreamMutex     sync.Mutex
	incomingUniStreams map[SessionID]chan quic.ReceiveStream

	logger utils.Logger
}

func newServerConn(session quic.EarlySession, logger utils.Logger) *serverConn {
	return &serverConn{
		EarlySession: session,
		decoder:      qpack.NewDecoder(nil),
		logger:       logger,
	}
}

func (c *serverConn) addIncomingStream(id SessionID, str quic.Stream) error {
	select {
	case c.streamCh(id) <- str:
		return nil
	case <-c.Context().Done():
		return c.Context().Err()
	default:
		return ErrStreamBufferFull
	}
}

func (c *serverConn) addIncomingUniStream(id SessionID, str quic.ReceiveStream) error {
	select {
	case c.uniStreamCh(id) <- str:
		return nil
	case <-c.Context().Done():
		return c.Context().Err()
	default:
		return ErrStreamBufferFull
	}
}

func (c *serverConn) acceptStream(ctx context.Context, id SessionID) (quic.Stream, error) {
	select {
	case str := <-c.streamCh(id):
		return str, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-c.Context().Done():
		return nil, c.Context().Err()
	}
}

func (c *serverConn) acceptUniStream(ctx context.Context, id SessionID) (quic.ReceiveStream, error) {
	select {
	case str := <-c.uniStreamCh(id):
		return str, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-c.Context().Done():
		return nil, c.Context().Err()
	}
}

func (c *serverConn) streamCh(id SessionID) chan quic.Stream {
	c.streamMutex.Lock()
	defer c.streamMutex.Unlock()
	if c.incomingStreams == nil {
		c.incomingStreams = make(map[SessionID]chan quic.Stream)
	}
	if c.incomingStreams[id] == nil {
		c.incomingStreams[id] = make(chan quic.Stream, maxBufferedStreams)
	}
	return c.incomingStreams[id]
}

func (c *serverConn) uniStreamCh(id SessionID) chan quic.ReceiveStream {
	c.uniStreamMutex.Lock()
	defer c.uniStreamMutex.Unlock()
	if c.incomingUniStreams == nil {
		c.incomingUniStreams = make(map[SessionID]chan quic.ReceiveStream)
	}
	if c.incomingUniStreams[id] == nil {
		c.incomingUniStreams[id] = make(chan quic.ReceiveStream, maxBufferedStreams)
	}
	return c.incomingUniStreams[id]
}

func (c *serverConn) cleanup(id SessionID) {
	c.streamMutex.Lock()
	delete(c.incomingStreams, id)
	c.streamMutex.Unlock()

	c.uniStreamMutex.Lock()
	delete(c.incomingUniStreams, id)
	c.uniStreamMutex.Unlock()

	// TODO: cleanup datagram buffer
}
