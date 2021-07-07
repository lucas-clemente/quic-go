package http3

import (
	"sync"

	"github.com/lucas-clemente/quic-go"
	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"
	"github.com/marten-seemann/qpack"
)

type SessionID = protocol.StreamID

type serverConn struct {
	quic.EarlySession
	decoder *qpack.Decoder

	mutex           sync.RWMutex
	responseWriters map[protocol.StreamID]*responseWriter

	logger utils.Logger
}

func newServerConn(session quic.EarlySession, logger utils.Logger) *serverConn {
	return &serverConn{
		EarlySession: session,
		decoder:      qpack.NewDecoder(nil),
		logger:       logger,
	}
}

func (c *serverConn) addResponseWriter(id SessionID, rw *responseWriter) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	if c.responseWriters == nil {
		c.responseWriters = make(map[SessionID]*responseWriter)
	}
	c.responseWriters[id] = rw
}

func (c *serverConn) getResponseWriter(id SessionID) *responseWriter {
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	return c.responseWriters[id]
}

func (c *serverConn) deleteResponseWriter(id SessionID) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	delete(c.responseWriters, id)
}
