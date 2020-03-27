package http3

import (
	"fmt"
	"io"
	"net/http"

	"github.com/lucas-clemente/quic-go"
	"github.com/marten-seemann/qpack"
)

// The body of a http.Request or http.Response.
type body struct {
	str quic.Stream

	isRequest bool

	// only set for the http.Response
	// The channel is closed when the user is done with this response:
	// either when Read() errors, or when Close() is called.
	reqDone       chan<- struct{}
	reqDoneClosed bool

	onFrameError func()

	bytesRemainingInFrame uint64

	resp *http.Response

	decoder *qpack.Decoder

	maxHeaderBytes uint64
}

var _ io.ReadCloser = &body{}

func newRequestBody(str quic.Stream, onFrameError func()) *body {
	return &body{
		str:          str,
		onFrameError: onFrameError,
		isRequest:    true,
	}
}

func newResponseBody(str quic.Stream, done chan<- struct{}, onFrameError func(), resp *http.Response, decoder *qpack.Decoder, maxHeaderBytes uint64) *body {
	return &body{
		str:            str,
		onFrameError:   onFrameError,
		reqDone:        done,
		resp:           resp,
		decoder:        decoder,
		maxHeaderBytes: maxHeaderBytes,
	}
}

func (r *body) Read(b []byte) (int, error) {
	n, err := r.readImpl(b)
	if err != nil && !r.isRequest {
		r.requestDone()
	}
	return n, err
}

func (r *body) readImpl(b []byte) (int, error) {
	if r.bytesRemainingInFrame == 0 {
	parseLoop:
		for {
			frame, err := parseNextFrame(r.str)
			if err != nil {
				return 0, err
			}
			switch f := frame.(type) {
			case *headersFrame:
				if r.isRequest {
					// skip HEADERS frame in request
					continue
				}
				if f.Length > r.maxHeaderBytes {
					return 0, fmt.Errorf("HEADERS frame too large: %d bytes (max: %d)", f.Length, r.maxHeaderBytes)
				}
				p := make([]byte, f.Length)
				r.str.Read(p)
				trailers, err := r.decoder.DecodeFull(p)
				if err != nil {
					// Ignoring invalid frame
					continue
				}

				for _, trailer := range trailers {
					if r.resp.Trailer == nil {
						r.resp.Trailer = http.Header{}
					}
					r.resp.Trailer.Add(trailer.Name, trailer.Value)
				}

				// Trailer Frame is the last frame.
				return 0, nil
			case *dataFrame:
				r.bytesRemainingInFrame = f.Length
				break parseLoop
			default:
				r.onFrameError()
				// parseNextFrame skips over unknown frame types
				// Therefore, this condition is only entered when we parsed another known frame type.
				return 0, fmt.Errorf("peer sent an unexpected frame: %T", f)
			}
		}
	}

	var n int
	var err error
	if r.bytesRemainingInFrame < uint64(len(b)) {
		n, err = r.str.Read(b[:r.bytesRemainingInFrame])
	} else {
		n, err = r.str.Read(b)
	}
	r.bytesRemainingInFrame -= uint64(n)
	return n, err
}

func (r *body) requestDone() {
	if r.reqDoneClosed {
		return
	}
	close(r.reqDone)
	r.reqDoneClosed = true
}

func (r *body) Close() error {
	// quic.Stream.Close() closes the write side, not the read side
	if r.isRequest {
		return r.str.Close()
	}
	r.requestDone()
	r.str.CancelRead(quic.ErrorCode(errorRequestCanceled))
	return nil
}
