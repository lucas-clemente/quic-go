package http3

import (
	"bytes"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/lucas-clemente/quic-go/internal/utils"
	"github.com/marten-seemann/qpack"
	"golang.org/x/net/http/httpguts"
	"golang.org/x/net/http2"
)

type responseWriter struct {
	stream io.Writer

	header   http.Header
	trailers []string

	status        int // status code passed to WriteHeader
	headerWritten bool

	logger utils.Logger
}

var _ http.ResponseWriter = &responseWriter{}

func newResponseWriter(stream io.Writer, logger utils.Logger) *responseWriter {
	return &responseWriter{
		header: http.Header{},
		stream: stream,
		logger: logger,
	}
}

func (w *responseWriter) Header() http.Header {
	return w.header
}

func (w *responseWriter) WriteHeader(status int) {
	if w.headerWritten {
		return
	}
	w.headerWritten = true
	w.status = status

	var headers bytes.Buffer
	enc := qpack.NewEncoder(&headers)
	enc.WriteField(qpack.HeaderField{Name: ":status", Value: strconv.Itoa(status)})

	for k, v := range w.header {
		for index := range v {
			if k == "Trailer" {
				w.declareTrailer(v[index])
			}
			enc.WriteField(qpack.HeaderField{Name: strings.ToLower(k), Value: v[index]})
		}
	}

	buf := &bytes.Buffer{}
	(&headersFrame{Length: uint64(headers.Len())}).Write(buf)
	w.logger.Infof("Responding with %d", status)
	if _, err := w.stream.Write(buf.Bytes()); err != nil {
		w.logger.Errorf("could not write headers frame: %s", err.Error())
	}
	if _, err := w.stream.Write(headers.Bytes()); err != nil {
		w.logger.Errorf("could not write header frame payload: %s", err.Error())
	}
}

func (w *responseWriter) Write(p []byte) (int, error) {
	if !w.headerWritten {
		w.WriteHeader(200)
	}
	if !bodyAllowedForStatus(w.status) {
		return 0, http.ErrBodyNotAllowed
	}
	df := &dataFrame{Length: uint64(len(p))}
	buf := &bytes.Buffer{}
	df.Write(buf)
	if _, err := w.stream.Write(buf.Bytes()); err != nil {
		return 0, err
	}
	return w.stream.Write(p)
}

func (w *responseWriter) Flush() {}

func (w *responseWriter) promoteTrailer() {
	for k, vv := range w.header {
		if !strings.HasPrefix(k, http2.TrailerPrefix) {
			continue
		}
		trailerKey := strings.TrimPrefix(k, http2.TrailerPrefix)
		w.declareTrailer(trailerKey)
		w.header[http.CanonicalHeaderKey(trailerKey)] = vv
	}
}

func strSliceContains(ss []string, s string) bool {
	for _, v := range ss {
		if v == s {
			return true
		}
	}
	return false
}

func (w *responseWriter) declareTrailer(k string) {
	k = http.CanonicalHeaderKey(k)
	if !httpguts.ValidTrailerHeader(k) {
		// Forbidden by RFC 7230, section 4.1.2.
		w.logger.Debugf("ignoring invalid trailer %q", k)
		return
	}
	if !strSliceContains(w.trailers, k) {
		w.trailers = append(w.trailers, k)
	}
}

func (w *responseWriter) hasNonEmptyTrailers() bool {
	for _, trailer := range w.trailers {
		if _, ok := w.header[trailer]; ok {
			return true
		}
	}
	return false
}

func (w *responseWriter) writeTrailers() {
	w.promoteTrailer()

	if !w.hasNonEmptyTrailers() {
		return
	}

	var headers bytes.Buffer
	enc := qpack.NewEncoder(&headers)
	for _, trailer := range w.trailers {
		if v, ok := w.header[trailer]; ok {
			for _, s := range v {
				enc.WriteField(qpack.HeaderField{Name: strings.ToLower(trailer), Value: s})
			}
		}
	}

	buf := &bytes.Buffer{}
	(&headersFrame{Length: uint64(headers.Len())}).Write(buf)

	if _, err := w.stream.Write(buf.Bytes()); err != nil {
		w.logger.Errorf("could not write headers frame: %s", err.Error())
	}
	if _, err := w.stream.Write(headers.Bytes()); err != nil {
		w.logger.Errorf("could not write header frame payload: %s", err.Error())
	}
}

// test that we implement http.Flusher
var _ http.Flusher = &responseWriter{}

// copied from http2/http2.go
// bodyAllowedForStatus reports whether a given response status code
// permits a body. See RFC 2616, section 4.4.
func bodyAllowedForStatus(status int) bool {
	switch {
	case status >= 100 && status <= 199:
		return false
	case status == 204:
		return false
	case status == 304:
		return false
	}
	return true
}
