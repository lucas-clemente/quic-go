package http3

import (
	"bytes"
	"fmt"
	"io"
	"net/http"

	"github.com/golang/mock/gomock"
	"github.com/lucas-clemente/quic-go"
	mockquic "github.com/lucas-clemente/quic-go/internal/mocks/quic"
	"github.com/marten-seemann/qpack"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

type bodyType uint8

const (
	bodyTypeRequest bodyType = iota
	bodyTypeResponse
)

func (t bodyType) String() string {
	if t == bodyTypeRequest {
		return "request"
	}
	return "response"
}

var _ = Describe("Body", func() {
	var (
		rb            *body
		str           *mockquic.MockStream
		buf           *bytes.Buffer
		reqDone       chan struct{}
		errorCbCalled bool
	)

	errorCb := func() { errorCbCalled = true }

	getDataFrame := func(data []byte) []byte {
		b := &bytes.Buffer{}
		(&dataFrame{Length: uint64(len(data))}).Write(b)
		b.Write(data)
		return b.Bytes()
	}

	BeforeEach(func() {
		buf = &bytes.Buffer{}
		errorCbCalled = false
	})

	for _, bt := range []bodyType{bodyTypeRequest, bodyTypeResponse} {
		bodyType := bt

		Context(fmt.Sprintf("using a %s body", bodyType), func() {
			BeforeEach(func() {
				str = mockquic.NewMockStream(mockCtrl)
				str.EXPECT().Write(gomock.Any()).DoAndReturn(func(b []byte) (int, error) {
					return buf.Write(b)
				}).AnyTimes()
				str.EXPECT().Read(gomock.Any()).DoAndReturn(func(b []byte) (int, error) {
					return buf.Read(b)
				}).AnyTimes()

				switch bodyType {
				case bodyTypeRequest:
					rb = newRequestBody(str, errorCb)
				case bodyTypeResponse:
					reqDone = make(chan struct{})
					rb = newResponseBody(str, reqDone, errorCb, &http.Response{}, qpack.NewDecoder(func(f qpack.HeaderField) {}), defaultMaxResponseHeaderBytes)
				}
			})

			It("reads DATA frames in a single run", func() {
				buf.Write(getDataFrame([]byte("foobar")))
				b := make([]byte, 6)
				n, err := rb.Read(b)
				Expect(err).ToNot(HaveOccurred())
				Expect(n).To(Equal(6))
				Expect(b).To(Equal([]byte("foobar")))
			})

			It("reads DATA frames in multiple runs", func() {
				buf.Write(getDataFrame([]byte("foobar")))
				b := make([]byte, 3)
				n, err := rb.Read(b)
				Expect(err).ToNot(HaveOccurred())
				Expect(n).To(Equal(3))
				Expect(b).To(Equal([]byte("foo")))
				n, err = rb.Read(b)
				Expect(err).ToNot(HaveOccurred())
				Expect(n).To(Equal(3))
				Expect(b).To(Equal([]byte("bar")))
			})

			It("reads DATA frames into too large buffers", func() {
				buf.Write(getDataFrame([]byte("foobar")))
				b := make([]byte, 10)
				n, err := rb.Read(b)
				Expect(err).ToNot(HaveOccurred())
				Expect(n).To(Equal(6))
				Expect(b[:n]).To(Equal([]byte("foobar")))
			})

			It("reads DATA frames into too large buffers, in multiple runs", func() {
				buf.Write(getDataFrame([]byte("foobar")))
				b := make([]byte, 4)
				n, err := rb.Read(b)
				Expect(err).ToNot(HaveOccurred())
				Expect(n).To(Equal(4))
				Expect(b).To(Equal([]byte("foob")))
				n, err = rb.Read(b)
				Expect(err).ToNot(HaveOccurred())
				Expect(n).To(Equal(2))
				Expect(b[:n]).To(Equal([]byte("ar")))
			})

			It("reads multiple DATA frames", func() {
				buf.Write(getDataFrame([]byte("foo")))
				buf.Write(getDataFrame([]byte("bar")))
				b := make([]byte, 6)
				n, err := rb.Read(b)
				Expect(err).ToNot(HaveOccurred())
				Expect(n).To(Equal(3))
				Expect(b[:n]).To(Equal([]byte("foo")))
				n, err = rb.Read(b)
				Expect(err).ToNot(HaveOccurred())
				Expect(n).To(Equal(3))
				Expect(b[:n]).To(Equal([]byte("bar")))
			})

			It("skips HEADERS frames", func() {
				buf.Write(getDataFrame([]byte("foo")))
				(&headersFrame{Length: 10}).Write(buf)
				buf.Write(make([]byte, 10))
				buf.Write(getDataFrame([]byte("bar")))
				b := make([]byte, 6)
				n, err := io.ReadFull(rb, b)
				Expect(err).ToNot(HaveOccurred())
				Expect(n).To(Equal(6))
				Expect(b).To(Equal([]byte("foobar")))
			})

			It("errors when it can't parse the frame", func() {
				buf.Write([]byte("invalid"))
				_, err := rb.Read([]byte{0})
				Expect(err).To(HaveOccurred())
			})

			It("errors on unexpected frames, and calls the error callback", func() {
				(&settingsFrame{}).Write(buf)
				_, err := rb.Read([]byte{0})
				Expect(err).To(MatchError("peer sent an unexpected frame: *http3.settingsFrame"))
				Expect(errorCbCalled).To(BeTrue())
			})

			if bodyType == bodyTypeRequest {
				It("closes requests", func() {
					str.EXPECT().Close()
					Expect(rb.Close()).To(Succeed())
				})
			}

			if bodyType == bodyTypeResponse {
				It("closes the reqDone channel when Read errors", func() {
					buf.Write([]byte("invalid"))
					_, err := rb.Read([]byte{0})
					Expect(err).To(HaveOccurred())
					Expect(reqDone).To(BeClosed())
				})

				It("allows multiple calls to Read, when Read errors", func() {
					buf.Write([]byte("invalid"))
					_, err := rb.Read([]byte{0})
					Expect(err).To(HaveOccurred())
					Expect(reqDone).To(BeClosed())
					_, err = rb.Read([]byte{0})
					Expect(err).To(HaveOccurred())
				})

				It("closes responses", func() {
					str.EXPECT().CancelRead(quic.ErrorCode(errorRequestCanceled))
					Expect(rb.Close()).To(Succeed())
				})

				It("allows multiple calls to Close", func() {
					str.EXPECT().CancelRead(quic.ErrorCode(errorRequestCanceled)).MaxTimes(2)
					Expect(rb.Close()).To(Succeed())
					Expect(reqDone).To(BeClosed())
					Expect(rb.Close()).To(Succeed())
				})
			}
		})
	}
})
