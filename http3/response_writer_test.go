package http3

import (
	"bytes"
	"io"
	"net/http"

	mockquic "github.com/lucas-clemente/quic-go/internal/mocks/quic"
	"github.com/lucas-clemente/quic-go/internal/utils"

	"github.com/golang/mock/gomock"
	"github.com/marten-seemann/qpack"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Response Writer", func() {
	var (
		rw     *responseWriter
		strBuf *bytes.Buffer
		sess   *mockquic.MockEarlySession
	)

	BeforeEach(func() {
		strBuf = &bytes.Buffer{}
		str := mockquic.NewMockStream(mockCtrl)
		str.EXPECT().Write(gomock.Any()).DoAndReturn(strBuf.Write).AnyTimes()
		sess = mockquic.NewMockEarlySession(mockCtrl)
		rw = newResponseWriter(sess, str, utils.DefaultLogger)
	})

	decodeHeader := func(str io.Reader) map[string][]string {
		rw.Flush()
		fields := make(map[string][]string)
		decoder := qpack.NewDecoder(nil)

		frame, err := parseNextFrame(str)
		Expect(err).ToNot(HaveOccurred())
		Expect(frame).To(BeAssignableToTypeOf(&headersFrame{}))
		headersFrame := frame.(*headersFrame)
		data := make([]byte, headersFrame.Length)
		_, err = io.ReadFull(str, data)
		Expect(err).ToNot(HaveOccurred())
		hfs, err := decoder.DecodeFull(data)
		Expect(err).ToNot(HaveOccurred())
		for _, p := range hfs {
			fields[p.Name] = append(fields[p.Name], p.Value)
		}
		return fields
	}

	getData := func(str io.Reader) []byte {
		frame, err := parseNextFrame(str)
		Expect(err).ToNot(HaveOccurred())
		Expect(frame).To(BeAssignableToTypeOf(&dataFrame{}))
		df := frame.(*dataFrame)
		data := make([]byte, df.Length)
		_, err = io.ReadFull(str, data)
		Expect(err).ToNot(HaveOccurred())
		return data
	}

	It("writes status", func() {
		rw.WriteHeader(http.StatusTeapot)
		fields := decodeHeader(strBuf)
		Expect(fields).To(HaveLen(1))
		Expect(fields).To(HaveKeyWithValue(":status", []string{"418"}))
	})

	It("writes headers", func() {
		rw.Header().Add("content-length", "42")
		rw.WriteHeader(http.StatusTeapot)
		fields := decodeHeader(strBuf)
		Expect(fields).To(HaveKeyWithValue("content-length", []string{"42"}))
	})

	It("writes multiple headers with the same name", func() {
		const cookie1 = "test1=1; Max-Age=7200; path=/"
		const cookie2 = "test2=2; Max-Age=7200; path=/"
		rw.Header().Add("set-cookie", cookie1)
		rw.Header().Add("set-cookie", cookie2)
		rw.WriteHeader(http.StatusTeapot)
		fields := decodeHeader(strBuf)
		Expect(fields).To(HaveKey("set-cookie"))
		cookies := fields["set-cookie"]
		Expect(cookies).To(ContainElement(cookie1))
		Expect(cookies).To(ContainElement(cookie2))
	})

	It("writes data", func() {
		n, err := rw.Write([]byte("foobar"))
		Expect(n).To(Equal(6))
		Expect(err).ToNot(HaveOccurred())
		// Should have written 200 on the header stream
		fields := decodeHeader(strBuf)
		Expect(fields).To(HaveKeyWithValue(":status", []string{"200"}))
		// And foobar on the data stream
		Expect(getData(strBuf)).To(Equal([]byte("foobar")))
	})

	It("writes data after WriteHeader is called", func() {
		rw.WriteHeader(http.StatusTeapot)
		n, err := rw.Write([]byte("foobar"))
		Expect(n).To(Equal(6))
		Expect(err).ToNot(HaveOccurred())
		// Should have written 418 on the header stream
		fields := decodeHeader(strBuf)
		Expect(fields).To(HaveKeyWithValue(":status", []string{"418"}))
		// And foobar on the data stream
		Expect(getData(strBuf)).To(Equal([]byte("foobar")))
	})

	It("does not WriteHeader() twice", func() {
		rw.WriteHeader(200)
		rw.WriteHeader(500)
		fields := decodeHeader(strBuf)
		Expect(fields).To(HaveLen(1))
		Expect(fields).To(HaveKeyWithValue(":status", []string{"200"}))
	})

	It("allows calling WriteHeader() several times when using the 103 status code", func() {
		rw.Header().Add("Link", "</style.css>; rel=preload; as=style")
		rw.Header().Add("Link", "</script.js>; rel=preload; as=script")
		rw.WriteHeader(http.StatusEarlyHints)

		n, err := rw.Write([]byte("foobar"))
		Expect(n).To(Equal(6))
		Expect(err).ToNot(HaveOccurred())

		// Early Hints must have been received
		fields := decodeHeader(strBuf)
		Expect(fields).To(HaveLen(2))
		Expect(fields).To(HaveKeyWithValue(":status", []string{"103"}))
		Expect(fields).To(HaveKeyWithValue("link", []string{"</style.css>; rel=preload; as=style", "</script.js>; rel=preload; as=script"}))

		// According to the spec, headers sent in the informational response must also be included in the final response
		fields = decodeHeader(strBuf)
		Expect(fields).To(HaveLen(2))
		Expect(fields).To(HaveKeyWithValue(":status", []string{"200"}))
		Expect(fields).To(HaveKeyWithValue("link", []string{"</style.css>; rel=preload; as=style", "</script.js>; rel=preload; as=script"}))

		Expect(getData(strBuf)).To(Equal([]byte("foobar")))
	})

	It("doesn't allow writes if the status code doesn't allow a body", func() {
		rw.WriteHeader(304)
		n, err := rw.Write([]byte("foobar"))
		Expect(n).To(BeZero())
		Expect(err).To(MatchError(http.ErrBodyNotAllowed))
	})

	It("allows access to the datagram methods", func() {
		sess.EXPECT().SendMessage([]byte("foobar"))
		rw.WriteDatagram([]byte("foobar"))
		sess.EXPECT().ReceiveMessage().Return([]byte("raboof"), nil)
		msg, err := rw.ReadDatagram()
		Expect(err).ToNot(HaveOccurred())
		Expect(msg).To(Equal([]byte("raboof")))
	})
})
