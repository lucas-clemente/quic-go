package http3

import (
	"bytes"
	"io"
	"net/http"

	"github.com/lucas-clemente/quic-go/internal/utils"
	"github.com/marten-seemann/qpack"
	"golang.org/x/net/http2"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Response Writer", func() {
	var (
		rw     *responseWriter
		strBuf *bytes.Buffer
	)

	BeforeEach(func() {
		strBuf = &bytes.Buffer{}
		rw = newResponseWriter(strBuf, utils.DefaultLogger)
	})

	decodeHeader := func(str io.Reader) map[string][]string {
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

	It("doesn't allow writes if the status code doesn't allow a body", func() {
		rw.WriteHeader(304)
		n, err := rw.Write([]byte("foobar"))
		Expect(n).To(BeZero())
		Expect(err).To(MatchError(http.ErrBodyNotAllowed))
	})

	It("write announced trailer", func() {
		rw.Header().Add("Trailer", "Key")
		rw.Header().Add("Trailer", "Key2")
		rw.WriteHeader(200)
		rw.Write([]byte("foobar"))
		rw.Header().Set("Key", "Value")
		rw.Header().Set("Key2", "Value")

		// Needs to call writeTrailers for simulate ends of the handler
		rw.writeTrailers()
		headers := decodeHeader(strBuf)
		Expect(headers).To(HaveKeyWithValue(":status", []string{"200"}))
		Expect(headers).To(HaveKeyWithValue("trailer", []string{"Key", "Key2"}))

		Expect(getData(strBuf)).To(Equal([]byte("foobar")))

		trailers := decodeHeader(strBuf)
		Expect(trailers).To(HaveKeyWithValue("key", []string{"Value"}))
		Expect(trailers).To(HaveKeyWithValue("key2", []string{"Value"}))

	})

	It("ignore non-announced trailer (without trailer prefix)", func() {
		rw.Header().Set("Trailer", "Key")
		rw.WriteHeader(200)
		rw.Write([]byte("foobar"))
		rw.Header().Set("UnknownKey", "Value")
		rw.Header().Set("Key", "Value")

		// Needs to call writeTrailers for simulate ends of the handler
		rw.writeTrailers()
		headers := decodeHeader(strBuf)
		Expect(headers).To(HaveKeyWithValue(":status", []string{"200"}))
		Expect(headers).To(HaveKeyWithValue("trailer", []string{"Key"}))

		Expect(getData(strBuf)).To(Equal([]byte("foobar")))

		trailers := decodeHeader(strBuf)
		Expect(trailers).To(HaveKeyWithValue("key", []string{"Value"}))
		Expect(trailers).To(Not(HaveKeyWithValue("unknownkey", []string{"Value"})))

	})

	It("write non-announced trailer (with trailer prefix)", func() {
		rw.Header().Set("Trailer", "Key")
		rw.WriteHeader(200)
		rw.Write([]byte("foobar"))
		rw.Header().Set("Key", "Value")
		rw.Header().Set(http2.TrailerPrefix+"Key2", "Value")

		// Needs to call writeTrailers for simulate ends of the handler
		rw.writeTrailers()
		headers := decodeHeader(strBuf)
		Expect(headers).To(HaveKeyWithValue(":status", []string{"200"}))
		Expect(headers).To(HaveKeyWithValue("trailer", []string{"Key"}))

		Expect(getData(strBuf)).To(Equal([]byte("foobar")))

		trailers := decodeHeader(strBuf)
		Expect(trailers).To(HaveKeyWithValue("key", []string{"Value"}))
		Expect(trailers).To(HaveKeyWithValue("key2", []string{"Value"}))

	})
})
