package http3

import (
	"net/http"
	"net/url"

	"github.com/marten-seemann/qpack"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Request", func() {
	It("populates request", func() {
		headers := []qpack.HeaderField{
			{Name: ":path", Value: "/foo"},
			{Name: ":authority", Value: "quic.clemente.io"},
			{Name: ":method", Value: "GET"},
			{Name: "content-length", Value: "42"},
		}
		req, err := requestFromHeaders(headers)
		Expect(err).NotTo(HaveOccurred())
		Expect(req.Method).To(Equal("GET"))
		Expect(req.URL.Path).To(Equal("/foo"))
		Expect(req.URL.Host).To(BeEmpty())
		Expect(req.Proto).To(Equal("HTTP/3"))
		Expect(req.ProtoMajor).To(Equal(3))
		Expect(req.ProtoMinor).To(BeZero())
		Expect(req.ContentLength).To(Equal(int64(42)))
		Expect(req.Header).To(BeEmpty())
		Expect(req.Body).To(BeNil())
		Expect(req.Host).To(Equal("quic.clemente.io"))
		Expect(req.RequestURI).To(Equal("/foo"))
	})

	It("parses path with leading double slashes", func() {
		headers := []qpack.HeaderField{
			{Name: ":path", Value: "//foo"},
			{Name: ":authority", Value: "quic.clemente.io"},
			{Name: ":method", Value: "GET"},
		}
		req, err := requestFromHeaders(headers)
		Expect(err).NotTo(HaveOccurred())
		Expect(req.Header).To(BeEmpty())
		Expect(req.Body).To(BeNil())
		Expect(req.URL.Path).To(Equal("//foo"))
		Expect(req.URL.Host).To(BeEmpty())
		Expect(req.Host).To(Equal("quic.clemente.io"))
		Expect(req.RequestURI).To(Equal("//foo"))
	})

	It("concatenates the cookie headers", func() {
		headers := []qpack.HeaderField{
			{Name: ":path", Value: "/foo"},
			{Name: ":authority", Value: "quic.clemente.io"},
			{Name: ":method", Value: "GET"},
			{Name: "cookie", Value: "cookie1=foobar1"},
			{Name: "cookie", Value: "cookie2=foobar2"},
		}
		req, err := requestFromHeaders(headers)
		Expect(err).NotTo(HaveOccurred())
		Expect(req.Header).To(Equal(http.Header{
			"Cookie": []string{"cookie1=foobar1; cookie2=foobar2"},
		}))
	})

	It("handles other headers", func() {
		headers := []qpack.HeaderField{
			{Name: ":path", Value: "/foo"},
			{Name: ":authority", Value: "quic.clemente.io"},
			{Name: ":method", Value: "GET"},
			{Name: "cache-control", Value: "max-age=0"},
			{Name: "duplicate-header", Value: "1"},
			{Name: "duplicate-header", Value: "2"},
		}
		req, err := requestFromHeaders(headers)
		Expect(err).NotTo(HaveOccurred())
		Expect(req.Header).To(Equal(http.Header{
			"Cache-Control":    []string{"max-age=0"},
			"Duplicate-Header": []string{"1", "2"},
		}))
	})

	It("handles CONNECT method", func() {
		headers := []qpack.HeaderField{
			{Name: ":authority", Value: "quic.clemente.io"},
			{Name: ":method", Value: http.MethodConnect},
		}
		req, err := requestFromHeaders(headers)
		Expect(err).NotTo(HaveOccurred())
		Expect(req.Method).To(Equal(http.MethodConnect))
		Expect(req.RequestURI).To(Equal("quic.clemente.io"))
	})

	It("errors with missing path", func() {
		headers := []qpack.HeaderField{
			{Name: ":authority", Value: "quic.clemente.io"},
			{Name: ":method", Value: "GET"},
		}
		_, err := requestFromHeaders(headers)
		Expect(err).To(MatchError(":path, :authority and :method must not be empty"))
	})

	It("errors with missing method", func() {
		headers := []qpack.HeaderField{
			{Name: ":path", Value: "/foo"},
			{Name: ":authority", Value: "quic.clemente.io"},
		}
		_, err := requestFromHeaders(headers)
		Expect(err).To(MatchError(":path, :authority and :method must not be empty"))
	})

	It("errors with missing authority", func() {
		headers := []qpack.HeaderField{
			{Name: ":path", Value: "/foo"},
			{Name: ":method", Value: "GET"},
		}
		_, err := requestFromHeaders(headers)
		Expect(err).To(MatchError(":path, :authority and :method must not be empty"))
	})

	It("errors with missing authority in CONNECT method", func() {
		headers := []qpack.HeaderField{
			{Name: ":method", Value: http.MethodConnect},
		}
		_, err := requestFromHeaders(headers)
		Expect(err).To(MatchError(":path must be empty and :authority must not be empty"))
	})

	It("errors with extra path in CONNECT method", func() {
		headers := []qpack.HeaderField{
			{Name: ":path", Value: "/foo"},
			{Name: ":authority", Value: "quic.clemente.io"},
			{Name: ":method", Value: http.MethodConnect},
		}
		_, err := requestFromHeaders(headers)
		Expect(err).To(MatchError(":path must be empty and :authority must not be empty"))
	})

	Context("extracting the hostname from a request", func() {
		var url *url.URL

		BeforeEach(func() {
			var err error
			url, err = url.Parse("https://quic.clemente.io:1337")
			Expect(err).ToNot(HaveOccurred())
		})

		It("uses req.URL.Host", func() {
			req := &http.Request{URL: url}
			Expect(hostnameFromRequest(req)).To(Equal("quic.clemente.io:1337"))
		})

		It("uses req.URL.Host even if req.Host is available", func() {
			req := &http.Request{
				Host: "www.example.org",
				URL:  url,
			}
			Expect(hostnameFromRequest(req)).To(Equal("quic.clemente.io:1337"))
		})

		It("returns an empty hostname if nothing is set", func() {
			Expect(hostnameFromRequest(&http.Request{})).To(BeEmpty())
		})
	})
})
