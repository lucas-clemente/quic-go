package http3

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/lucas-clemente/quic-go"
	mockquic "github.com/lucas-clemente/quic-go/internal/mocks/quic"
	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/testdata"
	"github.com/lucas-clemente/quic-go/internal/utils"
	"github.com/lucas-clemente/quic-go/quicvarint"

	"github.com/golang/mock/gomock"
	"github.com/marten-seemann/qpack"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

type mockConn struct {
	net.Conn
	version protocol.VersionNumber
}

func newMockConn(version protocol.VersionNumber) net.Conn {
	return &mockConn{version: version}
}

func (c *mockConn) GetQUICVersion() protocol.VersionNumber {
	return c.version
}

var _ = Describe("Server", func() {
	var (
		s                  *Server
		origQuicListenAddr = quicListenAddr
	)

	BeforeEach(func() {
		s = &Server{
			Server: &http.Server{
				TLSConfig: testdata.GetTLSConfig(),
			},
			logger: utils.DefaultLogger,
		}
		origQuicListenAddr = quicListenAddr
	})

	AfterEach(func() {
		quicListenAddr = origQuicListenAddr
	})

	Context("handling requests", func() {
		var (
			qpackDecoder       *qpack.Decoder
			str                *mockquic.MockStream
			sess               *mockquic.MockEarlySession
			exampleGetRequest  *http.Request
			examplePostRequest *http.Request
		)
		reqContext := context.Background()

		decodeHeader := func(str io.Reader) map[string][]string {
			fields := make(map[string][]string)
			decoder := qpack.NewDecoder(nil)

			frame, err := parseNextFrame(str)
			ExpectWithOffset(1, err).ToNot(HaveOccurred())
			ExpectWithOffset(1, frame).To(BeAssignableToTypeOf(&headersFrame{}))
			headersFrame := frame.(*headersFrame)
			data := make([]byte, headersFrame.Length)
			_, err = io.ReadFull(str, data)
			ExpectWithOffset(1, err).ToNot(HaveOccurred())
			hfs, err := decoder.DecodeFull(data)
			ExpectWithOffset(1, err).ToNot(HaveOccurred())
			for _, p := range hfs {
				fields[p.Name] = append(fields[p.Name], p.Value)
			}
			return fields
		}

		encodeRequest := func(req *http.Request) []byte {
			buf := &bytes.Buffer{}
			str := mockquic.NewMockStream(mockCtrl)
			str.EXPECT().Write(gomock.Any()).DoAndReturn(buf.Write).AnyTimes()
			closed := make(chan struct{})
			str.EXPECT().Close().Do(func() { close(closed) })
			rw := newRequestWriter(utils.DefaultLogger)
			Expect(rw.WriteRequest(str, req, false)).To(Succeed())
			Eventually(closed).Should(BeClosed())
			return buf.Bytes()
		}

		setRequest := func(data []byte) {
			buf := bytes.NewBuffer(data)
			str.EXPECT().Read(gomock.Any()).DoAndReturn(func(p []byte) (int, error) {
				if buf.Len() == 0 {
					return 0, io.EOF
				}
				return buf.Read(p)
			}).AnyTimes()
		}

		BeforeEach(func() {
			var err error
			exampleGetRequest, err = http.NewRequest("GET", "https://www.example.com", nil)
			Expect(err).ToNot(HaveOccurred())
			examplePostRequest, err = http.NewRequest("POST", "https://www.example.com", bytes.NewReader([]byte("foobar")))
			Expect(err).ToNot(HaveOccurred())

			qpackDecoder = qpack.NewDecoder(nil)
			str = mockquic.NewMockStream(mockCtrl)

			sess = mockquic.NewMockEarlySession(mockCtrl)
			addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1337}
			sess.EXPECT().RemoteAddr().Return(addr).AnyTimes()
			sess.EXPECT().ConnectionState().AnyTimes()
			sess.EXPECT().LocalAddr().AnyTimes()
		})

		It("calls the HTTP handler function", func() {
			requestChan := make(chan *http.Request, 1)
			s.Handler = http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
				requestChan <- r
			})

			setRequest(encodeRequest(exampleGetRequest))
			str.EXPECT().Context().Return(reqContext)
			str.EXPECT().Write(gomock.Any()).DoAndReturn(func(p []byte) (int, error) {
				return len(p), nil
			}).AnyTimes()
			str.EXPECT().CancelRead(gomock.Any())

			Expect(s.handleRequest(sess, str, qpackDecoder, nil)).To(Equal(requestError{}))
			var req *http.Request
			Eventually(requestChan).Should(Receive(&req))
			Expect(req.Host).To(Equal("www.example.com"))
			Expect(req.RemoteAddr).To(Equal("127.0.0.1:1337"))
			Expect(req.Context().Value(ServerContextKey)).To(Equal(s))
		})

		It("returns 200 with an empty handler", func() {
			s.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})

			responseBuf := &bytes.Buffer{}
			setRequest(encodeRequest(exampleGetRequest))
			str.EXPECT().Context().Return(reqContext)
			str.EXPECT().Write(gomock.Any()).DoAndReturn(responseBuf.Write).AnyTimes()
			str.EXPECT().CancelRead(gomock.Any())

			serr := s.handleRequest(sess, str, qpackDecoder, nil)
			Expect(serr.err).ToNot(HaveOccurred())
			hfs := decodeHeader(responseBuf)
			Expect(hfs).To(HaveKeyWithValue(":status", []string{"200"}))
		})

		It("handles a panicking handler", func() {
			s.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				panic("foobar")
			})

			responseBuf := &bytes.Buffer{}
			setRequest(encodeRequest(exampleGetRequest))
			str.EXPECT().Context().Return(reqContext)
			str.EXPECT().Write(gomock.Any()).DoAndReturn(responseBuf.Write).AnyTimes()
			str.EXPECT().CancelRead(gomock.Any())

			serr := s.handleRequest(sess, str, qpackDecoder, nil)
			Expect(serr.err).ToNot(HaveOccurred())
			hfs := decodeHeader(responseBuf)
			Expect(hfs).To(HaveKeyWithValue(":status", []string{"500"}))
		})

		It("doesn't close the stream if the handler called DataStream()", func() {
			s.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				str := w.(DataStreamer).DataStream()
				str.Write([]byte("foobar"))
			})

			setRequest(encodeRequest(exampleGetRequest))
			str.EXPECT().Context().Return(reqContext)
			str.EXPECT().Write([]byte("foobar"))
			// don't EXPECT CancelRead()

			serr := s.handleRequest(sess, str, qpackDecoder, nil)
			Expect(serr.err).ToNot(HaveOccurred())
		})

		Context("control stream handling", func() {
			var sess *mockquic.MockEarlySession
			testDone := make(chan struct{})

			BeforeEach(func() {
				sess = mockquic.NewMockEarlySession(mockCtrl)
				controlStr := mockquic.NewMockStream(mockCtrl)
				controlStr.EXPECT().Write(gomock.Any())
				sess.EXPECT().OpenUniStream().Return(controlStr, nil)
				sess.EXPECT().AcceptStream(gomock.Any()).Return(nil, errors.New("done"))
				sess.EXPECT().RemoteAddr().Return(&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1337}).AnyTimes()
				sess.EXPECT().ConnectionState().AnyTimes()
				sess.EXPECT().LocalAddr().AnyTimes()
			})

			AfterEach(func() { testDone <- struct{}{} })

			It("parses the SETTINGS frame", func() {
				buf := &bytes.Buffer{}
				quicvarint.Write(buf, streamTypeControlStream)
				(&settingsFrame{}).Write(buf)
				controlStr := mockquic.NewMockStream(mockCtrl)
				controlStr.EXPECT().Read(gomock.Any()).DoAndReturn(buf.Read).AnyTimes()
				sess.EXPECT().AcceptUniStream(gomock.Any()).DoAndReturn(func(context.Context) (quic.ReceiveStream, error) {
					return controlStr, nil
				})
				sess.EXPECT().AcceptUniStream(gomock.Any()).DoAndReturn(func(context.Context) (quic.ReceiveStream, error) {
					<-testDone
					return nil, errors.New("test done")
				})
				s.handleConn(sess)
				time.Sleep(scaleDuration(20 * time.Millisecond)) // don't EXPECT any calls to sess.CloseWithError
			})

			for _, t := range []uint64{streamTypeQPACKEncoderStream, streamTypeQPACKDecoderStream} {
				streamType := t
				name := "encoder"
				if streamType == streamTypeQPACKDecoderStream {
					name = "decoder"
				}

				It(fmt.Sprintf("ignores the QPACK %s streams", name), func() {
					buf := &bytes.Buffer{}
					quicvarint.Write(buf, streamType)
					str := mockquic.NewMockStream(mockCtrl)
					str.EXPECT().Read(gomock.Any()).DoAndReturn(buf.Read).AnyTimes()

					sess.EXPECT().AcceptUniStream(gomock.Any()).DoAndReturn(func(context.Context) (quic.ReceiveStream, error) {
						return str, nil
					})
					sess.EXPECT().AcceptUniStream(gomock.Any()).DoAndReturn(func(context.Context) (quic.ReceiveStream, error) {
						<-testDone
						return nil, errors.New("test done")
					})
					s.handleConn(sess)
					time.Sleep(scaleDuration(20 * time.Millisecond)) // don't EXPECT any calls to str.CancelRead
				})
			}

			It("reset streams other than the control stream and the QPACK streams", func() {
				buf := &bytes.Buffer{}
				quicvarint.Write(buf, 1337)
				str := mockquic.NewMockStream(mockCtrl)
				str.EXPECT().Read(gomock.Any()).DoAndReturn(buf.Read).AnyTimes()
				done := make(chan struct{})
				str.EXPECT().CancelRead(quic.StreamErrorCode(errorStreamCreationError)).Do(func(code quic.StreamErrorCode) {
					close(done)
				})

				sess.EXPECT().AcceptUniStream(gomock.Any()).DoAndReturn(func(context.Context) (quic.ReceiveStream, error) {
					return str, nil
				})
				sess.EXPECT().AcceptUniStream(gomock.Any()).DoAndReturn(func(context.Context) (quic.ReceiveStream, error) {
					<-testDone
					return nil, errors.New("test done")
				})
				s.handleConn(sess)
				Eventually(done).Should(BeClosed())
			})

			It("errors when the first frame on the control stream is not a SETTINGS frame", func() {
				buf := &bytes.Buffer{}
				quicvarint.Write(buf, streamTypeControlStream)
				(&dataFrame{}).Write(buf)
				controlStr := mockquic.NewMockStream(mockCtrl)
				controlStr.EXPECT().Read(gomock.Any()).DoAndReturn(buf.Read).AnyTimes()
				sess.EXPECT().AcceptUniStream(gomock.Any()).DoAndReturn(func(context.Context) (quic.ReceiveStream, error) {
					return controlStr, nil
				})
				sess.EXPECT().AcceptUniStream(gomock.Any()).DoAndReturn(func(context.Context) (quic.ReceiveStream, error) {
					<-testDone
					return nil, errors.New("test done")
				})
				done := make(chan struct{})
				sess.EXPECT().CloseWithError(gomock.Any(), gomock.Any()).Do(func(code quic.ApplicationErrorCode, _ string) {
					defer GinkgoRecover()
					Expect(code).To(BeEquivalentTo(errorMissingSettings))
					close(done)
				})
				s.handleConn(sess)
				Eventually(done).Should(BeClosed())
			})

			It("errors when parsing the frame on the control stream fails", func() {
				buf := &bytes.Buffer{}
				quicvarint.Write(buf, streamTypeControlStream)
				b := &bytes.Buffer{}
				(&settingsFrame{}).Write(b)
				buf.Write(b.Bytes()[:b.Len()-1])
				controlStr := mockquic.NewMockStream(mockCtrl)
				controlStr.EXPECT().Read(gomock.Any()).DoAndReturn(buf.Read).AnyTimes()
				sess.EXPECT().AcceptUniStream(gomock.Any()).DoAndReturn(func(context.Context) (quic.ReceiveStream, error) {
					return controlStr, nil
				})
				sess.EXPECT().AcceptUniStream(gomock.Any()).DoAndReturn(func(context.Context) (quic.ReceiveStream, error) {
					<-testDone
					return nil, errors.New("test done")
				})
				done := make(chan struct{})
				sess.EXPECT().CloseWithError(gomock.Any(), gomock.Any()).Do(func(code quic.ApplicationErrorCode, _ string) {
					defer GinkgoRecover()
					Expect(code).To(BeEquivalentTo(errorFrameError))
					close(done)
				})
				s.handleConn(sess)
				Eventually(done).Should(BeClosed())
			})

			It("errors when the client opens a push stream", func() {
				buf := &bytes.Buffer{}
				quicvarint.Write(buf, streamTypePushStream)
				(&dataFrame{}).Write(buf)
				controlStr := mockquic.NewMockStream(mockCtrl)
				controlStr.EXPECT().Read(gomock.Any()).DoAndReturn(buf.Read).AnyTimes()
				sess.EXPECT().AcceptUniStream(gomock.Any()).DoAndReturn(func(context.Context) (quic.ReceiveStream, error) {
					return controlStr, nil
				})
				sess.EXPECT().AcceptUniStream(gomock.Any()).DoAndReturn(func(context.Context) (quic.ReceiveStream, error) {
					<-testDone
					return nil, errors.New("test done")
				})
				done := make(chan struct{})
				sess.EXPECT().CloseWithError(gomock.Any(), gomock.Any()).Do(func(code quic.ApplicationErrorCode, _ string) {
					defer GinkgoRecover()
					Expect(code).To(BeEquivalentTo(errorStreamCreationError))
					close(done)
				})
				s.handleConn(sess)
				Eventually(done).Should(BeClosed())
			})

			It("errors when the client advertises datagram support (and we enabled support for it)", func() {
				s.EnableDatagrams = true
				buf := &bytes.Buffer{}
				quicvarint.Write(buf, streamTypeControlStream)
				(&settingsFrame{Datagram: true}).Write(buf)
				controlStr := mockquic.NewMockStream(mockCtrl)
				controlStr.EXPECT().Read(gomock.Any()).DoAndReturn(buf.Read).AnyTimes()
				sess.EXPECT().AcceptUniStream(gomock.Any()).DoAndReturn(func(context.Context) (quic.ReceiveStream, error) {
					return controlStr, nil
				})
				sess.EXPECT().AcceptUniStream(gomock.Any()).DoAndReturn(func(context.Context) (quic.ReceiveStream, error) {
					<-testDone
					return nil, errors.New("test done")
				})
				done := make(chan struct{})
				sess.EXPECT().CloseWithError(gomock.Any(), gomock.Any()).Do(func(code quic.ApplicationErrorCode, reason string) {
					defer GinkgoRecover()
					Expect(code).To(BeEquivalentTo(errorSettingsError))
					Expect(reason).To(Equal("missing QUIC Datagram support"))
					close(done)
				})
				s.handleConn(sess)
				Eventually(done).Should(BeClosed())
			})
		})

		Context("stream- and connection-level errors", func() {
			var sess *mockquic.MockEarlySession
			testDone := make(chan struct{})

			BeforeEach(func() {
				testDone = make(chan struct{})
				addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1337}
				sess = mockquic.NewMockEarlySession(mockCtrl)
				controlStr := mockquic.NewMockStream(mockCtrl)
				controlStr.EXPECT().Write(gomock.Any())
				sess.EXPECT().OpenUniStream().Return(controlStr, nil)
				sess.EXPECT().AcceptUniStream(gomock.Any()).DoAndReturn(func(context.Context) (quic.ReceiveStream, error) {
					<-testDone
					return nil, errors.New("test done")
				})
				sess.EXPECT().AcceptStream(gomock.Any()).Return(str, nil)
				sess.EXPECT().AcceptStream(gomock.Any()).Return(nil, errors.New("done"))
				sess.EXPECT().RemoteAddr().Return(addr).AnyTimes()
				sess.EXPECT().ConnectionState().AnyTimes()
				sess.EXPECT().LocalAddr().AnyTimes()
			})

			AfterEach(func() { testDone <- struct{}{} })

			It("cancels reading when client sends a body in GET request", func() {
				handlerCalled := make(chan struct{})
				s.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					close(handlerCalled)
				})

				requestData := encodeRequest(exampleGetRequest)
				buf := &bytes.Buffer{}
				(&dataFrame{Length: 6}).Write(buf) // add a body
				buf.Write([]byte("foobar"))
				responseBuf := &bytes.Buffer{}
				setRequest(append(requestData, buf.Bytes()...))
				done := make(chan struct{})
				str.EXPECT().Context().Return(reqContext)
				str.EXPECT().Write(gomock.Any()).DoAndReturn(responseBuf.Write).AnyTimes()
				str.EXPECT().CancelRead(quic.StreamErrorCode(errorNoError))
				str.EXPECT().Close().Do(func() { close(done) })

				s.handleConn(sess)
				Eventually(done).Should(BeClosed())
				hfs := decodeHeader(responseBuf)
				Expect(hfs).To(HaveKeyWithValue(":status", []string{"200"}))
			})

			It("errors when the client sends a too large header frame", func() {
				s.Server.MaxHeaderBytes = 20
				s.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					Fail("Handler should not be called.")
				})

				requestData := encodeRequest(exampleGetRequest)
				buf := &bytes.Buffer{}
				(&dataFrame{Length: 6}).Write(buf) // add a body
				buf.Write([]byte("foobar"))
				responseBuf := &bytes.Buffer{}
				setRequest(append(requestData, buf.Bytes()...))
				done := make(chan struct{})
				str.EXPECT().Write(gomock.Any()).DoAndReturn(responseBuf.Write).AnyTimes()
				str.EXPECT().CancelWrite(quic.StreamErrorCode(errorFrameError)).Do(func(quic.StreamErrorCode) { close(done) })

				s.handleConn(sess)
				Eventually(done).Should(BeClosed())
			})

			It("handles a request for which the client immediately resets the stream", func() {
				handlerCalled := make(chan struct{})
				s.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					close(handlerCalled)
				})

				testErr := errors.New("stream reset")
				done := make(chan struct{})
				str.EXPECT().Read(gomock.Any()).Return(0, testErr)
				str.EXPECT().CancelWrite(quic.StreamErrorCode(errorRequestIncomplete)).Do(func(quic.StreamErrorCode) { close(done) })

				s.handleConn(sess)
				Consistently(handlerCalled).ShouldNot(BeClosed())
			})

			It("closes the connection when the first frame is not a HEADERS frame", func() {
				handlerCalled := make(chan struct{})
				s.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					close(handlerCalled)
				})

				buf := &bytes.Buffer{}
				(&dataFrame{}).Write(buf)
				setRequest(buf.Bytes())
				str.EXPECT().Write(gomock.Any()).DoAndReturn(func(p []byte) (int, error) {
					return len(p), nil
				}).AnyTimes()

				done := make(chan struct{})
				sess.EXPECT().CloseWithError(gomock.Any(), gomock.Any()).Do(func(code quic.ApplicationErrorCode, _ string) {
					Expect(code).To(Equal(quic.ApplicationErrorCode(errorFrameUnexpected)))
					close(done)
				})
				s.handleConn(sess)
				Eventually(done).Should(BeClosed())
			})

			It("closes the connection when the first frame is not a HEADERS frame", func() {
				handlerCalled := make(chan struct{})
				s.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					close(handlerCalled)
				})

				// use 2*DefaultMaxHeaderBytes here. qpack will compress the requiest,
				// but the request will still end up larger than DefaultMaxHeaderBytes.
				url := bytes.Repeat([]byte{'a'}, http.DefaultMaxHeaderBytes*2)
				req, err := http.NewRequest(http.MethodGet, "https://"+string(url), nil)
				Expect(err).ToNot(HaveOccurred())
				setRequest(encodeRequest(req))
				// str.EXPECT().Context().Return(reqContext)
				str.EXPECT().Write(gomock.Any()).DoAndReturn(func(p []byte) (int, error) {
					return len(p), nil
				}).AnyTimes()
				done := make(chan struct{})
				str.EXPECT().CancelWrite(quic.StreamErrorCode(errorFrameError)).Do(func(quic.StreamErrorCode) { close(done) })

				s.handleConn(sess)
				Eventually(done).Should(BeClosed())
			})
		})

		It("resets the stream when the body of POST request is not read, and the request handler replaces the request.Body", func() {
			handlerCalled := make(chan struct{})
			s.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				r.Body = struct {
					io.Reader
					io.Closer
				}{}
				close(handlerCalled)
			})

			setRequest(encodeRequest(examplePostRequest))
			str.EXPECT().Context().Return(reqContext)
			str.EXPECT().Write(gomock.Any()).DoAndReturn(func(p []byte) (int, error) {
				return len(p), nil
			}).AnyTimes()
			str.EXPECT().CancelRead(quic.StreamErrorCode(errorNoError))

			serr := s.handleRequest(sess, str, qpackDecoder, nil)
			Expect(serr.err).ToNot(HaveOccurred())
			Eventually(handlerCalled).Should(BeClosed())
		})

		It("cancels the request context when the stream is closed", func() {
			handlerCalled := make(chan struct{})
			s.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				defer GinkgoRecover()
				Expect(r.Context().Done()).To(BeClosed())
				Expect(r.Context().Err()).To(MatchError(context.Canceled))
				close(handlerCalled)
			})
			setRequest(encodeRequest(examplePostRequest))

			reqContext, cancel := context.WithCancel(context.Background())
			cancel()
			str.EXPECT().Context().Return(reqContext)
			str.EXPECT().Write(gomock.Any()).DoAndReturn(func(p []byte) (int, error) {
				return len(p), nil
			}).AnyTimes()
			str.EXPECT().CancelRead(quic.StreamErrorCode(errorNoError))

			serr := s.handleRequest(sess, str, qpackDecoder, nil)
			Expect(serr.err).ToNot(HaveOccurred())
			Eventually(handlerCalled).Should(BeClosed())
		})
	})

	Context("setting http headers", func() {
		BeforeEach(func() {
			s.QuicConfig = &quic.Config{Versions: []protocol.VersionNumber{protocol.VersionDraft29}}
		})

		expected := http.Header{
			"Alt-Svc": {`h3-29=":443"; ma=2592000`},
		}

		It("sets proper headers with numeric port", func() {
			s.Server.Addr = ":443"
			hdr := http.Header{}
			Expect(s.SetQuicHeaders(hdr)).To(Succeed())
			Expect(hdr).To(Equal(expected))
		})

		It("sets proper headers with full addr", func() {
			s.Server.Addr = "127.0.0.1:443"
			hdr := http.Header{}
			Expect(s.SetQuicHeaders(hdr)).To(Succeed())
			Expect(hdr).To(Equal(expected))
		})

		It("sets proper headers with string port", func() {
			s.Server.Addr = ":https"
			hdr := http.Header{}
			Expect(s.SetQuicHeaders(hdr)).To(Succeed())
			Expect(hdr).To(Equal(expected))
		})

		It("works multiple times", func() {
			s.Server.Addr = ":https"
			hdr := http.Header{}
			Expect(s.SetQuicHeaders(hdr)).To(Succeed())
			Expect(hdr).To(Equal(expected))
			hdr = http.Header{}
			Expect(s.SetQuicHeaders(hdr)).To(Succeed())
			Expect(hdr).To(Equal(expected))
		})

		It("works if the quic.Config sets QUIC versions", func() {
			s.Server.Addr = ":443"
			s.QuicConfig.Versions = []quic.VersionNumber{quic.Version1, quic.VersionDraft29}
			hdr := http.Header{}
			Expect(s.SetQuicHeaders(hdr)).To(Succeed())
			Expect(hdr).To(Equal(http.Header{"Alt-Svc": {`h3=":443"; ma=2592000,h3-29=":443"; ma=2592000`}}))
		})
	})

	It("errors when ListenAndServe is called with s.Server nil", func() {
		Expect((&Server{}).ListenAndServe()).To(MatchError("use of http3.Server without http.Server"))
	})

	It("errors when ListenAndServeTLS is called with s.Server nil", func() {
		Expect((&Server{}).ListenAndServeTLS(testdata.GetCertificatePaths())).To(MatchError("use of http3.Server without http.Server"))
	})

	It("should nop-Close() when s.server is nil", func() {
		Expect((&Server{}).Close()).To(Succeed())
	})

	It("errors when ListenAndServe is called after Close", func() {
		serv := &Server{Server: &http.Server{}}
		Expect(serv.Close()).To(Succeed())
		Expect(serv.ListenAndServe()).To(MatchError(http.ErrServerClosed))
	})

	Context("Serve", func() {
		origQuicListen := quicListen

		AfterEach(func() {
			quicListen = origQuicListen
		})

		It("serves a packet conn", func() {
			ln := mockquic.NewMockEarlyListener(mockCtrl)
			conn := &net.UDPConn{}
			quicListen = func(c net.PacketConn, tlsConf *tls.Config, config *quic.Config) (quic.EarlyListener, error) {
				Expect(c).To(Equal(conn))
				return ln, nil
			}

			s := &Server{Server: &http.Server{}}
			s.TLSConfig = &tls.Config{}

			stopAccept := make(chan struct{})
			ln.EXPECT().Accept(gomock.Any()).DoAndReturn(func(context.Context) (quic.Session, error) {
				<-stopAccept
				return nil, errors.New("closed")
			})
			done := make(chan struct{})
			go func() {
				defer GinkgoRecover()
				defer close(done)
				s.Serve(conn)
			}()

			Consistently(done).ShouldNot(BeClosed())
			ln.EXPECT().Close().Do(func() { close(stopAccept) })
			Expect(s.Close()).To(Succeed())
			Eventually(done).Should(BeClosed())
		})

		It("serves two packet conns", func() {
			ln1 := mockquic.NewMockEarlyListener(mockCtrl)
			ln2 := mockquic.NewMockEarlyListener(mockCtrl)
			lns := make(chan quic.EarlyListener, 2)
			lns <- ln1
			lns <- ln2
			conn1 := &net.UDPConn{}
			conn2 := &net.UDPConn{}
			quicListen = func(c net.PacketConn, tlsConf *tls.Config, config *quic.Config) (quic.EarlyListener, error) {
				return <-lns, nil
			}

			s := &Server{Server: &http.Server{}}
			s.TLSConfig = &tls.Config{}

			stopAccept1 := make(chan struct{})
			ln1.EXPECT().Accept(gomock.Any()).DoAndReturn(func(context.Context) (quic.Session, error) {
				<-stopAccept1
				return nil, errors.New("closed")
			})
			stopAccept2 := make(chan struct{})
			ln2.EXPECT().Accept(gomock.Any()).DoAndReturn(func(context.Context) (quic.Session, error) {
				<-stopAccept2
				return nil, errors.New("closed")
			})

			done1 := make(chan struct{})
			go func() {
				defer GinkgoRecover()
				defer close(done1)
				s.Serve(conn1)
			}()
			done2 := make(chan struct{})
			go func() {
				defer GinkgoRecover()
				defer close(done2)
				s.Serve(conn2)
			}()

			Consistently(done1).ShouldNot(BeClosed())
			Expect(done2).ToNot(BeClosed())
			ln1.EXPECT().Close().Do(func() { close(stopAccept1) })
			ln2.EXPECT().Close().Do(func() { close(stopAccept2) })
			Expect(s.Close()).To(Succeed())
			Eventually(done1).Should(BeClosed())
			Eventually(done2).Should(BeClosed())
		})
	})

	Context("ListenAndServe", func() {
		BeforeEach(func() {
			s.Server.Addr = "localhost:0"
		})

		AfterEach(func() {
			Expect(s.Close()).To(Succeed())
		})

		checkGetConfigForClientVersions := func(conf *tls.Config) {
			c, err := conf.GetConfigForClient(&tls.ClientHelloInfo{Conn: newMockConn(protocol.VersionDraft29)})
			ExpectWithOffset(1, err).ToNot(HaveOccurred())
			ExpectWithOffset(1, c.NextProtos).To(Equal([]string{nextProtoH3Draft29}))
			c, err = conf.GetConfigForClient(&tls.ClientHelloInfo{Conn: newMockConn(protocol.Version1)})
			ExpectWithOffset(1, err).ToNot(HaveOccurred())
			ExpectWithOffset(1, c.NextProtos).To(Equal([]string{nextProtoH3}))
		}

		It("uses the quic.Config to start the QUIC server", func() {
			conf := &quic.Config{HandshakeIdleTimeout: time.Nanosecond}
			var receivedConf *quic.Config
			quicListenAddr = func(addr string, _ *tls.Config, config *quic.Config) (quic.EarlyListener, error) {
				receivedConf = config
				return nil, errors.New("listen err")
			}
			s.QuicConfig = conf
			Expect(s.ListenAndServe()).To(HaveOccurred())
			Expect(receivedConf).To(Equal(conf))
		})

		It("sets the GetConfigForClient and replaces the ALPN token to the tls.Config, if the GetConfigForClient callback is not set", func() {
			tlsConf := &tls.Config{
				ClientAuth: tls.RequireAndVerifyClientCert,
				NextProtos: []string{"foo", "bar"},
			}
			var receivedConf *tls.Config
			quicListenAddr = func(addr string, tlsConf *tls.Config, _ *quic.Config) (quic.EarlyListener, error) {
				receivedConf = tlsConf
				return nil, errors.New("listen err")
			}
			s.TLSConfig = tlsConf
			Expect(s.ListenAndServe()).To(HaveOccurred())
			Expect(receivedConf.NextProtos).To(BeEmpty())
			Expect(receivedConf.ClientAuth).To(BeZero())
			// make sure the original tls.Config was not modified
			Expect(tlsConf.NextProtos).To(Equal([]string{"foo", "bar"}))
			// make sure that the config returned from the GetConfigForClient callback sets the fields of the original config
			conf, err := receivedConf.GetConfigForClient(&tls.ClientHelloInfo{})
			Expect(err).ToNot(HaveOccurred())
			Expect(conf.ClientAuth).To(Equal(tls.RequireAndVerifyClientCert))
			checkGetConfigForClientVersions(receivedConf)
		})

		It("sets the GetConfigForClient callback if no tls.Config is given", func() {
			var receivedConf *tls.Config
			quicListenAddr = func(addr string, tlsConf *tls.Config, _ *quic.Config) (quic.EarlyListener, error) {
				receivedConf = tlsConf
				return nil, errors.New("listen err")
			}
			Expect(s.ListenAndServe()).To(HaveOccurred())
			Expect(receivedConf).ToNot(BeNil())
			checkGetConfigForClientVersions(receivedConf)
		})

		It("sets the ALPN for tls.Configs returned by the tls.GetConfigForClient", func() {
			tlsConf := &tls.Config{
				GetConfigForClient: func(ch *tls.ClientHelloInfo) (*tls.Config, error) {
					return &tls.Config{
						ClientAuth: tls.RequireAndVerifyClientCert,
						NextProtos: []string{"foo", "bar"},
					}, nil
				},
			}

			var receivedConf *tls.Config
			quicListenAddr = func(addr string, conf *tls.Config, _ *quic.Config) (quic.EarlyListener, error) {
				receivedConf = conf
				return nil, errors.New("listen err")
			}
			s.TLSConfig = tlsConf
			Expect(s.ListenAndServe()).To(HaveOccurred())
			// check that the original config was not modified
			conf, err := tlsConf.GetConfigForClient(&tls.ClientHelloInfo{})
			Expect(err).ToNot(HaveOccurred())
			Expect(conf.NextProtos).To(Equal([]string{"foo", "bar"}))
			// check that the config returned by the GetConfigForClient callback uses the returned config
			conf, err = receivedConf.GetConfigForClient(&tls.ClientHelloInfo{})
			Expect(err).ToNot(HaveOccurred())
			Expect(conf.ClientAuth).To(Equal(tls.RequireAndVerifyClientCert))
			checkGetConfigForClientVersions(receivedConf)
		})

		It("sets the ALPN for tls.Configs returned by the tls.GetConfigForClient, if it returns a static tls.Config", func() {
			tlsClientConf := &tls.Config{NextProtos: []string{"foo", "bar"}}
			tlsConf := &tls.Config{
				GetConfigForClient: func(ch *tls.ClientHelloInfo) (*tls.Config, error) {
					return tlsClientConf, nil
				},
			}

			var receivedConf *tls.Config
			quicListenAddr = func(addr string, conf *tls.Config, _ *quic.Config) (quic.EarlyListener, error) {
				receivedConf = conf
				return nil, errors.New("listen err")
			}
			s.TLSConfig = tlsConf
			Expect(s.ListenAndServe()).To(HaveOccurred())
			// check that the original config was not modified
			conf, err := tlsConf.GetConfigForClient(&tls.ClientHelloInfo{})
			Expect(err).ToNot(HaveOccurred())
			Expect(conf.NextProtos).To(Equal([]string{"foo", "bar"}))
			checkGetConfigForClientVersions(receivedConf)
		})

		It("works if GetConfigForClient returns a nil tls.Config", func() {
			tlsConf := &tls.Config{GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) { return nil, nil }}

			var receivedConf *tls.Config
			quicListenAddr = func(addr string, conf *tls.Config, _ *quic.Config) (quic.EarlyListener, error) {
				receivedConf = conf
				return nil, errors.New("listen err")
			}
			s.TLSConfig = tlsConf
			Expect(s.ListenAndServe()).To(HaveOccurred())
			conf, err := receivedConf.GetConfigForClient(&tls.ClientHelloInfo{})
			Expect(err).ToNot(HaveOccurred())
			Expect(conf).ToNot(BeNil())
			checkGetConfigForClientVersions(receivedConf)
		})
	})

	It("closes gracefully", func() {
		Expect(s.CloseGracefully(0)).To(Succeed())
	})

	It("errors when listening fails", func() {
		testErr := errors.New("listen error")
		quicListenAddr = func(addr string, tlsConf *tls.Config, config *quic.Config) (quic.EarlyListener, error) {
			return nil, testErr
		}
		fullpem, privkey := testdata.GetCertificatePaths()
		Expect(ListenAndServeQUIC("", fullpem, privkey, nil)).To(MatchError(testErr))
	})

	It("supports H3_DATAGRAM", func() {
		s.EnableDatagrams = true
		var receivedConf *quic.Config
		quicListenAddr = func(addr string, _ *tls.Config, config *quic.Config) (quic.EarlyListener, error) {
			receivedConf = config
			return nil, errors.New("listen err")
		}
		Expect(s.ListenAndServe()).To(HaveOccurred())
		Expect(receivedConf.EnableDatagrams).To(BeTrue())
	})
})
