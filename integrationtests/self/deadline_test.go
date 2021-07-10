package self_test

import (
	"context"
	"fmt"
	"io/ioutil"
	"net"
	"time"

	"github.com/lucas-clemente/quic-go"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Stream deadline tests", func() {
	setup := func() (quic.Listener, quic.Stream, quic.Stream) {
		server, err := quic.ListenAddr("localhost:0", getTLSConfig(), getQuicConfig(nil))
		Expect(err).ToNot(HaveOccurred())
		strChan := make(chan quic.SendStream)
		go func() {
			defer GinkgoRecover()
			sess, err := server.Accept(context.Background())
			Expect(err).ToNot(HaveOccurred())
			str, err := sess.AcceptStream(context.Background())
			Expect(err).ToNot(HaveOccurred())
			_, err = str.Read([]byte{0})
			Expect(err).ToNot(HaveOccurred())
			strChan <- str
		}()

		sess, err := quic.DialAddr(
			fmt.Sprintf("localhost:%d", server.Addr().(*net.UDPAddr).Port),
			getTLSClientConfig(),
			getQuicConfig(nil),
		)
		Expect(err).ToNot(HaveOccurred())
		clientStr, err := sess.OpenStream()
		Expect(err).ToNot(HaveOccurred())
		_, err = clientStr.Write([]byte{0}) // need to write one byte so the server learns about the stream
		Expect(err).ToNot(HaveOccurred())
		var serverStr quic.Stream
		Eventually(strChan).Should(Receive(&serverStr))
		return server, serverStr, clientStr
	}

	Context("read deadlines", func() {
		It("completes a transfer when the deadline is set", func() {
			server, serverStr, clientStr := setup()
			defer server.Close()

			const timeout = 20 * time.Millisecond
			done := make(chan struct{})
			go func() {
				defer GinkgoRecover()
				_, err := serverStr.Write(PRDataLong)
				Expect(err).ToNot(HaveOccurred())
				close(done)
			}()

			var bytesRead int
			var timeoutCounter int
			var expectedTimeouts int
			buf := make([]byte, 1<<10)
			data := make([]byte, len(PRDataLong))
			clientStr.SetReadDeadline(time.Now().Add(timeout))
			start := time.Now()
			for bytesRead < len(PRDataLong) {
				n, err := clientStr.Read(buf)
				if nerr, ok := err.(net.Error); ok && nerr.Timeout() {
					timeoutCounter++
					clientStr.SetReadDeadline(time.Now().Add(timeout))
				} else {
					Expect(err).ToNot(HaveOccurred())
				}
				if time.Since(start) >= timeout {
					expectedTimeouts++
					start = time.Now()
				}
				copy(data[bytesRead:], buf[:n])
				bytesRead += n
			}
			Expect(data).To(Equal(PRDataLong))
			// make sure the test actually worked an Read actually ran into the deadline a few times
			Expect(timeoutCounter).To(BeNumerically(">=", expectedTimeouts))
			Eventually(done).Should(BeClosed())
		})

		It("completes a transfer when the deadline is set concurrently", func() {
			server, serverStr, clientStr := setup()
			defer server.Close()

			const timeout = 20 * time.Millisecond
			go func() {
				defer GinkgoRecover()
				_, err := serverStr.Write(PRDataLong)
				Expect(err).ToNot(HaveOccurred())
			}()

			var bytesRead int
			var timeoutCounter int
			buf := make([]byte, 1<<10)
			data := make([]byte, len(PRDataLong))
			clientStr.SetReadDeadline(time.Now().Add(timeout))
			deadlineDone := make(chan struct{})
			received := make(chan struct{})
			go func() {
				defer close(deadlineDone)
				for {
					select {
					case <-received:
						return
					default:
						time.Sleep(timeout)
					}
					clientStr.SetReadDeadline(time.Now().Add(timeout))
				}
			}()

			for bytesRead < len(PRDataLong) {
				n, err := clientStr.Read(buf)
				if nerr, ok := err.(net.Error); ok && nerr.Timeout() {
					timeoutCounter++
				} else {
					Expect(err).ToNot(HaveOccurred())
				}
				copy(data[bytesRead:], buf[:n])
				bytesRead += n
			}
			close(received)
			Expect(data).To(Equal(PRDataLong))
			// make sure the test actually worked an Read actually ran into the deadline a few times
			Expect(timeoutCounter).To(BeNumerically(">=", 10))
			Eventually(deadlineDone).Should(BeClosed())
		})
	})

	Context("write deadlines", func() {
		It("completes a transfer when the deadline is set", func() {
			server, serverStr, clientStr := setup()
			defer server.Close()

			const timeout = 20 * time.Millisecond
			done := make(chan struct{})
			go func() {
				defer GinkgoRecover()
				data, err := ioutil.ReadAll(serverStr)
				Expect(err).ToNot(HaveOccurred())
				Expect(data).To(Equal(PRDataLong))
				close(done)
			}()

			var bytesWritten int
			var timeoutCounter int
			var expectedTimeouts int
			clientStr.SetWriteDeadline(time.Now().Add(timeout))
			start := time.Now()
			for bytesWritten < len(PRDataLong) {
				n, err := clientStr.Write(PRDataLong[bytesWritten:])
				if nerr, ok := err.(net.Error); ok && nerr.Timeout() {
					timeoutCounter++
					clientStr.SetWriteDeadline(time.Now().Add(timeout))
				} else {
					Expect(err).ToNot(HaveOccurred())
				}
				if time.Since(start) >= timeout {
					expectedTimeouts++
					start = time.Now()
				}
				bytesWritten += n
			}
			clientStr.Close()
			// make sure the test actually worked an Read actually ran into the deadline a few times
			Expect(timeoutCounter).To(BeNumerically(">=", expectedTimeouts))
			Eventually(done).Should(BeClosed())
		})

		It("completes a transfer when the deadline is set concurrently", func() {
			server, serverStr, clientStr := setup()
			defer server.Close()

			const timeout = 20 * time.Millisecond
			readDone := make(chan struct{})
			go func() {
				defer GinkgoRecover()
				data, err := ioutil.ReadAll(serverStr)
				Expect(err).ToNot(HaveOccurred())
				Expect(data).To(Equal(PRDataLong))
				close(readDone)
			}()

			clientStr.SetWriteDeadline(time.Now().Add(timeout))
			deadlineDone := make(chan struct{})
			received := make(chan struct{})
			go func() {
				defer close(deadlineDone)
				for {
					select {
					case <-received:
						return
					default:
						time.Sleep(timeout)
					}
					clientStr.SetWriteDeadline(time.Now().Add(timeout))
				}
			}()

			var bytesWritten int
			var timeoutCounter int
			var expectedTimeouts int
			clientStr.SetWriteDeadline(time.Now().Add(timeout))
			start := time.Now()
			for bytesWritten < len(PRDataLong) {
				n, err := clientStr.Write(PRDataLong[bytesWritten:])
				if nerr, ok := err.(net.Error); ok && nerr.Timeout() {
					timeoutCounter++
				} else {
					Expect(err).ToNot(HaveOccurred())
				}
				if time.Since(start) >= timeout {
					expectedTimeouts++
				}
				bytesWritten += n
			}
			close(received)
			clientStr.Close()
			// make sure the test actually worked an Read actually ran into the deadline a few times
			Expect(timeoutCounter).To(BeNumerically(">=", expectedTimeouts-1))
			Eventually(readDone).Should(BeClosed())
			Eventually(deadlineDone).Should(BeClosed())
		})
	})
})
