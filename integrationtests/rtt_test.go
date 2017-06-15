package integrationtests

import (
	"bufio"
	"bytes"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strconv"
	"time"

	_ "github.com/lucas-clemente/quic-clients" // download clients
	"github.com/lucas-clemente/quic-go/integrationtests/proxy"
	"github.com/lucas-clemente/quic-go/internal/utils"
	"github.com/lucas-clemente/quic-go/protocol"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	. "github.com/onsi/gomega/gexec"
)

var _ = Describe("non-zero RTT", func() {
	BeforeEach(func() {
		dataMan.GenerateData(dataLen)
	})

	var proxy *quicproxy.QuicProxy

	// Default timeout_s was 20
	runRTTTest := func(rtt time.Duration, version protocol.VersionNumber, timeout_s int) {
		var err error
		proxy, err = quicproxy.NewQuicProxy("localhost:", quicproxy.Opts{
			RemoteAddr: "localhost:" + port,
			DelayPacket: func(_ quicproxy.Direction, _ protocol.PacketNumber) time.Duration {
				return rtt / 2
			},
		})
		Expect(err).ToNot(HaveOccurred())

		command := exec.Command(
			clientPath,
			"--quic-version="+strconv.Itoa(int(version)),
			"--host=127.0.0.1",
			"--port="+strconv.Itoa(proxy.LocalPort()),
			"https://quic.clemente.io/data",
		)

		session, err := Start(command, nil, GinkgoWriter)
		Expect(err).NotTo(HaveOccurred())
		defer session.Kill()
		Eventually(session, timeout_s).Should(Exit(0))
		Expect(bytes.Contains(session.Out.Contents(), dataMan.GetData())).To(BeTrue())
	}

	AfterEach(func() {
		err := proxy.Close()
		Expect(err).ToNot(HaveOccurred())
		time.Sleep(time.Millisecond)
	})

	for i := range protocol.SupportedVersions {
		version := protocol.SupportedVersions[i]

		Context(fmt.Sprintf("with quic version %d", version), func() {
			It("gets a file with 10ms RTT", func() {
				runRTTTest(10*time.Millisecond, version, 20)
			})

			fileSizes := [...]int{dataLen, 5 * 1024 * 1024, dataLongLen}
			for _, fileSize := range fileSizes {
				fileSizeMB := fmt.Sprintf("%.2f", float64(fileSize)/1024/1024)
				It("gets a "+fileSizeMB+"MB file with 75ms RTT", func() {
					flags := log.Flags()
					log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds)
					utils.SetLogLevel(utils.LogLevelDebug)
					dataMan.GenerateData(fileSize)
					runRTTTest(rtt, version, 30) // run test with larger timeout
					utils.SetLogLevel(utils.LogLevelNothing)
					log.SetFlags(flags)
				})
			}
		})
	}
})
