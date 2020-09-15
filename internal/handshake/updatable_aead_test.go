package handshake

import (
	"crypto/rand"
	"crypto/tls"
	"fmt"
	"os"
	"time"

	mocklogging "github.com/lucas-clemente/quic-go/internal/mocks/logging"
	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/qerr"
	"github.com/lucas-clemente/quic-go/internal/qtls"
	"github.com/lucas-clemente/quic-go/internal/utils"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Updatable AEAD", func() {
	It("ChaCha test vector from the draft", func() {
		secret := splitHexString("9ac312a7f877468ebe69422748ad00a1 5443f18203a07d6060f688f30f21632b")
		aead := newUpdatableAEAD(&utils.RTTStats{}, nil, nil)
		chacha := cipherSuites[2]
		Expect(chacha.ID).To(Equal(tls.TLS_CHACHA20_POLY1305_SHA256))
		aead.SetWriteKey(chacha, secret)
		header := splitHexString("4200bff4")
		const pnOffset = 1
		payloadOffset := len(header)
		plaintext := splitHexString("01")
		payload := aead.Seal(nil, plaintext, 654360564, header)
		Expect(payload).To(Equal(splitHexString("655e5cd55c41f69080575d7999c25a5bfb")))
		packet := append(header, payload...)
		aead.EncryptHeader(packet[pnOffset+4:pnOffset+4+16], &packet[0], packet[pnOffset:payloadOffset])
		Expect(packet).To(Equal(splitHexString("4cfe4189655e5cd55c41f69080575d7999c25a5bfb")))
	})

	for i := range cipherSuites {
		cs := cipherSuites[i]

		Context(fmt.Sprintf("using %s", qtls.CipherSuiteName(cs.ID)), func() {
			var (
				client, server             *updatableAEAD
				clientTracer, serverTracer *mocklogging.MockConnectionTracer
				rttStats                   *utils.RTTStats
			)

			BeforeEach(func() {
				clientTracer = mocklogging.NewMockConnectionTracer(mockCtrl)
				serverTracer = mocklogging.NewMockConnectionTracer(mockCtrl)
				trafficSecret1 := make([]byte, 16)
				trafficSecret2 := make([]byte, 16)
				rand.Read(trafficSecret1)
				rand.Read(trafficSecret2)

				rttStats = utils.NewRTTStats()
				client = newUpdatableAEAD(rttStats, clientTracer, utils.DefaultLogger)
				server = newUpdatableAEAD(rttStats, serverTracer, utils.DefaultLogger)
				client.SetReadKey(cs, trafficSecret2)
				client.SetWriteKey(cs, trafficSecret1)
				server.SetReadKey(cs, trafficSecret1)
				server.SetWriteKey(cs, trafficSecret2)
			})

			Context("header protection", func() {
				It("encrypts and decrypts the header", func() {
					var lastFiveBitsDifferent int
					for i := 0; i < 100; i++ {
						sample := make([]byte, 16)
						rand.Read(sample)
						header := []byte{0xb5, 1, 2, 3, 4, 5, 6, 7, 8, 0xde, 0xad, 0xbe, 0xef}
						client.EncryptHeader(sample, &header[0], header[9:13])
						if header[0]&0x1f != 0xb5&0x1f {
							lastFiveBitsDifferent++
						}
						Expect(header[0] & 0xe0).To(Equal(byte(0xb5 & 0xe0)))
						Expect(header[1:9]).To(Equal([]byte{1, 2, 3, 4, 5, 6, 7, 8}))
						Expect(header[9:13]).ToNot(Equal([]byte{0xde, 0xad, 0xbe, 0xef}))
						server.DecryptHeader(sample, &header[0], header[9:13])
						Expect(header).To(Equal([]byte{0xb5, 1, 2, 3, 4, 5, 6, 7, 8, 0xde, 0xad, 0xbe, 0xef}))
					}
					Expect(lastFiveBitsDifferent).To(BeNumerically(">", 75))
				})
			})

			Context("message encryption", func() {
				var msg, ad []byte

				BeforeEach(func() {
					msg = []byte("Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.")
					ad = []byte("Donec in velit neque.")
				})

				It("encrypts and decrypts a message", func() {
					encrypted := server.Seal(nil, msg, 0x1337, ad)
					opened, err := client.Open(nil, encrypted, time.Now(), 0x1337, protocol.KeyPhaseZero, ad)
					Expect(err).ToNot(HaveOccurred())
					Expect(opened).To(Equal(msg))
				})

				It("saves the first packet number", func() {
					client.Seal(nil, msg, 0x1337, ad)
					Expect(client.FirstPacketNumber()).To(Equal(protocol.PacketNumber(0x1337)))
					client.Seal(nil, msg, 0x1338, ad)
					Expect(client.FirstPacketNumber()).To(Equal(protocol.PacketNumber(0x1337)))
				})

				It("fails to open a message if the associated data is not the same", func() {
					encrypted := client.Seal(nil, msg, 0x1337, ad)
					_, err := server.Open(nil, encrypted, time.Now(), 0x1337, protocol.KeyPhaseZero, []byte("wrong ad"))
					Expect(err).To(MatchError(ErrDecryptionFailed))
				})

				It("fails to open a message if the packet number is not the same", func() {
					encrypted := server.Seal(nil, msg, 0x1337, ad)
					_, err := client.Open(nil, encrypted, time.Now(), 0x42, protocol.KeyPhaseZero, ad)
					Expect(err).To(MatchError(ErrDecryptionFailed))
				})

				It("returns an AEAD_LIMIT_REACHED error when reaching the AEAD limit", func() {
					client.invalidPacketLimit = 10
					for i := 0; i < 9; i++ {
						_, err := client.Open(nil, []byte("foobar"), time.Now(), protocol.PacketNumber(i), protocol.KeyPhaseZero, []byte("ad"))
						Expect(err).To(MatchError(ErrDecryptionFailed))
					}
					_, err := client.Open(nil, []byte("foobar"), time.Now(), 10, protocol.KeyPhaseZero, []byte("ad"))
					Expect(err).To(MatchError(qerr.AEADLimitReached))
				})

				Context("key updates", func() {
					Context("receiving key updates", func() {
						It("updates keys", func() {
							now := time.Now()
							Expect(server.KeyPhase()).To(Equal(protocol.KeyPhaseZero))
							encrypted0 := server.Seal(nil, msg, 0x1337, ad)
							server.rollKeys()
							Expect(server.KeyPhase()).To(Equal(protocol.KeyPhaseOne))
							encrypted1 := server.Seal(nil, msg, 0x1337, ad)
							Expect(encrypted0).ToNot(Equal(encrypted1))
							// expect opening to fail. The client didn't roll keys yet
							_, err := client.Open(nil, encrypted1, now, 0x1337, protocol.KeyPhaseZero, ad)
							Expect(err).To(MatchError(ErrDecryptionFailed))
							client.rollKeys()
							decrypted, err := client.Open(nil, encrypted1, now, 0x1337, protocol.KeyPhaseOne, ad)
							Expect(err).ToNot(HaveOccurred())
							Expect(decrypted).To(Equal(msg))
						})

						It("updates the keys when receiving a packet with the next key phase", func() {
							now := time.Now()
							// receive the first packet at key phase zero
							encrypted0 := client.Seal(nil, msg, 0x42, ad)
							decrypted, err := server.Open(nil, encrypted0, now, 0x42, protocol.KeyPhaseZero, ad)
							Expect(err).ToNot(HaveOccurred())
							Expect(decrypted).To(Equal(msg))
							// send one packet at key phase zero
							Expect(server.KeyPhase()).To(Equal(protocol.KeyPhaseZero))
							_ = server.Seal(nil, msg, 0x1, ad)
							// now received a message at key phase one
							client.rollKeys()
							encrypted1 := client.Seal(nil, msg, 0x43, ad)
							serverTracer.EXPECT().UpdatedKey(protocol.KeyPhase(1), true)
							decrypted, err = server.Open(nil, encrypted1, now, 0x43, protocol.KeyPhaseOne, ad)
							Expect(err).ToNot(HaveOccurred())
							Expect(decrypted).To(Equal(msg))
							Expect(server.KeyPhase()).To(Equal(protocol.KeyPhaseOne))
						})

						It("opens a reordered packet with the old keys after an update", func() {
							now := time.Now()
							encrypted01 := client.Seal(nil, msg, 0x42, ad)
							encrypted02 := client.Seal(nil, msg, 0x43, ad)
							// receive the first packet with key phase 0
							_, err := server.Open(nil, encrypted01, now, 0x42, protocol.KeyPhaseZero, ad)
							Expect(err).ToNot(HaveOccurred())
							// send one packet at key phase zero
							_ = server.Seal(nil, msg, 0x1, ad)
							// now receive a packet with key phase 1
							client.rollKeys()
							encrypted1 := client.Seal(nil, msg, 0x44, ad)
							Expect(server.KeyPhase()).To(Equal(protocol.KeyPhaseZero))
							serverTracer.EXPECT().UpdatedKey(protocol.KeyPhase(1), true)
							_, err = server.Open(nil, encrypted1, now, 0x44, protocol.KeyPhaseOne, ad)
							Expect(err).ToNot(HaveOccurred())
							Expect(server.KeyPhase()).To(Equal(protocol.KeyPhaseOne))
							// now receive a reordered packet with key phase 0
							decrypted, err := server.Open(nil, encrypted02, now, 0x43, protocol.KeyPhaseZero, ad)
							Expect(err).ToNot(HaveOccurred())
							Expect(decrypted).To(Equal(msg))
							Expect(server.KeyPhase()).To(Equal(protocol.KeyPhaseOne))
						})

						It("drops keys 3 PTOs after a key update", func() {
							now := time.Now()
							rttStats.UpdateRTT(10*time.Millisecond, 0, now)
							pto := rttStats.PTO(true)
							encrypted01 := client.Seal(nil, msg, 0x42, ad)
							encrypted02 := client.Seal(nil, msg, 0x43, ad)
							// receive the first packet with key phase 0
							_, err := server.Open(nil, encrypted01, now, 0x42, protocol.KeyPhaseZero, ad)
							Expect(err).ToNot(HaveOccurred())
							// send one packet at key phase zero
							_ = server.Seal(nil, msg, 0x1, ad)
							// now receive a packet with key phase 1
							client.rollKeys()
							encrypted1 := client.Seal(nil, msg, 0x44, ad)
							Expect(server.KeyPhase()).To(Equal(protocol.KeyPhaseZero))
							serverTracer.EXPECT().UpdatedKey(protocol.KeyPhase(1), true)
							serverTracer.EXPECT().DroppedKey(protocol.KeyPhase(0))
							_, err = server.Open(nil, encrypted1, now, 0x44, protocol.KeyPhaseOne, ad)
							Expect(err).ToNot(HaveOccurred())
							Expect(server.KeyPhase()).To(Equal(protocol.KeyPhaseOne))
							// now receive a reordered packet with key phase 0
							_, err = server.Open(nil, encrypted02, now.Add(3*pto).Add(time.Nanosecond), 0x43, protocol.KeyPhaseZero, ad)
							Expect(err).To(MatchError(ErrKeysDropped))
						})

						It("errors when the peer starts with key phase 1", func() {
							client.rollKeys()
							encrypted := client.Seal(nil, msg, 0x1337, ad)
							_, err := server.Open(nil, encrypted, time.Now(), 0x1337, protocol.KeyPhaseOne, ad)
							Expect(err).To(MatchError("KEY_UPDATE_ERROR: wrong initial key phase"))
						})

						It("only errors when the peer starts with key phase 1 if decrypting the packet succeeds", func() {
							client.rollKeys()
							encrypted := client.Seal(nil, msg, 0x1337, ad)
							encrypted = encrypted[:len(encrypted)-1]
							_, err := server.Open(nil, encrypted, time.Now(), 0x1337, protocol.KeyPhaseOne, ad)
							Expect(err).To(MatchError(ErrDecryptionFailed))
						})

						It("errors when the peer updates keys too frequently", func() {
							// receive the first packet at key phase zero
							encrypted0 := client.Seal(nil, msg, 0x42, ad)
							_, err := server.Open(nil, encrypted0, time.Now(), 0x42, protocol.KeyPhaseZero, ad)
							Expect(err).ToNot(HaveOccurred())
							// now receive a packet at key phase one, before having sent any packets
							client.rollKeys()
							encrypted1 := client.Seal(nil, msg, 0x42, ad)
							_, err = server.Open(nil, encrypted1, time.Now(), 0x42, protocol.KeyPhaseOne, ad)
							Expect(err).To(MatchError("KEY_UPDATE_ERROR: keys updated too quickly"))
						})
					})

					Context("initiating key updates", func() {
						const keyUpdateInterval = 20

						BeforeEach(func() {
							Expect(server.keyUpdateInterval).To(BeEquivalentTo(protocol.KeyUpdateInterval))
							server.keyUpdateInterval = keyUpdateInterval
						})

						It("initiates the first key update as soon as possible", func() {
							for i := 0; i < 10; i++ {
								pn := protocol.PacketNumber(i)
								Expect(server.KeyPhase()).To(Equal(protocol.KeyPhaseZero))
								server.Seal(nil, msg, pn, ad)
							}
							// now receive a packet with this key phase
							server.SetLargestAcked(5)
							serverTracer.EXPECT().UpdatedKey(protocol.KeyPhase(1), false)
							Expect(server.KeyPhase()).To(Equal(protocol.KeyPhaseOne))
						})

						It("initiates a key update after sealing the maximum number of packets", func() {
							// The first key update is initiated as soon as possible.
							Expect(server.KeyPhase()).To(Equal(protocol.KeyPhaseZero))
							server.Seal(nil, msg, 0, ad)
							serverTracer.EXPECT().UpdatedKey(protocol.KeyPhase(1), false)
							server.SetLargestAcked(0)
							Expect(server.KeyPhase()).To(Equal(protocol.KeyPhaseOne))
							// Now make sure that we initiate the next key update.
							for i := 1; i <= keyUpdateInterval; i++ {
								pn := protocol.PacketNumber(i)
								Expect(server.KeyPhase()).To(Equal(protocol.KeyPhaseOne))
								server.Seal(nil, msg, pn, ad)
								server.SetLargestAcked(pn)
							}
							serverTracer.EXPECT().UpdatedKey(protocol.KeyPhase(2), false)
							Expect(server.KeyPhase()).To(Equal(protocol.KeyPhaseZero))
						})

						It("only initiates a key update after receiving an acknowledgement", func() {
							for i := 0; i < keyUpdateInterval; i++ {
								pn := protocol.PacketNumber(i)
								Expect(server.KeyPhase()).To(Equal(protocol.KeyPhaseZero))
								server.Seal(nil, msg, pn, ad)
							}
							// no update allowed before receiving an acknowledgement for the current key phase
							Expect(server.KeyPhase()).To(Equal(protocol.KeyPhaseZero))
							server.SetLargestAcked(0)
							serverTracer.EXPECT().UpdatedKey(protocol.KeyPhase(1), false)
							Expect(server.KeyPhase()).To(Equal(protocol.KeyPhaseOne))
						})

						It("initiates a key update after opening the maximum number of packets", func() {
							for i := 0; i < keyUpdateInterval; i++ {
								pn := protocol.PacketNumber(i)
								Expect(server.KeyPhase()).To(Equal(protocol.KeyPhaseZero))
								encrypted := client.Seal(nil, msg, pn, ad)
								_, err := server.Open(nil, encrypted, time.Now(), pn, protocol.KeyPhaseZero, ad)
								Expect(err).ToNot(HaveOccurred())
							}
							// no update allowed before receiving an acknowledgement for the current key phase
							Expect(server.KeyPhase()).To(Equal(protocol.KeyPhaseZero))
							server.Seal(nil, msg, 1, ad)
							server.SetLargestAcked(1)
							serverTracer.EXPECT().UpdatedKey(protocol.KeyPhase(1), false)
							Expect(server.KeyPhase()).To(Equal(protocol.KeyPhaseOne))
						})

						It("drops keys 3 PTOs after a key update", func() {
							now := time.Now()
							Expect(server.KeyPhase()).To(Equal(protocol.KeyPhaseZero))
							server.Seal(nil, msg, 0, ad)
							server.SetLargestAcked(0)
							serverTracer.EXPECT().UpdatedKey(protocol.KeyPhase(1), false)
							Expect(server.KeyPhase()).To(Equal(protocol.KeyPhaseOne))
							// Now we've initiated the first key update.
							// Decrypt a message sent from the client more than 3 PTO later to make sure the key is still there
							threePTO := 3 * rttStats.PTO(false)
							dataKeyPhaseZero := client.Seal(nil, msg, 1, ad)
							_, err := server.Open(nil, dataKeyPhaseZero, now.Add(threePTO).Add(time.Second), 1, protocol.KeyPhaseZero, ad)
							Expect(err).ToNot(HaveOccurred())
							// Now receive a packet with key phase 1.
							// This should start the timer to drop the keys after 3 PTOs.
							client.rollKeys()
							dataKeyPhaseOne := client.Seal(nil, msg, 10, ad)
							t := now.Add(threePTO).Add(time.Second)
							_, err = server.Open(nil, dataKeyPhaseOne, t, 10, protocol.KeyPhaseOne, ad)
							Expect(err).ToNot(HaveOccurred())
							// Make sure the keys are still here.
							_, err = server.Open(nil, dataKeyPhaseZero, t.Add(threePTO*9/10), 1, protocol.KeyPhaseZero, ad)
							Expect(err).ToNot(HaveOccurred())
							serverTracer.EXPECT().DroppedKey(protocol.KeyPhase(0))
							_, err = server.Open(nil, dataKeyPhaseZero, t.Add(threePTO).Add(time.Nanosecond), 1, protocol.KeyPhaseZero, ad)
							Expect(err).To(MatchError(ErrKeysDropped))
						})

						It("doesn't drop the first key generation too early", func() {
							now := time.Now()
							data1 := client.Seal(nil, msg, 1, ad)
							_, err := server.Open(nil, data1, now, 1, protocol.KeyPhaseZero, ad)
							Expect(err).ToNot(HaveOccurred())
							for i := 0; i < keyUpdateInterval; i++ {
								pn := protocol.PacketNumber(i)
								Expect(server.KeyPhase()).To(Equal(protocol.KeyPhaseZero))
								server.Seal(nil, msg, pn, ad)
								server.SetLargestAcked(pn)
							}
							serverTracer.EXPECT().UpdatedKey(protocol.KeyPhase(1), false)
							Expect(server.KeyPhase()).To(Equal(protocol.KeyPhaseOne))
							// The server never received a packet at key phase 1.
							// Make sure the key phase 0 is still there at a much later point.
							data2 := client.Seal(nil, msg, 1, ad)
							_, err = server.Open(nil, data2, now.Add(10*rttStats.PTO(true)), 1, protocol.KeyPhaseZero, ad)
							Expect(err).ToNot(HaveOccurred())
						})
					})

					Context("reading the key update env", func() {
						AfterEach(func() {
							os.Setenv(keyUpdateEnv, "")
							setKeyUpdateInterval()
						})

						It("uses the default value if the env is not set", func() {
							setKeyUpdateInterval()
							Expect(keyUpdateInterval).To(BeEquivalentTo(protocol.KeyUpdateInterval))
						})

						It("uses the env", func() {
							os.Setenv(keyUpdateEnv, "1337")
							setKeyUpdateInterval()
							Expect(keyUpdateInterval).To(BeEquivalentTo(1337))
						})

						It("panics when it can't parse the env", func() {
							os.Setenv(keyUpdateEnv, "foobar")
							Expect(setKeyUpdateInterval).To(Panic())
						})
					})
				})
			})
		})
	}
})
