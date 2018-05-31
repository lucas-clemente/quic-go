package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/big"

	quic "github.com/lucas-clemente/quic-go"
	"github.com/lucas-clemente/quic-go/qtrace"
)

const addr = "localhost:4242"

const message = "foobar"

// We use the same code as in example/echo, but attached the Tracer.
func main() {
	config := quic.Config{
		QuicTracer: qtrace.Tracer{
			GotPacket:              GotPacket,
			SentPacket:             SentPacket,
			ClientSentCHLO:         HandshakeMsg,
			ClientGotHandshakeMsg:  HandshakeMsg,
			ServerSentCHLO:         HandshakeMsg,
			ServerSentInchoateCHLO: HandshakeMsg,
			ServerGotHandshakeMsg:  HandshakeMsg,
		},
	}

	go func() { log.Fatal(echoServer(&config)) }()

	err := clientMain(&config)
	if err != nil {
		panic(err)
	}
}

// Start a server that echos all data on the first stream opened by the client
func echoServer(config *quic.Config) error {
	listener, err := quic.ListenAddr(addr, generateTLSConfig(), config)
	if err != nil {
		return err
	}
	sess, err := listener.Accept()
	if err != nil {
		return err
	}
	stream, err := sess.AcceptStream()
	if err != nil {
		panic(err)
	}
	// Echo through the loggingWriter
	_, err = io.Copy(loggingWriter{stream}, stream)
	return err
}

func clientMain(config *quic.Config) error {
	session, err := quic.DialAddr(addr, &tls.Config{InsecureSkipVerify: true}, config)
	if err != nil {
		return err
	}

	stream, err := session.OpenStreamSync()
	if err != nil {
		return err
	}

	fmt.Printf("Client: Sending '%s'\n", message)
	_, err = stream.Write([]byte(message))
	if err != nil {
		return err
	}

	buf := make([]byte, len(message))
	_, err = io.ReadFull(stream, buf)
	if err != nil {
		return err
	}
	fmt.Printf("Client: Got '%s'\n", buf)

	return nil
}

// A wrapper for io.Writer that also logs the message.
type loggingWriter struct{ io.Writer }

func (w loggingWriter) Write(b []byte) (int, error) {
	fmt.Printf("Server: Got '%s'\n", string(b))
	return w.Writer.Write(b)
}

// Setup a bare-bones TLS config for the server
func generateTLSConfig() *tls.Config {
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		panic(err)
	}
	template := x509.Certificate{SerialNumber: big.NewInt(1)}
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		panic(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		panic(err)
	}
	return &tls.Config{Certificates: []tls.Certificate{tlsCert}}
}

/*********************
 *** Trace Handler ***
 *********************/
func GotPacket(raw []byte, encryptionLevel int){
	fmt.Println("GotPacket:")
	fmt.Println("  Encryption:\t", encryptionLevel)
	fmt.Println("  Raw:\t\t", len(raw), "Bytes")
}

func SentPacket(raw []byte, encryptionLevel int, number uint64){
	fmt.Println("SentPacket ")
	fmt.Println("  Number:\t", number)
	fmt.Println("  Encryption:\t", encryptionLevel)
	fmt.Println("  Raw:\t\t", len(raw), "Bytes")
}

func HandshakeMsg(message qtrace.TracerHandshakeMessage){
	fmt.Println("HandshakeMsg")
	fmt.Println("  Message:\t\t", message)
}
