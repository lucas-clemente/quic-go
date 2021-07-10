// +build go1.16
// +build gc

package qtls

import (
	"unsafe"

	qtls "github.com/marten-seemann/qtls-go1-16"
)

//go:linkname cipherSuiteTLS13ByID github.com/marten-seemann/qtls-go1-16.cipherSuiteTLS13ByID
func cipherSuiteTLS13ByID(id uint16) *cipherSuiteTLS13

// CipherSuiteTLS13ByID gets a TLS 1.3 cipher suite.
func CipherSuiteTLS13ByID(id uint16) *CipherSuiteTLS13 {
	val := cipherSuiteTLS13ByID(id)
	cs := (*cipherSuiteTLS13)(unsafe.Pointer(val))
	return &qtls.CipherSuiteTLS13{
		ID:     cs.ID,
		KeyLen: cs.KeyLen,
		AEAD:   cs.AEAD,
		Hash:   cs.Hash,
	}
}
