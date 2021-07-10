// +build go1.15
// +build !go1.16
// +build gccgo

package qtls

import (
	"unsafe"

	qtls "github.com/marten-seemann/qtls-go1-15"
)

//go:linkname cipherSuiteTLS13ByID "github_0com_1marten_x2dseemann_1qtls_x2dgo1_x2d15.cipherSuiteTLS13ByID"
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
