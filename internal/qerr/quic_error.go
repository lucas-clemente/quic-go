package qerr

import (
	"fmt"
	"net"
)

// A QuicError consists of an error code plus a error reason
type QuicError struct {
	ErrorCode          ErrorCode
	ErrorMessage       string
	isTimeout          bool
	isApplicationError bool
	delayed            bool
}

var _ net.Error = &QuicError{}

// Error creates a new QuicError instance
func Error(errorCode ErrorCode, errorMessage string) *QuicError {
	return &QuicError{
		ErrorCode:    errorCode,
		ErrorMessage: errorMessage,
	}
}

// TimeoutError creates a new QuicError instance for a timeout error
func TimeoutError(errorMessage string) *QuicError {
	return &QuicError{
		ErrorMessage: errorMessage,
		isTimeout:    true,
	}
}

// CryptoError create a new QuicError instance for a crypto error
func CryptoError(tlsAlert uint8, errorMessage string) *QuicError {
	return &QuicError{
		ErrorCode:    0x100 + ErrorCode(tlsAlert),
		ErrorMessage: errorMessage,
	}
}

// ApplicationError creates a new QuicError instance for an application error
func ApplicationError(errorCode ErrorCode, errorMessage string) *QuicError {
	return &QuicError{
		ErrorCode:          errorCode,
		ErrorMessage:       errorMessage,
		isApplicationError: true,
	}
}

func (e *QuicError) Error() string {
	if e.isApplicationError {
		if len(e.ErrorMessage) == 0 {
			return fmt.Sprintf("Application error %#x", uint64(e.ErrorCode))
		}
		return fmt.Sprintf("Application error %#x: %s", uint64(e.ErrorCode), e.ErrorMessage)
	}
	if len(e.ErrorMessage) == 0 {
		return e.ErrorCode.Error()
	}
	return fmt.Sprintf("%s: %s", e.ErrorCode.String(), e.ErrorMessage)
}

// IsCryptoError says if this error is a crypto error
func (e *QuicError) IsCryptoError() bool {
	return e.ErrorCode.isCryptoError()
}

// Temporary says if the error is temporary.
func (e *QuicError) Temporary() bool {
	return false
}

// Timeout says if this error is a timeout.
func (e *QuicError) Timeout() bool {
	return e.isTimeout && !e.delayed
}

// IsAttackTimeout says if this error is an attack timeout error.
func (e *QuicError) IsAttackTimeout() bool {
	return e.isTimeout && e.delayed
}

// IsDelayedError says if this error is a delayed error
func (e *QuicError) IsDelayedError() bool {
	return e.delayed
}

// ToQuicError converts an arbitrary error to a QuicError. It leaves QuicErrors
// unchanged, and properly handles `ErrorCode`s.
func ToQuicError(err error) *QuicError {
	switch e := err.(type) {
	case *QuicError:
		return e
	case ErrorCode:
		return Error(e, "")
	}
	return Error(InternalError, err.Error())
}

// ToAttackTimeoutError converts an arbitrary error to an attack timeout error.
func ToAttackTimeoutError(err error) *QuicError {
	qErr := ToQuicError(err)
	qErr.isTimeout = true
	qErr.delayed = true
	return qErr
}

// ToDelayedError converts an arbitrary error to a delayed error.
func ToDelayedError(err error) *QuicError {
	qErr := ToQuicError(err)
	qErr.delayed = true
	return qErr
}
