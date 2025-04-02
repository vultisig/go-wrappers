// Provides Go bindings for interacting with the Rust library that handles cryptographic
// pre-signature operations within a distributed key management system. The primary
// functionalities cover the conversion and management of pre-signature data, including
// creation from byte arrays, serialization, and session identification.
//
// Key functionalities include:
// - Converting serialized pre-signature data into a handle.
// - Serializing a pre-signature handle back into byte format.
// - Retrieving a unique session ID from a pre-signature handle.
package session

/*
#include "../../includes/go-dkls.h"
#include <stdlib.h>
*/
import "C"
import (
	"runtime"
	"unsafe"

	"github.com/vultisig/go-wrapper/go-dkls/errors"
)

// DklsPresignFromBytes converts serialized pre-signature data into a pre-signature handle.
//
// Parameters:
//   - buf: []byte - a byte slice containing the serialized pre-signature data to be converted.
//
// Returns:
//   - Handle: a handle representing the converted pre-signature.
//   - error: an error if the Rust function call fails, or if there is an issue with memory allocation.
func DklsPresignFromBytes(buf []byte) (Handle, error) {
	pinner := new(runtime.Pinner)
	defer pinner.Unpin()

	cBuf := cGoSlice(buf, pinner)

	var cHnd C.Handle

	res := C.dkls_presign_from_bytes(
		cBuf,
		&cHnd,
	)
	if res != 0 {
		return 0, errors.MapLibError(int(res))
	}

	return Handle(cHnd._0), nil
}

// DklsPresignToBytes serializes a pre-signature handle into a byte slice.
//
// Parameters:
//   - share: Handle - the pre-signature handle to be serialized.
//
// Returns:
//   - []byte: a byte slice representing the serialized pre-signature data.
//   - error: an error if the Rust function call fails or if there is an issue with memory allocation.
func DklsPresignToBytes(share Handle) ([]byte, error) {
	cShare := cHandle(share)

	var cBuf C.tss_buffer
	defer C.tss_buffer_free(&cBuf)

	res := C.dkls_presign_to_bytes(
		cShare,
		&cBuf,
	)
	if res != 0 {
		return nil, errors.MapLibError(int(res))
	}

	buf := C.GoBytes(unsafe.Pointer(cBuf.ptr), C.int(cBuf.len))

	return buf, nil
}

// DklsPresignSessionID retrieves the session ID from a pre-signature handle.
//
// Parameters:
//   - share: Handle - the pre-signature handle from which to extract the session ID.
//
// Returns:
//   - []byte: a byte slice representing the session ID associated with the pre-signature.
//   - error: an error if the Rust function call fails or if there is an issue with memory allocation.
func DklsPresignSessionID(share Handle) ([]byte, error) {
	cShare := cHandle(share)

	var cBuf C.tss_buffer
	defer C.tss_buffer_free(&cBuf)

	res := C.dkls_presign_session_id(
		cShare,
		&cBuf,
	)
	if res != 0 {
		return nil, errors.MapLibError(int(res))
	}

	buf := C.GoBytes(unsafe.Pointer(cBuf.ptr), C.int(cBuf.len))

	return buf, nil
}
