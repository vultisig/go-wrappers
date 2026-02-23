package mldsa

// #include "../includes/vs-core.h"
// #include <stdlib.h>
// #include "vs-core-result.h"
//
// static result decode_key_id(go_slice setup) {
//      result res = {0};
//
//      res.error = mldsa_decode_key_id(
//          slice_ptr(setup),
//          &res.buffer
//      );
//
//      return res;
// }
//
// static result decode_message(go_slice setup) {
//      result res = {0};
//
//      res.error = mldsa_decode_message(
//          slice_ptr(setup),
//          &res.buffer
//      );
//
//      return res;
// }
//
// static result decode_party_name(go_slice setup, uint32_t index) {
//      result res = {0};
//
//      res.error = mldsa_decode_party_name(
//          slice_ptr(setup),
//          index,
//          &res.buffer
//      );
//
//      return res;
// }
//
import "C"
import (
	"runtime"
	"unsafe"
)

// MldsaDecodeKeyID decodes a key ID from a setup message.
//
// Parameters:
//   - setup: []byte - a byte slice containing the setup message from which
//     the key ID will be
//     decoded.
//
// Returns:
//   - []byte: the decoded key ID as a byte slice.
//   - error: an error if the Rust function call fails or if any other issue
//     occurs.
func MldsaDecodeKeyID(setup []byte) ([]byte, error) {
	res := C.decode_key_id(newGoSlice(setup))
	defer freeTssBuffer(res.buffer)

	if res.error != 0 {
		return nil, mapLibError(res.error)
	}

	keyID := C.GoBytes(
		unsafe.Pointer(res.buffer.ptr),
		C.int(res.buffer.len),
	)

	runtime.KeepAlive(setup)

	return keyID, nil
}

// MldsaDecodeMessage decodes a message from a setup message.
//
// Parameters:
//   - setup: []byte - a byte slice containing the setup message from which
//     the message will be
//     decoded.
//
// Returns:
//   - []byte: the decoded message as a byte slice.
//   - error: an error if the Rust function call fails or if any other issue
//     occurs.
func MldsaDecodeMessage(setup []byte) ([]byte, error) {
	res := C.decode_message(newGoSlice(setup))
	defer freeTssBuffer(res.buffer)

	if res.error != 0 {
		return nil, mapLibError(res.error)
	}

	message := C.GoBytes(
		unsafe.Pointer(res.buffer.ptr),
		C.int(res.buffer.len),
	)

	runtime.KeepAlive(setup)

	return message, nil
}

// MldsaDecodePartyName decodes the party name from a setup message for a
// specified index.
//
// Parameters:
//   - setup: []byte - a byte slice containing the setup message from which
//     the party name will be
//     retrieved.
//   - index: uint32 - the index of the party whose name is to be decoded.
//
// Returns:
//   - []byte: the decoded party name as a byte slice.
//   - error: an error if the Rust function call fails or if any other issue
//     occurs.
func MldsaDecodePartyName(setup []byte, index int) ([]byte, error) {
	res := C.decode_party_name(newGoSlice(setup), C.uint32_t(index))
	defer freeTssBuffer(res.buffer)

	if res.error != 0 {
		return nil, mapLibError(res.error)
	}

	message := C.GoBytes(
		unsafe.Pointer(res.buffer.ptr),
		C.int(res.buffer.len),
	)

	runtime.KeepAlive(setup)

	return message, nil
}
