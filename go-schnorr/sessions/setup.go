package session

/*
#include "../../includes/go-schnorr.h"
#include <stdlib.h>
*/
import "C"
import (
	"runtime"
	"unsafe"

	"github.com/vultisig/go-wrappers/go-schnorr/errors"
)

// SchnorrDecodeKeyId decodes a key ID from a setup message.
//
// Parameters:
//   - setup: []byte - a byte slice containing the setup message from which the key ID will be decoded.
//
// Returns:
//   - []byte: the decoded key ID as a byte slice.
//   - error: an error if the Rust function call fails or if any other issue occurs.
func SchnorrDecodeKeyID(setup []byte) ([]byte, error) {
	pinner := new(runtime.Pinner)
	defer pinner.Unpin()

	cSetup := cGoSlice(setup, pinner)

	var cKeyID C.tss_buffer
	defer C.tss_buffer_free(&cKeyID)

	res := C.schnorr_decode_key_id(
		cSetup,
		&cKeyID,
	)
	if res != 0 {
		return nil, errors.MapLibError(int(res))
	}

	KeyID := C.GoBytes(unsafe.Pointer(cKeyID.ptr), C.int(cKeyID.len))

	return KeyID, nil
}

// SchnorrDecodeSessionId decodes a session ID from a setup message.
//
// Parameters:
//   - setup: []byte - a byte slice containing the setup message from which the session ID will be decoded.
//
// Returns:
//   - []byte: the decoded session ID as a byte slice.
//   - error: an error if the Rust function call fails or if any other issue occurs.
func SchnorrDecodeSessionID(setup []byte) ([]byte, error) {
	pinner := new(runtime.Pinner)
	defer pinner.Unpin()

	cSetup := cGoSlice(setup, pinner)

	var cMessage C.tss_buffer
	defer C.tss_buffer_free(&cMessage)

	res := C.schnorr_decode_session_id(
		cSetup,
		&cMessage,
	)
	if res != 0 {
		return nil, errors.MapLibError(int(res))
	}

	message := C.GoBytes(unsafe.Pointer(cMessage.ptr), C.int(cMessage.len))

	return message, nil
}

// SchnorrDecodeMessage decodes a message from a setup message.
//
// Parameters:
//   - setup: []byte - a byte slice containing the setup message from which the message will be decoded.
//
// Returns:
//   - []byte: the decoded message as a byte slice.
//   - error: an error if the Rust function call fails or if any other issue occurs.
func SchnorrDecodeMessage(setup []byte) ([]byte, error) {
	pinner := new(runtime.Pinner)
	defer pinner.Unpin()

	cSetup := cGoSlice(setup, pinner)

	var cMessage C.tss_buffer
	defer C.tss_buffer_free(&cMessage)

	res := C.schnorr_decode_message(
		cSetup,
		&cMessage,
	)
	if res != 0 {
		return nil, errors.MapLibError(int(res))
	}

	message := C.GoBytes(unsafe.Pointer(cMessage.ptr), C.int(cMessage.len))

	return message, nil
}

// SchnorrDecodePartyName decodes the party name from a setup message for a specified index.
//
// Parameters:
//   - setup: []byte - a byte slice containing the setup message from which the party name will be retrieved.
//   - index: uint32 - the index of the party whose name is to be decoded.
//
// Returns:
//   - []byte: the decoded party name as a byte slice.
//   - error: an error if the Rust function call fails or if any other issue occurs.
func SchnorrDecodePartyName(setup []byte, index int) ([]byte, error) {
	pinner := new(runtime.Pinner)
	defer pinner.Unpin()

	cSetup := cGoSlice(setup, pinner)

	var cMessage C.tss_buffer
	defer C.tss_buffer_free(&cMessage)

	res := C.schnorr_decode_party_name(
		cSetup,
		C.uint32_t(index),
		&cMessage,
	)
	if res != 0 {
		return nil, errors.MapLibError(int(res))
	}

	message := C.GoBytes(unsafe.Pointer(cMessage.ptr), C.int(cMessage.len))

	return message, nil
}
