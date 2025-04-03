// Provides implementation for interacting with key share handles.
//
// Includes functions to manage key shares, allowing conversions between key shares and byte slices,
// retrieval of public keys and key IDs.
//
// Key functionalities include:
// - Constructing a key share from a byte slice
// - Converting a key share to a byte slice
// - Retrieving the public key associated with a key share
// - Obtaining the key ID of a key share
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

// SchnorrKeyshareFromBytes provides a keyshare handle from a byte buffer.
//
// Parameters:
//   - buf: []byte - a byte slice containing keyshare data.
//
// Returns:
//   - Handle: a handle representing the output keyshare.
//   - error: an error if the Rust function call fails or if any other issue occurs.
func SchnorrKeyshareFromBytes(buf []byte) (Handle, error) {
	pinner := new(runtime.Pinner)
	defer pinner.Unpin()

	cBuffer := cGoSlice(buf, pinner)

	var cHnd C.Handle

	res := C.schnorr_keyshare_from_bytes(
		cBuffer,
		&cHnd,
	)
	if res != 0 {
		return 0, errors.MapLibError(int(res))
	}

	return Handle(cHnd._0), nil
}

// SchnorrKeyshareToBytes converts a keyshare handle to a byte slice.
//
// Parameters:
//   - share: Handle - a handle representing the keyshare to be converted.
//
// Returns:
//   - []byte: a byte slice containing the serialized keyshare data.
//   - error: an error if the Rust function call fails or if any other issue occurs.
func SchnorrKeyshareToBytes(share Handle) ([]byte, error) {
	cShare := cHandle(share)

	var cBuffer C.tss_buffer
	defer C.tss_buffer_free(&cBuffer)

	res := C.schnorr_keyshare_to_bytes(
		cShare,
		&cBuffer,
	)
	if res != 0 {
		return nil, errors.MapLibError(int(res))
	}

	buf := C.GoBytes(unsafe.Pointer(cBuffer.ptr), C.int(cBuffer.len))

	return buf, nil
}

// SchnorrKeysharePublicKey retrieves the public key associated with a keyshare handle.
//
// Parameters:
//   - share: Handle - a handle representing the keyshare whose public key is to be retrieved.
//
// Returns:
//   - []byte: a byte slice containing the serialized public key.
//   - error: an error if the Rust function call fails or if any other issue occurs.
func SchnorrKeysharePublicKey(share Handle) ([]byte, error) {
	cShare := cHandle(share)

	var cBuffer C.tss_buffer
	defer C.tss_buffer_free(&cBuffer)

	res := C.schnorr_keyshare_public_key(
		cShare,
		&cBuffer,
	)
	if res != 0 {
		return nil, errors.MapLibError(int(res))
	}

	buf := C.GoBytes(unsafe.Pointer(cBuffer.ptr), C.int(cBuffer.len))

	return buf, nil
}

// SchnorrKeyshareKeyId retrieves the key ID associated with a given keyshare handle.
//
// Parameters:
//   - share: Handle - a handle representing the keyshare from which the key ID will be retrieved.
//
// Returns:
//   - []byte: a byte slice containing the key ID associated with the keyshare.
//   - error: an error if the Rust function call fails or if any other issue occurs.
func SchnorrKeyshareKeyID(share Handle) ([]byte, error) {
	cShare := cHandle(share)

	var cBuffer C.tss_buffer
	defer C.tss_buffer_free(&cBuffer)

	res := C.schnorr_keyshare_key_id(
		cShare,
		&cBuffer,
	)
	if res != 0 {
		return nil, errors.MapLibError(int(res))
	}

	retBuf := C.GoBytes(unsafe.Pointer(cBuffer.ptr), C.int(cBuffer.len))

	return retBuf, nil
}

// SchnorrKeyshareChainCode retrieves the key ID associated with a given keyshare handle.
//
// Parameters:
//   - share: Handle - a handle representing the keyshare from which the key ID will be retrieved.
//
// Returns:
//   - []byte: a byte slice containing the chaincode associated with the keyshare.
//   - error: an error if the Rust function call fails or if any other issue occurs.
func SchnorrKeyshareChainCode(share Handle) ([]byte, error) {
	cShare := cHandle(share)

	var cBuffer C.tss_buffer
	defer C.tss_buffer_free(&cBuffer)

	res := C.schnorr_keyshare_chaincode(
		cShare,
		&cBuffer,
	)
	if res != 0 {
		return nil, errors.MapLibError(int(res))
	}

	retBuf := C.GoBytes(unsafe.Pointer(cBuffer.ptr), C.int(cBuffer.len))

	return retBuf, nil
}
