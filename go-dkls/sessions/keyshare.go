// Provides implementation for interacting with key share handles.
//
// Includes functions to manage key shares, allowing conversions between key shares and byte slices,
// retrieval of public keys and key IDs, and derivation of child keys from a root private key.
//
// Key functionalities include:
// - Constructing a key share from a byte slice
// - Converting a key share to a byte slice
// - Retrieving the public key associated with a key share
// - Obtaining the key ID of a key share
// - Deriving a hierarchical family of keys from a root private key
// - Freeing resources associated with key shares
package session

/*
#include "../../includes/go-dkls.h"
#include <stdlib.h>
*/
import "C"
import (
	"go-wrapper/go-dkls/errors"
	"runtime"
	"unsafe"
)

// DklsKeyshareFromBytes provides a keyshare handle from a byte buffer.
//
// Parameters:
//   - buf: []byte - a byte slice containing keyshare data.
//
// Returns:
//   - Handle: a handle representing the output keyshare.
//   - error: an error if the Rust function call fails or if any other issue occurs.
func DklsKeyshareFromBytes(buf []byte) (Handle, error) {
	pinner := new(runtime.Pinner)
	defer pinner.Unpin()

	cBuffer := cGoSlice(buf, pinner)

	var cHnd C.Handle

	res := C.dkls_keyshare_from_bytes(
		cBuffer,
		&cHnd,
	)
	if res != 0 {
		return 0, errors.MapLibError(int(res))
	}

	return Handle(cHnd._0), nil
}

// DklsKeyshareToBytes converts a keyshare handle to a byte slice.
//
// Parameters:
//   - share: Handle - a handle representing the keyshare to be converted.
//
// Returns:
//   - []byte: a byte slice containing the serialized keyshare data.
//   - error: an error if the Rust function call fails or if any other issue occurs.
func DklsKeyshareToBytes(share Handle) ([]byte, error) {
	cShare := cHandle(share)

	var cBuffer C.tss_buffer
	defer C.tss_buffer_free(&cBuffer)

	res := C.dkls_keyshare_to_bytes(
		cShare,
		&cBuffer,
	)
	if res != 0 {
		return nil, errors.MapLibError(int(res))
	}

	buf := C.GoBytes(unsafe.Pointer(cBuffer.ptr), C.int(cBuffer.len))

	return buf, nil
}

// DklsKeysharePublicKey retrieves the public key associated with a keyshare handle.
//
// Parameters:
//   - share: Handle - a handle representing the keyshare whose public key is to be retrieved.
//
// Returns:
//   - []byte: a byte slice containing the serialized public key.
//   - error: an error if the Rust function call fails or if any other issue occurs.
func DklsKeysharePublicKey(share Handle) ([]byte, error) {
	cShare := cHandle(share)

	var cBuffer C.tss_buffer
	defer C.tss_buffer_free(&cBuffer)

	res := C.dkls_keyshare_public_key(
		cShare,
		&cBuffer,
	)
	if res != 0 {
		return nil, errors.MapLibError(int(res))
	}

	buf := C.GoBytes(unsafe.Pointer(cBuffer.ptr), C.int(cBuffer.len))

	return buf, nil
}

// DklsKeyshareKeyID retrieves the key ID associated with a given keyshare handle.
//
// Parameters:
//   - share: Handle - a handle representing the keyshare from which the key ID will be retrieved.
//
// Returns:
//   - []byte: a byte slice containing the key ID associated with the keyshare.
//   - error: an error if the Rust function call fails or if any other issue occurs.
func DklsKeyshareKeyID(share Handle) ([]byte, error) {
	cShare := cHandle(share)

	var cBuffer C.tss_buffer
	defer C.tss_buffer_free(&cBuffer)

	res := C.dkls_keyshare_key_id(
		cShare,
		&cBuffer,
	)
	if res != 0 {
		return nil, errors.MapLibError(int(res))
	}

	retBuf := C.GoBytes(unsafe.Pointer(cBuffer.ptr), C.int(cBuffer.len))

	return retBuf, nil
}

// DklsKeyshareDeriveChildPublicKey derives a child public key based on a keyshare handle and
// a specified derivation path.
//
// Parameters:
//   - share: Handle - a handle representing the root keyshare from which the child key will be derived.
//   - derivationPathStr: []byte - a byte slice representing the derivation path for the child key.
//
// Returns:
//   - []byte: a byte slice containing the derived child public key.
//   - error: an error if the Rust function call fails or if any other issue occurs.
func DklsKeyshareDeriveChildPublicKey(share Handle, derivationPathStr []byte) ([]byte, error) {
	pinner := new(runtime.Pinner)
	defer pinner.Unpin()

	cShare := cHandle(share)
	cDerivationPathStr := cTssBuffer(derivationPathStr, pinner)

	var cBuffer C.tss_buffer
	defer C.tss_buffer_free(&cBuffer)

	res := C.dkls_keyshare_derive_child_public_key(
		cShare,
		cDerivationPathStr,
		&cBuffer,
	)
	if res != 0 {
		return nil, errors.MapLibError(int(res))
	}

	retBuf := C.GoBytes(unsafe.Pointer(cBuffer.ptr), C.int(cBuffer.len))

	return retBuf, nil
}

// DklsKeyshareToRefreshBytes serializes a keyshare handle into a byte slice for use in key refresh operations.
//
// Parameters:
//   - share: Handle - a handle representing the keyshare to be serialized.
//
// Returns:
//   - []byte: a byte slice containing the serialized keyshare data for refreshing.
//   - error: an error if the Rust function call fails or if any other issue occurs during serialization.
func DklsKeyshareToRefreshBytes(share Handle) ([]byte, error) {
	cShare := cHandle(share)

	var cRefreshShareBytes C.tss_buffer
	defer C.tss_buffer_free(&cRefreshShareBytes)

	res := C.dkls_keyshare_to_refresh_bytes(
		cShare,
		&cRefreshShareBytes,
	)
	if res != 0 {
		return nil, errors.MapLibError(int(res))
	}

	buf := C.GoBytes(unsafe.Pointer(cRefreshShareBytes.ptr), C.int(cRefreshShareBytes.len))

	return buf, nil
}

func DklsRefreshShareFromBytes(buf []byte) (Handle, error) {
	pinner := new(runtime.Pinner)
	defer pinner.Unpin()

	cBuffer := cTssBuffer(buf, pinner)

	var cHnd C.Handle

	res := C.dkls_refresh_share_from_bytes(
		cBuffer,
		&cHnd,
	)
	if res != 0 {
		return 0, errors.MapLibError(int(res))
	}

	return Handle(cHnd._0), nil
}

func DklsRefreshShareToBytes(share Handle) ([]byte, error) {
	cShare := cHandle(share)

	var cBuffer C.tss_buffer
	defer C.tss_buffer_free(&cBuffer)

	res := C.dkls_refresh_share_to_bytes(
		cShare,
		&cBuffer,
	)
	if res != 0 {
		return nil, errors.MapLibError(int(res))
	}

	buf := C.GoBytes(unsafe.Pointer(cBuffer.ptr), C.int(cBuffer.len))

	return buf, nil
}

// DklsKeyshareFree releases the resources associated with a keyshare handle.
//
// Parameters:
//   - share: Handle - a handle representing the keyshare to be freed.
//
// Returns:
//   - error: an error if the Rust function call fails or if any issue occurs during deallocation.
func DklsKeyshareFree(share Handle) error {
	cShare := cHandle(share)

	res := C.dkls_keyshare_free(
		&cShare,
	)
	if res != 0 {
		return errors.MapLibError(int(res))
	}

	return nil
}

// DklsKeyshareChainCode retrieves the key ID associated with a given keyshare handle.
//
// Parameters:
//   - share: Handle - a handle representing the keyshare from which the key ID will be retrieved.
//
// Returns:
//   - []byte: a byte slice containing the chaincode associated with the keyshare.
//   - error: an error if the Rust function call fails or if any other issue occurs.
func DklsKeyshareChainCode(share Handle) ([]byte, error) {
	cShare := cHandle(share)

	var cBuffer C.tss_buffer
	defer C.tss_buffer_free(&cBuffer)

	res := C.dkls_keyshare_chaincode(
		cShare,
		&cBuffer,
	)
	if res != 0 {
		return nil, errors.MapLibError(int(res))
	}

	retBuf := C.GoBytes(unsafe.Pointer(cBuffer.ptr), C.int(cBuffer.len))

	return retBuf, nil
}
