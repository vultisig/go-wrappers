// Provides Go bindings for interacting with the Rust library
// that implements the Key Import Session functionality
// within the DKLS protocol.
//
// This file includes functions for managing initiation of key import,
// as well as key import itself. It is facilitating seamless communication
// between Go and Rust.
package session

/*
#include "../../includes/go-dkls.h"
#include <stdlib.h>
*/
import "C"

import (
	"runtime"
	"strings"
	"unsafe"

	"github.com/vultisig/go-wrappers/go-dkls/errors"
)

// DklsKeyImportInitiatorNew creates a key import receiver session and generates a setup message for
// key importers.
//
// Parameters:
//   - privateKey: []byte - a byte slice containing the private key.
//   - rootChain: []byte - an optional byte slice contaning root chain code.
//   - threshold: uint8 - threshold
//   - ids: []string - human readable party identifiers.
//
// Returns:
//   - Handle: handle which will store the allocated session.
//   - []byte: a byte slice containing the setup message.
//   - error: an error if the Rust function call fails or if any other issue occurs.
func DklsKeyImportInitiatorNew(privateKey []byte, rootChain []byte, threshold uint8, ids []string) (Handle, []byte, error) {
	pinner := runtime.Pinner{}
	defer pinner.Unpin()

	cPrivateKey := (*C.go_slice)(unsafe.Pointer(&privateKey))
	pinner.Pin(&privateKey[0])

	idBytes := []byte(strings.Join(ids, "\x00"))
	cIds := (*C.go_slice)(unsafe.Pointer(&idBytes))
	pinner.Pin(&idBytes[0])

	setupMsg := C.tss_buffer{}
	defer C.tss_buffer_free(&setupMsg)

	cRootChain := (*C.go_slice)(nil)
	if rootChain != nil {
		cRootChain = (*C.go_slice)(unsafe.Pointer(&rootChain))
		pinner.Pin(&rootChain[0])
	}

	handle := C.Handle{}

	rc := C.dkls_key_import_initiator_new(
		cPrivateKey,
		cRootChain,
		C.uint8_t(threshold),
		cIds,
		&setupMsg,
		&handle,
	)

	if rc != 0 {
		return 0, nil, errors.MapLibError(int(rc))
	}

	setup := C.GoBytes(unsafe.Pointer(setupMsg.ptr), C.int(setupMsg.len))

	return Handle(handle._0), setup, nil
}

// DklsKeyImporter creates a key importer for the session
//
// Parameters:
//   - setupMsg: []byte - a byte slice containing the setup message.
//   - id: string - human readable party identifier.
//
// Returns:
//   - Handle: handle which will store the allocated session.
//   - []byte: a byte slice containing the setup message.
//   - error: an error if the Rust function call fails or if any other issue occurs.
func DklsKeyImporter(setupMsg []byte, id string) (Handle, error) {
	pinner := runtime.Pinner{}
	defer pinner.Unpin()

	cSetupMsg := (*C.go_slice)(unsafe.Pointer(&setupMsg))
	pinner.Pin(&setupMsg[0])

	idBytes := []byte(id)
	cID := (*C.go_slice)(unsafe.Pointer(&idBytes))
	pinner.Pin(&idBytes[0])

	handle := C.Handle{}

	rc := C.dkls_key_importer_new(
		cSetupMsg,
		cID,
		&handle,
	)

	if rc != 0 {
		return 0, errors.MapLibError(int(rc))
	}

	return Handle(handle._0), nil
}
