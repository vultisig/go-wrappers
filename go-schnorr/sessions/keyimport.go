// Provides Go bindings for interacting with the Rust library
// that implements the Key Import Session functionality
// within the Schnorr protocol.
//
// This file includes functions for managing initiation of key import,
// as well as key import itself. It is facilitating seamless communication
// between Go and Rust.
package session

/*
#include "../../includes/go-schnorr.h"
#include <stdlib.h>
*/
import "C"
import (
	"runtime"
	"strings"
	"unsafe"

	"github.com/vultisig/go-wrapper/go-schnorr/errors"
)

// SchnorrKeyImportInitiatorNew creates a key import receiver session and generates a setup message for
// key importers.
//
// Parameters:
//   - privateKey: []byte - a byte slice containing the private key.
//   - threshold: uint8 - threshold
//   - ids: []string - human readable party identifiers.
//
// Returns:
//   - Handle: handle which will store the allocated session.
//   - []byte: a byte slice containing the setup message.
//   - error: an error if the Rust function call fails or if any other issue occurs.
func SchnorrKeyImportInitiatorNew(privateKey []byte, rootchain []byte, threshold uint8, ids []string) (Handle, []byte, error) {
	pinner := new(runtime.Pinner)
	defer pinner.Unpin()

	cPrivateKey := cGoSlice(privateKey, pinner)
	cThreshold := C.uint8_t(threshold)

	idBytes := []byte(strings.Join(ids, "\x00"))
	cIDs := (*C.go_slice)(unsafe.Pointer(&idBytes))
	pinner.Pin(&idBytes[0])

	cSetupMsg := C.tss_buffer{}
	defer C.tss_buffer_free(&cSetupMsg)

	cRootChain := (*C.go_slice)(nil)
	if rootchain != nil {
		cRootChain = (*C.go_slice)(unsafe.Pointer(&rootchain))
		pinner.Pin(&rootchain[0])
	}

	cHnd := C.Handle{}

	res := C.schnorr_key_import_initiator_new(
		cPrivateKey,
		cRootChain,
		cThreshold,
		cIDs,
		&cSetupMsg,
		&cHnd,
	)
	if res != 0 {
		return 0, nil, errors.MapLibError(int(res))
	}

	setup := C.GoBytes(unsafe.Pointer(cSetupMsg.ptr), C.int(cSetupMsg.len))

	return Handle(cHnd._0), setup, nil
}

// SchnorrKeyImporterNew creates a key importer for the session
//
// Parameters:
//   - setupMsg: []byte - a byte slice containing the setup message.
//   - id: string - human readable party identifier.
//
// Returns:
//   - Handle: handle which will store the allocated session.
//   - []byte: a byte slice containing the setup message.
//   - error: an error if the Rust function call fails or if any other issue occurs.
func SchnorrKeyImporterNew(setupMsg []byte, id string) (Handle, error) {
	pinner := new(runtime.Pinner)
	defer pinner.Unpin()

	cSetupMsg := cGoSlice(setupMsg, pinner)

	idBytes := []byte(id)
	cID := (*C.go_slice)(unsafe.Pointer(&idBytes))
	pinner.Pin(&idBytes[0])

	cHnd := C.Handle{}

	res := C.schnorr_key_importer_new(
		cSetupMsg,
		cID,
		&cHnd,
	)
	if res != 0 {
		return 0, errors.MapLibError(int(res))
	}

	return Handle(cHnd._0), nil
}
