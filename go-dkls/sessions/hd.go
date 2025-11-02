// Provides Go bindings for interacting with the Rust library
// that implements the HD derivation session functionality
// within the DKLS protocol.
//
// This file includes functions for managing HD derivation sessions, including setup, message
// handling, and session finalization. It facilitates communication between Go and Rust.

package session

/*
#include "../../includes/go-dkls.h"
#include <stdlib.h>
*/
import "C"
import (
	"runtime"
	"unsafe"

	"github.com/vultisig/go-wrappers/go-dkls/errors"
)

// DklsHdSetupMsgNew generates a new HD derivation setup message.
//
// Parameters:
//   - keyID: []byte - key identifiers used in the derivation process.
//   - chainPath: []byte - derivation path specifying the HD node to derive.
//   - ids: []byte - null-delimited participant identifiers.
//
// Returns:
//   - []byte: generated setup message.
//   - error: An error is returned if the Rust function call fails or if any issue occurs.
func DklsHdSetupMsgNew(keyID []byte, chainPath []byte, ids []byte) ([]byte, error) {
	pinner := new(runtime.Pinner)
	defer pinner.Unpin()

	cKeyID := cGoSlice(keyID, pinner)
	cChainPath := cGoSlice(chainPath, pinner)
	cIDs := cGoSlice(ids, pinner)

	var cSetupMsg C.tss_buffer
	defer C.tss_buffer_free(&cSetupMsg)

	res := C.dkls_hd_setupmsg_new(
		cKeyID,
		cChainPath,
		cIDs,
		&cSetupMsg,
	)
	if res != 0 {
		return nil, errors.MapLibError(int(res))
	}

	setup := C.GoBytes(unsafe.Pointer(cSetupMsg.ptr), C.int(cSetupMsg.len))

	return setup, nil
}

// DklsHdSessionFromSetup creates an HD derivation session using the provided setup message and keyshare.
//
// Parameters:
//   - setup: []byte - encoded setup message.
//   - id: []byte - participant identifier.
//   - share: Handle - keyshare handle for the participant.
//
// Returns:
//   - Handle: handle representing the HD derivation session.
//   - error: An error is returned if the Rust function call fails or if any issue occurs.
func DklsHdSessionFromSetup(setup []byte, id []byte, share Handle) (Handle, error) {
	pinner := new(runtime.Pinner)
	defer pinner.Unpin()

	cSetup := cGoSlice(setup, pinner)
	cID := cGoSlice(id, pinner)
	cShare := cHandle(share)

	var cSession C.Handle

	res := C.dkls_hd_session_from_setup(
		cSetup,
		cID,
		cShare,
		&cSession,
	)
	if res != 0 {
		return 0, errors.MapLibError(int(res))
	}

	return Handle(cSession._0), nil
}

// DklsHdSessionInputMessage processes an input message for the HD derivation session.
//
// Parameters:
//   - session: Handle - HD session handle.
//   - message: []byte - protocol message to process.
//
// Returns:
//   - bool: indicates whether the protocol finished (true) or expects more messages (false).
//   - error: An error is returned if the Rust function call fails or if any issue occurs.
func DklsHdSessionInputMessage(session Handle, message []byte) (bool, error) {
	pinner := new(runtime.Pinner)
	defer pinner.Unpin()

	cSession := cHandle(session)
	cMessage := cGoSlice(message, pinner)

	finished := C.uint32_t(0)

	res := C.dkls_hd_session_input_message(
		cSession,
		cMessage,
		&finished,
	)
	if res != 0 {
		return false, errors.MapLibError(int(res))
	}

	return finished != 0, nil
}

// DklsHdSessionOutputMessage retrieves the next outbound message produced by the HD session.
// Returns nil when there are no pending messages.
func DklsHdSessionOutputMessage(session Handle) ([]byte, error) {
	cSession := cHandle(session)

	var cMsg C.tss_buffer
	defer C.tss_buffer_free(&cMsg)

	res := C.dkls_hd_session_output_message(
		cSession,
		&cMsg,
	)
	if res != 0 {
		return nil, errors.MapLibError(int(res))
	}

	if cMsg.len == 0 {
		return nil, nil
	}

	msg := C.GoBytes(unsafe.Pointer(cMsg.ptr), C.int(cMsg.len))

	return msg, nil
}

// DklsHdSessionMessageReceiver returns the receiver identifier for a given message and index.
//
// Parameters:
//   - session: Handle - HD session handle.
//   - message: []byte - protocol message produced by the session.
//   - index: int - receiver index to query.
//
// Returns:
//   - string: identifier of the receiver, or an empty string if there is no receiver for the index.
//   - error: An error is returned if the Rust function call fails or if any issue occurs.
func DklsHdSessionMessageReceiver(session Handle, message []byte, index int) (string, error) {
	pinner := new(runtime.Pinner)
	defer pinner.Unpin()

	cSession := cHandle(session)
	cMessage := cGoSlice(message, pinner)

	var cReceiver C.tss_buffer
	defer C.tss_buffer_free(&cReceiver)

	res := C.dkls_hd_session_message_receiver(
		cSession,
		cMessage,
		C.uint32_t(index),
		&cReceiver,
	)
	if res != 0 {
		return "", errors.MapLibError(int(res))
	}

	if cReceiver.len == 0 {
		return "", nil
	}

	receiver := C.GoBytes(unsafe.Pointer(cReceiver.ptr), C.int(cReceiver.len))

	return string(receiver), nil
}

// DklsHdSessionFinish finalizes the HD session and returns the derived keyshare handle.
func DklsHdSessionFinish(session Handle) (Handle, error) {
	cSession := cHandle(session)

	var cOutput C.Handle

	res := C.dkls_hd_session_finish(
		cSession,
		&cOutput,
	)
	if res != 0 {
		return 0, errors.MapLibError(int(res))
	}

	return Handle(cOutput._0), nil
}

// DklsHdSessionFree releases resources associated with the HD session handle.
func DklsHdSessionFree(session Handle) error {
	cSession := cHandle(session)

	res := C.dkls_hd_session_free(
		&cSession,
	)
	if res != 0 {
		return errors.MapLibError(int(res))
	}

	return nil
}
