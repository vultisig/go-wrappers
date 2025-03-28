// Provides Go bindings for interacting with the Rust library
// that implements the Sign Session functionality
// within the DKLS protocol.
//
// This file includes functions for managing sign sessions, including setup, message
// handling, and session finalization. It is facilitating seamless communication
// between Go and Rust.
//
// Key functionalities include:
// - Creating and managing sign sessions
// - Inputting and outputting messages during the session
// - Finalizing sessions and removing associated data
// - Handling communication between Go and Rust for efficient resource utilization

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

// DklsSignSetupMsgNew generates a new signing setup message
//
// Parameters:
//   - keyIDs: []byte - key identifiers used in the signing process.
//   - chainPath: []byte - chain path.
//   - messageHash: []byte - a hash of the message to be signed.
//   - ids: []byte -  IDs of signers.
//
// Returns:
//   - []byte: generated setup message.
//   - error: An error is returned if the Rust function call fails or if any other issue is encountered.
func DklsSignSetupMsgNew(keyID []byte, chainPath []byte, messageHash []byte, ids []byte) ([]byte, error) {
	pinner := new(runtime.Pinner)
	defer pinner.Unpin()

	// Instantiating `c.go_slice` and pinning the pointer to the slice to prevent garbage collection.
	ckeyID := cGoSlice(keyID, pinner)

	cChainPath := cGoSlice(chainPath, pinner)

	cMsg := cGoSlice(messageHash, pinner)

	cIDs := cGoSlice(ids, pinner)

	var cSetupMsg C.tss_buffer
	defer C.tss_buffer_free(&cSetupMsg)

	res := C.dkls_sign_setupmsg_new(
		ckeyID,
		cChainPath,
		cMsg,
		cIDs,
		&cSetupMsg,
	)
	if res != 0 {
		return nil, errors.MapLibError(int(res))
	}

	// Copying the Rust memory into the Go heap so garbage collector can deallocate it.
	setupMsg := C.GoBytes(unsafe.Pointer(cSetupMsg.ptr), C.int(cSetupMsg.len))

	return setupMsg, nil
}

// DklsFinishSetupMsgNew generates a new DSG finish setup message
//
// Parameters:
//   - sessionID: []byte - session identifier.
//   - messageHash: []byte - a hash of the message to be signed.
//   - ids: []byte -  IDs of signers.
//
// Returns:
//   - []byte: generated setup message.
//   - error: An error is returned if the Rust function call fails or if any other issue is encountered.
func DklsFinishSetupMsgNew(sessionID []byte, messageHash []byte, ids []byte) ([]byte, error) {
	pinner := new(runtime.Pinner)
	defer pinner.Unpin()

	csessionID := cGoSlice(sessionID, pinner)
	cMessageHash := cGoSlice(messageHash, pinner)
	cIDs := cGoSlice(ids, pinner)

	var cSetupMsg C.tss_buffer
	defer C.tss_buffer_free(&cSetupMsg)

	res := C.dkls_finish_setupmsg_new(
		csessionID,
		cMessageHash,
		cIDs,
		&cSetupMsg,
	)
	if res != 0 {
		return nil, errors.MapLibError(int(res))
	}

	setupMsg := C.GoBytes(unsafe.Pointer(cSetupMsg.ptr), C.int(cSetupMsg.len))

	return setupMsg, nil
}

// DklsSignSessionFromSetup initializes a signing session from a setup message.
//
// Parameters:
//   - setup: []byte - the setup message used to initialize the signing session.
//   - id: []byte - the identifier of the signer.
//   - shareOrPresign: Handle - the keyshare or presign handle. Depending on the type of passed handler,
//     the function will create a different type of session.
//
// Returns:
//   - Handle: the handle representing the initialized signing session.
//   - error: An error is returned if the Rust function call fails or if any other issue is encountered.
func DklsSignSessionFromSetup(setup []byte, id []byte, shareOrPresign Handle) (Handle, error) {
	pinner := new(runtime.Pinner)
	defer pinner.Unpin()

	cSetup := cGoSlice(setup, pinner)

	cID := cGoSlice(id, pinner)

	cShareOrPresign := cHandle(shareOrPresign)

	var cHnd C.Handle

	res := C.dkls_sign_session_from_setup(
		cSetup,
		cID,
		cShareOrPresign,
		&cHnd,
	)
	if res != 0 {
		return 0, errors.MapLibError(int(res))
	}

	return Handle(cHnd._0), nil
}

// DklsSignSessionOutputMessage retrieves the output message from the signing session.
//
// Parameters:
//   - session: Handle - the handle representing the signing session.
//
// Returns:
//   - []byte: the message generated within the signing session.
//   - error: An error is returned if the Rust function call fails or if any other issue is encountered.
func DklsSignSessionOutputMessage(session Handle) ([]byte, error) {
	cSession := cHandle(session)

	var cMessage C.tss_buffer
	defer C.tss_buffer_free(&cMessage)

	res := C.dkls_sign_session_output_message(
		cSession,
		&cMessage,
	)
	if res != 0 {
		return nil, errors.MapLibError(int(res))
	}

	message := C.GoBytes(unsafe.Pointer(cMessage.ptr), C.int(cMessage.len))

	return message, nil
}

// DklsSignSessionMessageReceiver processes a message in the signing session for a specific receiver.
//
// Parameters:
//   - session: Handle - the handle representing the signing session.
//   - message: []byte - the message to be processed by the signing session.
//   - index: uint32 - the index of the message receiver.
//
// Returns:
//   - []byte: A byte slice containing the receiver of a message.
//   - error: An error is returned if the Rust function call fails or if any other issue is encountered.
func DklsSignSessionMessageReceiver(session Handle, message []byte, index int) ([]byte, error) {
	pinner := new(runtime.Pinner)
	defer pinner.Unpin()

	cSession := cHandle(session)

	cMessage := cGoSlice(message, pinner)

	var cReceiver C.tss_buffer
	defer C.tss_buffer_free(&cReceiver)

	res := C.dkls_sign_session_message_receiver(
		cSession,
		cMessage,
		C.uint32_t(index),
		&cReceiver,
	)
	if res != 0 {
		return nil, errors.MapLibError(int(res))
	}

	receiver := C.GoBytes(unsafe.Pointer(cReceiver.ptr), C.int(cReceiver.len))

	return receiver, nil
}

// DklsSignSessionInputMessage processes an input message in the signing session.
//
// Parameters:
//   - session: Handle - the handle representing the signing session.
//   - message: []byte - the message to be inputted into the session.
//
// Returns:
//   - bool: true if the signing session is finished, false otherwise.
//   - error: An error is returned if the Rust function call fails or if any other issue is encountered.
func DklsSignSessionInputMessage(session Handle, message []byte) (bool, error) {
	pinner := new(runtime.Pinner)
	defer pinner.Unpin()

	cSession := cHandle(session)

	cMessage := cGoSlice(message, pinner)

	cFinished := C.uint32_t(0)

	res := C.dkls_sign_session_input_message(
		cSession,
		cMessage,
		&cFinished,
	)
	if res != 0 {
		return false, errors.MapLibError(int(res))
	}

	return cFinished != 0, nil
}

// DklsSignSessionFinish finalizes the signing session and returns the generated output.
//
// For full or final sessions, this is an ECDSA signature: [ R || S || rec-id ].
// For a pre-sign session, it is the serialization of the pre-signature object.
//
// The session will be unconditionally finished, and all inner memory
// will be released. An error code, if any, will be returned on the first
// call. Subsequent calls will return `LIB_INVALID_SESSION_STATE`.
//
// `DklsSignSessionFree()` must be called to free the session handler.
//
// Parameters:
//   - session: Handle - the handle representing the signing session.
//
// Returns:
//   - []byte: the final output of the signing session.
//   - error: An error is returned if the Rust function call fails or if any other issue is encountered.
func DklsSignSessionFinish(session Handle) ([]byte, error) {
	cSession := cHandle(session)

	var cOutput C.tss_buffer
	defer C.tss_buffer_free(&cOutput)

	res := C.dkls_sign_session_finish(
		cSession,
		&cOutput,
	)
	if res != 0 {
		return nil, errors.MapLibError(int(res))
	}

	output := C.GoBytes(unsafe.Pointer(cOutput.ptr), C.int(cOutput.len))

	return output, nil
}

// DklsSignSessionFree removes the data associated with the signing session.
//
// Parameters:
//   - session: Handle - a handle representing the signing session to be removed.
//
// Returns:
//   - error: An error is returned if the Rust function call fails or if any other issue is encountered.
func DklsSignSessionFree(session Handle) error {
	cSession := cHandle(session)

	res := C.dkls_sign_session_free(
		&cSession,
	)
	if res != 0 {
		return errors.MapLibError(int(res))
	}

	return nil
}
