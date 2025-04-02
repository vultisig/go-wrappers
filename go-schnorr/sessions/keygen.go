// Provides Go bindings for interacting with the Rust library
// that implements the Key Generation Session functionality
// within the Schnorr protocol.
//
// This file includes functions for managing key generation sessions, including setup, message
// handling, and session finalization. It is facilitating seamless communication
// between Go and Rust.
//
// Key functionalities include:
// - Creating and managing key generation sessions
// - Inputting and outputting messages during the key generation process
// - Finalizing sessions and removing associated data
// - Handling communication between Go and Rust for efficient resource utilization
package session

/*
#include "../../includes/go-schnorr.h"
#include <stdlib.h>
*/
import "C"
import (
	"runtime"
	"unsafe"

	"github.com/vultisig/go-wrapper/go-schnorr/errors"
)

// SchnorrKeygenSetupMsgNew creates a setup message for key generation.
//
// Parameters:
//   - threshold: uint32 - t parameter for the MPC threshold protocol: t minimum nodes are needed to sign. t-1 degree polynomial.
//   - keyID: []byte - unique identifier of all keyshares: currently hash of public key.
//   - ids: []byte - human readable party identifiers.
//
// Returns:
//   - []byte: The generated keygen setup message as a byte slice.
//   - error: An error is returned if the Rust function call fails or if any other issue is encountered.
func SchnorrKeygenSetupMsgNew(threshold int32, keyID []byte, ids []byte) ([]byte, error) {
	// Creating a runtime pinner instance to prevent the GoLang garbage collector from deallocating memory
	// reserved for values returned from the Rust library.
	pinner := new(runtime.Pinner)
	defer pinner.Unpin()

	cThreshold := C.uint(threshold)
	cKeyIDs := cGoSlice(keyID, pinner)
	cIDs := cGoSlice(ids, pinner)

	var cSetupMsg C.tss_buffer
	defer C.tss_buffer_free(&cSetupMsg)

	res := C.schnorr_keygen_setupmsg_new(
		cThreshold,
		cKeyIDs,
		cIDs,
		&cSetupMsg,
	)
	if res != 0 {
		return nil, errors.MapLibError(int(res))
	}

	setupMsg := C.GoBytes(unsafe.Pointer(cSetupMsg.ptr), C.int(cSetupMsg.len))

	return setupMsg, nil
}

// SchnorrKeygenSessionFromSetup initializes a key generation session using the encoded setup message.
//
// Parameters:
//   - setup: []byte - An encoded setup message.
//   - id: []byte - human readable party identifier.
//
// Returns:
//   - Handle: A key generation session handle.
//   - error: An error is returned if the Rust function call fails or if any issue occurs during the setup.
func SchnorrKeygenSessionFromSetup(setup []byte, id []byte) (Handle, error) {
	pinner := new(runtime.Pinner)
	defer pinner.Unpin()

	cSetup := cGoSlice(setup, pinner)
	cID := cGoSlice(id, pinner)

	var cHnd C.Handle

	res := C.schnorr_keygen_session_from_setup(
		cSetup,
		cID,
		&cHnd,
	)
	if res != 0 {
		return 0, errors.MapLibError(int(res))
	}

	return Handle(cHnd._0), nil
}

// SchnorrKeyRefreshSessionFromSetup creates a key refresh session from a encoded setup message.
//
// Parameters:
//   - setup: []byte - Encoded setup message.
//   - id: []byte - human readable party identifier.
//   - oldKeyshare: Handle - The handle representing the old keyshare used in the key refresh.
//
// Returns:
//   - Handle: A handle that represents the key refresh session.
//   - error: An error is returned if the Rust function call fails or if any issue occurs during
//     the session initialization.
func SchnorrKeyRefreshSessionFromSetup(setup []byte, id []byte, oldKeyshare Handle) (Handle, error) {
	pinner := new(runtime.Pinner)
	defer pinner.Unpin()

	cSetup := cGoSlice(setup, pinner)
	cID := cGoSlice(id, pinner)
	cOldKeyshare := cHandle(oldKeyshare)

	var cSessionHnd C.Handle

	res := C.schnorr_key_refresh_session_from_setup(
		cSetup,
		cID,
		cOldKeyshare,
		&cSessionHnd,
	)
	if res != 0 {
		return 0, errors.MapLibError(int(res))
	}

	return Handle(cSessionHnd._0), nil
}

// DklsKeyMigrateSessionFromSetup initializes a session for migrating a key
//
// Parameters:
//   - setup: []byte - Existing setup for the key refresh.
//   - id: []byte - A human readable party identifier.
//   - publicKey: []byte - The expected public key.
//   - rootChainCode: []byte - The rootChainCode  to be copied to the KeyShare for soft derivation: 32 raw bytes
//   - secretCoefficient: []byte - The secret coefficient of additive share of each party secret share s_i_0, s.t:  Σ(s_i_0) = sk
//
// Returns:
//   - Handle: A handle that represents the key refresh session.
//   - error: An error is returned if the Rust function call fails or if any issue occurs during
//     the session initialization.
func SchnorrKeyMigrateSessionFromSetup(setup []byte, id []byte, publicKey []byte, rootChainCode []byte, secretCoefficient []byte) (Handle, error) {
	pinner := new(runtime.Pinner)
	defer pinner.Unpin()

	cSetup := cGoSlice(setup, pinner)
	cID := cGoSlice(id, pinner)
	cPublicKey := cGoSlice(publicKey, pinner)
	cRootChainCode := cGoSlice(rootChainCode, pinner)
	cSecretCoefficient := cGoSlice(secretCoefficient, pinner)

	var cSessionHnd C.Handle

	res := C.schnorr_key_migration_session_from_setup(
		cSetup,
		cID,
		cPublicKey,
		cRootChainCode,
		cSecretCoefficient,
		&cSessionHnd,
	)
	if res != 0 {
		return 0, errors.MapLibError(int(res))
	}

	return Handle(cSessionHnd._0), nil
}

// SchnorrKeygenSessionInputMessage transitions the Schnorr MPC state machine on an input message
//
// Parameters:
//   - session: Handle - The session handler for that specific Schnorr DKG protocol.
//   - message: []byte - The message to be passed as input to the state machine of MPC Execution state machine.
//
// Returns:
//   - bool: A boolean value indicating whether the key generation session has finished (true)
//     or is still ongoing (false).
//   - error: An error is returned if the Rust function call fails or if any issue occurs during
//     message processing.
func SchnorrKeygenSessionInputMessage(session Handle, message []byte) (bool, error) {
	pinner := new(runtime.Pinner)
	defer pinner.Unpin()

	cSession := cHandle(session)
	cMessage := cGoSlice(message, pinner)

	finished := C.int32_t(0)

	res := C.schnorr_keygen_session_input_message(
		cSession,
		cMessage,
		&finished,
	)
	if res != 0 {
		return false, errors.MapLibError(int(res))
	}

	return finished != 0, nil
}

// SchnorrKeygenSessionOutputMessage receives an output message for the Schnorr MPC state machine
//
// Parameters:
//   - session: Handle - The handle representing the current key generation session.
//
// Returns:
//   - []byte: A byte slice containing the output message generated within the session.
//   - error: An error is returned if the Rust function call fails or if any issue occurs during message retrieval.
func SchnorrKeygenSessionOutputMessage(session Handle) ([]byte, error) {
	cSession := cHandle(session)

	var cMsg C.tss_buffer
	defer C.tss_buffer_free(&cMsg)

	res := C.schnorr_keygen_session_output_message(
		cSession,
		&cMsg,
	)
	if res != 0 {
		return nil, errors.MapLibError(int(res))
	}

	if cMsg.len == 0 {
		return nil, nil
	}

	retMsg := C.GoBytes(unsafe.Pointer(cMsg.ptr), C.int(cMsg.len))

	return retMsg, nil
}

// SchnorrKeygenSessionMessageReceiver returns a receiver of a message. Tailored for Vultisig
//
// Parameters:
//   - session: Handle - The handle representing the current key generation session.
//   - message: []byte - A byte slice containing the message to be processed.
//   - index: int - The index identifying the specific receiver.
//
// Returns:
//   - string: A receiver of a message.
//   - error: An error is returned if the Rust function call fails or if any issue occurs during message processing.
func SchnorrKeygenSessionMessageReceiver(session Handle, message []byte, index uint32) (string, error) {
	pinner := new(runtime.Pinner)
	defer pinner.Unpin()

	cSession := cHandle(session)
	cMessage := cGoSlice(message, pinner)
	cIndex := C.uint32_t(index)

	var cReceiver C.tss_buffer
	defer C.tss_buffer_free(&cReceiver)

	res := C.schnorr_keygen_session_message_receiver(
		cSession,
		cMessage,
		cIndex,
		&cReceiver,
	)
	if res != 0 {
		return "", errors.MapLibError(int(res))
	}

	if cReceiver.len == 0 {
		return "", nil
	}

	retReceiver := string(C.GoBytes(unsafe.Pointer(cReceiver.ptr), C.int(cReceiver.len)))

	return retReceiver, nil
}

// SchnorrKeygenSessionFinish finishes the session and collects the generated key share for Schnorr.
// The session will be unconditionally finished, and all inner memory
// will be released. An error code, if any, will be returned on the first
// call. Subsequent calls will return `LIB_INVALID_SESSION_STATE`.
//
// Note:
// `schnorr_keygen_session_free()` must be called to free the session handler.
//
// Parameters:
//   - session: Handle - key generation session handle.
//
// Returns:
//   - Handle: The handle representing the key share generated within the session.
//   - error: An error is returned if the Rust function call fails or if any issue occurs during session finalization.
func SchnorrKeygenSessionFinish(session Handle) (Handle, error) {
	cSession := cHandle(session)

	var cKeyshareHandle C.Handle

	res := C.schnorr_keygen_session_finish(
		cSession,
		&cKeyshareHandle,
	)
	if res != 0 {
		return 0, errors.MapLibError(int(res))
	}

	return Handle(cKeyshareHandle._0), nil
}

// SchnorrKeygenSessionFree deallocates a session handler and associated memory.
//
// Parameters:
//   - session: Handle - A handle representing the key generation session to be dealocated.
//
// Returns:
//   - error: An error is returned if the Rust function call fails or if any issue occurs during session finalization.
func SchnorrKeygenSessionFree(session Handle) error {
	cSession := cHandle(session)

	res := C.schnorr_keygen_session_free(&cSession)
	if res != 0 {
		return errors.MapLibError(int(res))
	}

	return nil
}
