// Provides Go bindings for interacting with the Rust library
// that implements the Key Generation Session functionality
// within the DKLS protocol.
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
#include "../../includes/go-dkls.h"
#include <stdlib.h>
*/
import "C"
import (
	"runtime"
	"unsafe"

	"github.com/vultisig/go-wrapper/go-dkls/errors"
)

// DklsKeygenSetupMsgNew creates a setup message for key generation.
//
// Parameters:
//   - threshold: int - The threshold number of keys required for key generation.
//   - keyID: []byte - A pointer to a byte slice containing the key identifiers.
//   - ids: []byte - A pointer to a byte slice containing participant IDs for the keygen process.
//
// Returns:
//   - []byte: The generated keygen setup message as a byte slice.
//   - error: An error is returned if the Rust function call fails or if any other issue is encountered.
func DklsKeygenSetupMsgNew(threshold int, keyID []byte, ids []byte) ([]byte, error) {
	// Creating a runtime pinner instance to prevent the GoLang garbage collector from deallocating memory
	// reserved for values returned from the Rust library.
	pinner := new(runtime.Pinner)
	defer pinner.Unpin()

	// Declaring `c.uint` value, which will be passed to the Rust function.
	cThreshold := C.uint(threshold)

	// Instantiating `c.go_slice` and pinning the pointer to the slice to prevent garbage collection.
	ckeyIDs := cGoSlice(keyID, pinner)

	cIDs := cGoSlice(ids, pinner)

	// Instantiating `c.tss_buffer`, which will accept the value returned from the Rust function.
	var cSetupMsg C.tss_buffer
	defer C.tss_buffer_free(&cSetupMsg)

	// Calling the Rust function to execute its logic and obtain the result.
	res := C.dkls_keygen_setupmsg_new(
		cThreshold,
		ckeyIDs,
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

// DklsKeygenSessionFromSetup initializes a key generation session using the provided setup message.
//
// Parameters:
//   - setup: []byte - A pointer to a byte slice containing the setup message used to initialize the session.
//   - id: []byte - A pointer to a byte slice containing the participant's identifier.
//     This can be nil if no identifier is provided.
//
// Returns:
//   - Handle: A key generation session handle.
//   - error: An error is returned if the Rust function call fails or if any issue occurs during the setup.
func DklsKeygenSessionFromSetup(setup []byte, id []byte) (Handle, error) {
	pinner := new(runtime.Pinner)
	defer pinner.Unpin()

	cSetup := cGoSlice(setup, pinner)

	cID := cGoSlice(id, pinner)

	var cHnd C.Handle

	res := C.dkls_keygen_session_from_setup(
		cSetup,
		cID,
		&cHnd,
	)
	if res != 0 {
		return 0, errors.MapLibError(int(res))
	}

	return Handle(cHnd._0), nil
}

// DklsKeyRefreshSessionFromSetup initializes a session for refreshing a key
//
// Parameters:
//   - setup: []byte - Existing setup for the key refresh.
//   - id: []byte - A human readable party identifier.
//   - oldKeyshare: Handle - The handle representing the old keyshare used in the key refresh.
//
// Returns:
//   - Handle: A handle that represents the key refresh session.
//   - error: An error is returned if the Rust function call fails or if any issue occurs during
//     the session initialization.
func DklsKeyRefreshSessionFromSetup(setup []byte, id []byte, oldKeyshare Handle) (Handle, error) {
	pinner := new(runtime.Pinner)
	defer pinner.Unpin()

	cSetup := cGoSlice(setup, pinner)
	cID := cGoSlice(id, pinner)
	cOldKeyshare := cHandle(oldKeyshare)

	var cSessionHnd C.Handle

	res := C.dkls_key_refresh_session_from_setup(
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
func DklsKeyMigrateSessionFromSetup(setup []byte, id []byte, publicKey []byte, rootChainCode []byte, secretCoefficient []byte) (Handle, error) {
	pinner := new(runtime.Pinner)
	defer pinner.Unpin()

	cSetup := cGoSlice(setup, pinner)
	cID := cGoSlice(id, pinner)
	cPublicKey := cGoSlice(publicKey, pinner)
	cRootChainCode := cGoSlice(rootChainCode, pinner)
	cSecretCoefficient := cGoSlice(secretCoefficient, pinner)

	var cSessionHnd C.Handle

	res := C.dkls_key_migration_session_from_setup(
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

// DklsKeygenSessionOutputMessage retrieves an output message from the key generation session.
//
// Parameters:
//   - session: Handle - The handle representing the current key generation session.
//
// Returns:
//   - []byte: A byte slice containing the output message generated within the session.
//   - error: An error is returned if the Rust function call fails or if any issue occurs during message retrieval.
func DklsKeygenSessionOutputMessage(session Handle) ([]byte, error) {
	cSession := cHandle(session)

	var cMsg C.tss_buffer
	defer C.tss_buffer_free(&cMsg)

	res := C.dkls_keygen_session_output_message(
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

// DklsKeygenSessionInputMessage processes an input message in the key generation session.
//
// Parameters:
//   - session: Handle - The current key generation session handle.
//   - message: []byte - A byte slice containing the input message for the session.
//
// Returns:
//   - bool: A boolean value indicating whether the key generation session has finished (true)
//     or is still ongoing (false).
//   - error: An error is returned if the Rust function call fails or if any issue occurs during
//     message processing.
func DklsKeygenSessionInputMessage(session Handle, message []byte) (bool, error) {
	pinner := new(runtime.Pinner)
	defer pinner.Unpin()

	cSession := cHandle(session)

	cMessage := cGoSlice(message, pinner)

	finished := C.int32_t(0)

	res := C.dkls_keygen_session_input_message(
		cSession,
		cMessage,
		&finished,
	)
	if res != 0 {
		return false, errors.MapLibError(int(res))
	}

	return finished != 0, nil
}

// DklsKeygenSessionMessageReceiver processes a message in the key generation session for a specific receiver.
//
// Parameters:
//   - session: Handle - The handle representing the current key generation session.
//   - message: []byte - A pointer to a byte slice containing the message to be processed.
//   - index: int - The index identifying the specific receiver.
//
// Returns:
//   - string: A receiver of a message.
//   - error: An error is returned if the Rust function call fails or if any issue occurs during message processing.
func DklsKeygenSessionMessageReceiver(session Handle, message []byte, index int) (string, error) {
	pinner := new(runtime.Pinner)
	defer pinner.Unpin()

	cSession := cHandle(session)

	cMessage := cGoSlice(message, pinner)

	var cReceiver C.tss_buffer
	defer C.tss_buffer_free(&cReceiver)

	res := C.dkls_keygen_session_message_receiver(
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

	retReceiver := string(C.GoBytes(unsafe.Pointer(cReceiver.ptr), C.int(cReceiver.len)))

	return retReceiver, nil
}

// DklsKeygenSessionFinish finalizes the key generation session and retrieves the key share.
//
// Parameters:
//   - session: Handle - The current key generation session handle.
//
// Returns:
//   - Handle: The handle representing the key share generated by the session.
//   - error: An error is returned if the Rust function call fails or if any issue occurs during session finalization.
func DklsKeygenSessionFinish(session Handle) (Handle, error) {
	cSession := cHandle(session)

	var cKeyshareHandle C.Handle

	res := C.dkls_keygen_session_finish(
		cSession,
		&cKeyshareHandle,
	)
	if res != 0 {
		return 0, errors.MapLibError(int(res))
	}

	return Handle(cKeyshareHandle._0), nil
}

// DklsKeygenSessionFree removes the data associated with a key generation session.
//
// Parameters:
//   - session: Handle - A handle representing the key generation session to be removed.
//
// Returns:
//   - error: An error is returned if the Rust function call fails or if any issue occurs during session finalization.
func DklsKeygenSessionFree(session Handle) error {
	cSession := cHandle(session)

	res := C.dkls_keygen_session_free(&cSession)
	if res != 0 {
		return errors.MapLibError(int(res))
	}

	return nil
}
