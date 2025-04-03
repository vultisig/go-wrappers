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

func DklsQcSetupMsgNew(keyshare Handle, threshold int, ids []string, oldParties []int, newParties []int) ([]byte, error) {
	pinner := runtime.Pinner{}
	defer pinner.Unpin()

	id_bytes := []byte(strings.Join(ids, "\x00"))
	cIds := (*C.go_slice)(unsafe.Pointer(&id_bytes))
	pinner.Pin(&id_bytes[0])

	cSetupMsg := C.tss_buffer{}
	defer C.tss_buffer_free(&cSetupMsg)

	bOldParties := []byte{}
	for _, i := range oldParties {
		bOldParties = append(bOldParties, byte(i))
	}
	cOldParties := (*C.go_slice)(unsafe.Pointer(&bOldParties))
	pinner.Pin(&bOldParties[0])

	bNewParties := []byte{}
	for _, i := range newParties {
		bNewParties = append(bNewParties, byte(i))
	}
	cNewParties := (*C.go_slice)(unsafe.Pointer(&bNewParties))
	pinner.Pin(&bNewParties[0])

	rc := C.dkls_qc_setupmsg_new(
		cHandle(keyshare),
		cIds,
		cOldParties,
		C.uint32_t(threshold),
		cNewParties,
		&cSetupMsg,
	)

	if rc != 0 {
		return nil, errors.MapLibError(int(rc))
	}

	// Copying the Rust memory into the Go heap so garbage collector can deallocate it.
	setupMsg := C.GoBytes(unsafe.Pointer(cSetupMsg.ptr), C.int(cSetupMsg.len))

	return setupMsg, nil
}

func DklsQcSessionFromSetup(setupMsg []byte, id string, keyshare Handle) (Handle, error) {
	pinner := runtime.Pinner{}
	defer pinner.Unpin()

	cSetupMsg := (*C.go_slice)(unsafe.Pointer(&setupMsg))
	pinner.Pin(&setupMsg[0])

	id_bytes := []byte(id)
	cID := (*C.go_slice)(unsafe.Pointer(&id_bytes))
	pinner.Pin(&id_bytes[0])

	handle := C.Handle{}

	rc := C.dkls_qc_session_from_setup(
		cSetupMsg,
		cID,
		cHandle(keyshare),
		&handle,
	)

	if rc != 0 {
		return 0, errors.MapLibError(int(rc))
	}

	return Handle(handle._0), nil
}

// DklsQcSessionOutputMessage retrieves an output message from the QC session.
//
// Parameters:
//   - session: Handle - The handle representing the current key generation session.
//
// Returns:
//   - []byte: A byte slice containing the output message generated within the session.
//   - error: An error is returned if the Rust function call fails or if any issue occurs during message retrieval.
func DklsQcSessionOutputMessage(session Handle) ([]byte, error) {
	cSession := cHandle(session)

	var cMsg C.tss_buffer
	defer C.tss_buffer_free(&cMsg)

	res := C.dkls_qc_session_output_message(
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

// DklsQcSessionInputMessage processes an input message in the QC session.
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
func DklsQcSessionInputMessage(session Handle, message []byte) (bool, error) {
	pinner := new(runtime.Pinner)
	defer pinner.Unpin()

	cMessage := (*C.go_slice)(unsafe.Pointer(&message))
	pinner.Pin(&message[0])

	finished := C.int32_t(0)

	res := C.dkls_qc_session_input_message(
		cHandle(session),
		cMessage,
		&finished,
	)

	if res != 0 {
		return false, errors.MapLibError(int(res))
	}

	return finished != 0, nil
}

// DklsQcSessionMessageReceiver processes a message in the QC session for a specific receiver.
//
// Parameters:
//   - session: Handle - The handle representing the current key generation session.
//   - message: []byte - A pointer to a byte slice containing the message to be processed.
//   - index: int - The index identifying the specific receiver.
//
// Returns:
//   - string: A receiver of a message.
//   - error: An error is returned if the Rust function call fails or if any issue occurs during message processing.
func DklsQcSessionMessageReceiver(session Handle, message []byte, index int) (string, error) {
	pinner := new(runtime.Pinner)
	defer pinner.Unpin()

	cMessage := (*C.go_slice)(unsafe.Pointer(&message))
	pinner.Pin(&message[0])

	var cReceiver C.tss_buffer
	defer C.tss_buffer_free(&cReceiver)

	res := C.dkls_qc_session_message_receiver(
		cHandle(session),
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

// DklsQcSessionFinish finalizes the key generation session and retrieves the key share.
//
// Parameters:
//   - session: Handle - The current key generation session handle.
//
// Returns:
//   - Handle: The handle representing the key share generated by the session.
//   - error: An error is returned if the Rust function call fails or if any issue occurs during session finalization.
func DklsQcSessionFinish(session Handle) (Handle, error) {
	cSession := cHandle(session)

	var cKeyshareHandle C.Handle

	res := C.dkls_qc_session_finish(
		cSession,
		&cKeyshareHandle,
	)

	if res != 0 {
		return 0, errors.MapLibError(int(res))
	}

	return Handle(cKeyshareHandle._0), nil
}
