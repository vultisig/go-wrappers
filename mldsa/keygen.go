package mldsa

// #include "../includes/vs-core.h"
// #include <stdlib.h>
// #include "vs-core-result.h"
//
// static result new_keygen_setup(
//      MldsaSecurityLevel level,
//      int threshold,
//      go_slice key_id,
//      go_slice ids
// ) {
//      result res = {0};
//
//      res.error = mldsa_keygen_setupmsg_new(
//          level,
//          (uint32_t)threshold,
//          slice_ptr(key_id),
//          slice_ptr(ids),
//          &res.buffer
//      );
//
//      return res;
// }
//
// static result keygen_from_setup(
//      MldsaSecurityLevel level,
//      go_slice setup,
//      go_slice id
// ) {
//      result res = {0};
//
//      res.error = mldsa_keygen_session_from_setup(
//          level,
//          slice_ptr(setup),
//          slice_ptr(id),
//          &res.hnd
//      );
//
//      return res;
// }
//
// static result keygen_input_message(
//      Handle hnd,
//      go_slice message
// ) {
//      result res = {0};
//
//      res.error = mldsa_keygen_session_input_message(
//          hnd,
//          slice_ptr(message),
//          &res.finished
//      );
//
//      return res;
// }
//
// static result keygen_output_message(
//      Handle hnd
// ) {
//      result res = {0};
//
//      res.error = mldsa_keygen_session_output_message(
//          hnd,
//          &res.buffer
//      );
//
//      return res;
// }
//
// static result keygen_message_receiver(
//      Handle session,
//      go_slice message,
//      int32_t index
// ) {
//      result res = {0};
//
//      res.error = mldsa_keygen_session_message_receiver(
//          session,
//          slice_ptr(message),
//          index,
//          &res.buffer
//      );
//
//      return res;
// }
//
// static result keygen_session_finish(Handle session) {
//      result res = {0};
//
//      res.error = mldsa_keygen_session_finish(session, &res.hnd);
//
//      return res;
// }
import "C"

import (
	"runtime"
	"unsafe"
)

func MldsaKeygenSetupMsgNew(
	level SecurityLevel,
	threshold int,
	keyID []byte,
	ids []byte,
) ([]byte, error) {
	res := C.new_keygen_setup(
		C.MldsaSecurityLevel(level),
		C.int(threshold),
		newGoSlice(keyID),
		newGoSlice(ids),
	)
	defer freeTssBuffer(res.buffer)

	if res.error != 0 {
		return nil, mapLibError(res.error)
	}

	setupMsg := C.GoBytes(
		unsafe.Pointer(res.buffer.ptr),
		C.int(res.buffer.len),
	)

	runtime.KeepAlive(keyID)
	runtime.KeepAlive(ids)

	return setupMsg, nil
}

func MldsaKeygenSessionFromSetup(
	level SecurityLevel,
	setup []byte,
	id []byte,
) (Handle, error) {
	res := C.keygen_from_setup(
		C.MldsaSecurityLevel(level),
		newGoSlice(setup),
		newGoSlice(id),
	)
	if res.error != 0 {
		return 0, mapLibError(res.error)
	}

	runtime.KeepAlive(setup)
	runtime.KeepAlive(id)

	return Handle(res.hnd._0), nil
}

func MldsaKeygenSessionFree(hnd Handle) {
	C.mldsa_keygen_session_free(cHandle(hnd))
}

func MldsaKeygenSessionInputMessage(
	session Handle,
	message []byte,
) (bool, error) {
	res := C.keygen_input_message(
		cHandle(session),
		newGoSlice(message),
	)

	runtime.KeepAlive(message)

	if res.error != 0 {
		return false, mapLibError(res.error)
	}

	return res.finished != 0, nil
}

func MldsaKeygenSessionOutputMessage(
	session Handle,
) ([]byte, error) {
	res := C.keygen_output_message(cHandle(session))
	defer freeTssBuffer(res.buffer)

	if res.error != 0 {
		return nil, mapLibError(res.error)
	}

	if res.buffer.len == 0 {
		return nil, nil
	}

	message := C.GoBytes(
		unsafe.Pointer(res.buffer.ptr),
		C.int(res.buffer.len),
	)

	return message, nil
}

func MldsaKeygenSessionMessageReceiver(
	session Handle,
	message []byte,
	index int,
) (string, error) {
	res := C.keygen_message_receiver(
		cHandle(session),
		newGoSlice(message),
		C.int32_t(index),
	)
	defer freeTssBuffer(res.buffer)

	runtime.KeepAlive(message)

	if res.error != 0 {
		return "", mapLibError(res.error)
	}

	receiver := C.GoBytes(
		unsafe.Pointer(res.buffer.ptr),
		C.int(res.buffer.len),
	)

	return string(receiver), nil
}

func MldsaKeygenSessionFinish(session Handle) (Handle, error) {
	res := C.keygen_session_finish(cHandle(session))
	if res.error != 0 {
		return 0, mapLibError(res.error)
	}

	return Handle(res.hnd._0), nil
}
