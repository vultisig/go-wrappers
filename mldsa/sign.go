package mldsa

// #include "../includes/vs-core.h"
// #include <stdlib.h>
// #include "vs-core-result.h"
//
// static result new_sign_setup(
//      MldsaSecurityLevel level,
//      go_slice key_id,
//      go_slice chain_path,
//      go_slice message_hash,
//      go_slice ids
// ) {
//      result res = {0};
//
//      res.error = mldsa_sign_setupmsg_new(
//          level,
//          slice_ptr(key_id),
//          slice_ptr(chain_path),
//          slice_ptr(message_hash),
//          slice_ptr(ids),
//          &res.buffer
//      );
//
//      return res;
// }
//
// static result sign_from_setup(
//      MldsaSecurityLevel level,
//      go_slice setup,
//      go_slice id,
//      Handle share
// ) {
//      result res = {0};
//
//      res.error = mldsa_sign_session_from_setup(
//          level,
//          slice_ptr(setup),
//          slice_ptr(id),
//          share,
//          &res.hnd
//      );
//
//      return res;
// }
//
// static result sign_input_message(
//      Handle hnd,
//      go_slice message
// ) {
//      result res = {0};
//
//      res.error = mldsa_sign_session_input_message(
//          hnd,
//          slice_ptr(message),
//          &res.finished
//      );
//
//      return res;
// }
//
// static result sign_output_message(
//      Handle hnd
// ) {
//      result res = {0};
//
//      res.error = mldsa_sign_session_output_message(
//          hnd,
//          &res.buffer
//      );
//
//      return res;
// }
//
// static result sign_message_receiver(
//      Handle session,
//      go_slice message,
//      int32_t index
// ) {
//      result res = {0};
//
//      res.error = mldsa_sign_session_message_receiver(
//          session,
//          slice_ptr(message),
//          index,
//          &res.buffer
//      );
//
//      return res;
// }
//
// static result sign_session_finish(Handle session) {
//      result res = {0};
//
//      res.error = mldsa_sign_session_finish(session, &res.buffer);
//
//      return res;
// }
import "C"

import (
	"runtime"
	"unsafe"
)

func MldsaSignSetupMsgNew(
	level SecurityLevel,
	keyID []byte,
	chainPath string,
	messageHash []byte,
	ids []byte,
) ([]byte, error) {
	res := C.new_sign_setup(
		C.MldsaSecurityLevel(level),
		newGoSlice(keyID),
		newGoSlice([]byte(chainPath)),
		newGoSlice(messageHash),
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

func MldsaSignSessionFromSetup(
	level SecurityLevel,
	setup []byte,
	id []byte,
	share Handle,
) (Handle, error) {
	res := C.sign_from_setup(
		C.MldsaSecurityLevel(level),
		newGoSlice(setup),
		newGoSlice(id),
		cHandle(share),
	)
	if res.error != 0 {
		return 0, mapLibError(res.error)
	}

	runtime.KeepAlive(setup)
	runtime.KeepAlive(id)

	return Handle(res.hnd._0), nil
}

func MldsaSignSessionFree(hnd Handle) {
	C.mldsa_sign_session_free(cHandle(hnd))
}

func MldsaSignSessionInputMessage(
	session Handle,
	message []byte,
) (bool, error) {
	res := C.sign_input_message(
		cHandle(session),
		newGoSlice(message),
	)

	runtime.KeepAlive(message)

	if res.error != 0 {
		return false, mapLibError(res.error)
	}

	return res.finished != 0, nil
}

func MldsaSignSessionOutputMessage(
	session Handle,
) ([]byte, error) {
	res := C.sign_output_message(cHandle(session))
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

func MldsaSignSessionMessageReceiver(
	session Handle,
	message []byte,
	index int,
) (string, error) {
	res := C.sign_message_receiver(
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

func MldsaSignSessionFinish(session Handle) ([]byte, error) {
	res := C.sign_session_finish(cHandle(session))
	defer freeTssBuffer(res.buffer)

	if res.error != 0 {
		return nil, mapLibError(res.error)
	}

	sig := C.GoBytes(
		unsafe.Pointer(res.buffer.ptr),
		C.int(res.buffer.len),
	)

	return sig, nil
}
