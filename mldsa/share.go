package mldsa

// #include "../includes/vs-core.h"
// #include <stdlib.h>
// typedef struct result {
//      lib_error  error;
//      tss_buffer buffer;
//      Handle     hnd;
//      int32_t    finished;
// } result;
//
// #define slice_ptr(s) ((s).len > 0 ? &(s) : NULL)
//
// static result share_from_bytes(go_slice bytes) {
//     result res = {0};
//
//     res.error = mldsa_keyshare_from_bytes(
//         slice_ptr(bytes),
//         &res.hnd
//     );
//
//     return res;
// }
//
// static result share_to_bytes(Handle share) {
//     result res = {0};
//
//     res.error = mldsa_keyshare_to_bytes(
//         share,
//         &res.buffer
//     );
//
//     return res;
// }
//
// static result share_key_id(Handle share) {
//     result res = {0};
//
//     res.error = mldsa_keyshare_key_id(
//         share,
//         &res.buffer
//     );
//
//     return res;
// }
//
// static result share_public_key(Handle share) {
//     result res = {0};
//
//     res.error = mldsa_keyshare_public_key(
//         share,
//         &res.buffer
//     );
//
//     return res;
// }
import "C"
import (
	"unsafe"
)

func MldsaKeyshareFromBytes(buffer []byte) (Handle, error) {
	res := C.share_from_bytes(newGoSlice(buffer))

	if res.error != 0 {
		return 0, mapLibError(res.error)
	}

	return Handle(res.hnd._0), nil
}

func MldsaKeyshareToBytes(share Handle) ([]byte, error) {
	res := C.share_to_bytes(cHandle(share))
	defer freeTssBuffer(res.buffer)

	if res.error != 0 {
		return nil, mapLibError(res.error)
	}

	bytes := C.GoBytes(
		unsafe.Pointer(res.buffer.ptr),
		C.int(res.buffer.len),
	)

	return bytes, nil
}

func MldsaKeyshareKeyID(share Handle) ([]byte, error) {
	res := C.share_key_id(cHandle(share))
	defer freeTssBuffer(res.buffer)

	if res.error != 0 {
		return nil, mapLibError(res.error)
	}

	bytes := C.GoBytes(
		unsafe.Pointer(res.buffer.ptr),
		C.int(res.buffer.len),
	)

	return bytes, nil
}

func MldsaKeysharePublicKey(share Handle) ([]byte, error) {

	res := C.share_public_key(cHandle(share))
	defer freeTssBuffer(res.buffer)

	if res.error != 0 {
		return nil, mapLibError(res.error)
	}

	bytes := C.GoBytes(
		unsafe.Pointer(res.buffer.ptr),
		C.int(res.buffer.len),
	)

	return bytes, nil
}
