package mldsa

/*
#include "../includes/vs-core.h"
#include <stdlib.h>
static void free_tss_buffer(tss_buffer buf) {
      tss_buffer_free(&buf);
}
*/
import "C"
import (
	"unsafe"
)

// Handle is a session or keyshare handle from the C library.
type Handle int32
// SecurityLevel is the ML-DSA security level (44, 65, or 87). Must match C enum MldsaSecurityLevel.
type SecurityLevel int32
const (
	MlDsa44 SecurityLevel = 44
	MlDsa65 SecurityLevel = 65
	MlDsa87 SecurityLevel = 87
)

func freeTssBuffer(buffer C.tss_buffer) {
	C.free_tss_buffer(buffer)
}

func newGoSlice(bytes []byte) C.go_slice {
	l := C.uintptr_t(len(bytes))
	ptr := unsafe.Pointer(unsafe.SliceData(bytes))

	return C.go_slice{
		ptr: (*C.uint8_t)(ptr),
		len: l,
		cap: l,
	}
}

func cHandle(hnd Handle) C.Handle {
	return C.Handle{_0: C.int32_t(hnd)}
}
