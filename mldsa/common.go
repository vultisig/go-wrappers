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

// GoLang representation of C.Handle
type Handle int32

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
