// Provides helper functions for facilitating interoperability between Go and Rust

package session

/*
#include "../../includes/go-dkls.h"
#include <stdlib.h>
*/
import "C"
import (
	"runtime"
	"unsafe"
)

// GoLang representation of C.Handle
type Handle int32

func cGoSlice(byteArray []byte, pinner *runtime.Pinner) *C.go_slice {
	var cGoSlice *C.go_slice
	if byteArray != nil {
		cGoSlice = (*C.go_slice)(unsafe.Pointer(&byteArray))
		pinner.Pin(&byteArray[0])
	}

	return cGoSlice
}

func cHandle(handle Handle) C.Handle {
	return C.Handle{
		_0: C.int32_t(handle),
	}
}

func cTssBuffer(byteArray []byte, pinner *runtime.Pinner) *C.tss_buffer {
	var cTssBuffer *C.tss_buffer
	if byteArray != nil {
		cTssBuffer = (*C.tss_buffer)(unsafe.Pointer(&byteArray))
		pinner.Pin(&byteArray[0])
	}

	return cTssBuffer
}
