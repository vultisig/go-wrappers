package mldsa

// #include "../includes/vs-core.h"
import "C"
import (
	"errors"
	"fmt"
)

var RejectSamplingError = errors.New("reject sampling")

var libErrorMessages = map[C.mldsa_lib_error]error{
	C.LIB_INVALID_HANDLE:              errors.New("invalid Handle, not found in the map"),
	C.LIB_HANDLE_IN_USE:               errors.New("handle In Use, the handle is already in use"),
	C.LIB_INVALID_HANDLE_TYPE:         errors.New("invalid Handle Type, the handle is not of the expected type"),
	C.LIB_NULL_PTR:                    errors.New("received null pointer"),
	C.LIB_INVALID_BUFFER_SIZE:         errors.New("received a buffer with invalid size"),
	C.LIB_INVALID_SESSION_STATE:       errors.New("invalid session state"),
	C.LIB_UNKNOWN_ERROR:               errors.New("unknown Error"),
	C.LIB_SERIALIZATION_ERROR:         errors.New("serialization error, error while serializing protocol type"),
	C.LIB_INVALID_DERIVATION_PATH_STR: errors.New("invalid derivation path string"),
	C.LIB_DERIVATION_ERROR:            errors.New("child key derivation error"),
	C.LIB_SETUP_MESSAGE_VALIDATION:    errors.New("setup message validation error"),
	C.LIB_NON_EMPTY_OUTPUT_BUFFER:     errors.New("passed non-empty output buffer"),
	C.LIB_SIGNGEN_ERROR:               errors.New("sign generation error"),
	C.LIB_KEYGEN_ERROR:                errors.New("key generation error"),
	C.LIB_REJSAMPLING:                 RejectSamplingError,
}

func mapLibError(err C.mldsa_lib_error) error {
	if err == 0 {
		return nil
	}

	if errMsg, found := libErrorMessages[err]; found {
		return errMsg
	}

	return fmt.Errorf("unknown error: %v", err)
}
