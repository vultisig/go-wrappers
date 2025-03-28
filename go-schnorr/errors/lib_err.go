package errors

/*
#include "../../includes/go-schnorr.h"
#include <stdlib.h>
*/
import "C"
import "fmt"

var libErrorMessages = map[C.lib_error]string{
	C.LIB_OK:                          "ok",
	C.LIB_INVALID_HANDLE:              "Invalid Handle, not found in the map",
	C.LIB_HANDLE_IN_USE:               "Handle In Use, the handle is already in use",
	C.LIB_INVALID_HANDLE_TYPE:         "Invalid Handle Type, the handle is not of the expected type",
	C.LIB_NULL_PTR:                    "Received null pointer",
	C.LIB_INVALID_BUFFER_SIZE:         "Received a buffer with invalid size",
	C.LIB_INVALID_SESSION_STATE:       "Invalid session state",
	C.LIB_UNKNOWN_ERROR:               "Unknown Error",
	C.LIB_SERIALIZATION_ERROR:         "Serialization error, error while serializing protocol type",
	C.LIB_INVALID_DERIVATION_PATH_STR: "Invalid derivation path string",
	C.LIB_DERIVATION_ERROR:            "Child key derivation error",
	C.LIB_SETUP_MESSAGE_VALIDATION:    "Setup message vaildation",
	C.LIB_NON_EMPTY_OUTPUT_BUFFER:     "Passed non-empty output buffer",
	C.LIB_SIGNGEN_ERROR:               "Sign generation error",
	C.LIB_KEYGEN_ERROR:                "Key generation error",
	C.LIB_KEY_EXPORT_ERROR:            "Key export error",
	C.LIB_ABORT_PROTOCOL_PARTY_1:      "Protocol abort by party 1",
	C.LIB_ABORT_PROTOCOL_PARTY_2:      "Protocol abort by party 2",
	C.LIB_ABORT_PROTOCOL_PARTY_3:      "Protocol abort by party 3",
	C.LIB_ABORT_PROTOCOL_PARTY_4:      "Protocol abort by party 4",
	C.LIB_ABORT_PROTOCOL_PARTY_5:      "Protocol abort by party 5",
	C.LIB_ABORT_PROTOCOL_PARTY_6:      "Protocol abort by party 6",
	C.LIB_ABORT_PROTOCOL_PARTY_7:      "Protocol abort by party 7",
	C.LIB_ABORT_PROTOCOL_PARTY_8:      "Protocol abort by party 8",
	C.LIB_ABORT_PROTOCOL_PARTY_9:      "Protocol abort by party 9",
	C.LIB_ABORT_PROTOCOL_PARTY_10:     "Protocol abort by party 10",
}

func MapLibError(err int) error {
	if errMsg, found := libErrorMessages[C.lib_error(err)]; found {
		return fmt.Errorf(errMsg)
	}

	return fmt.Errorf("unknown error: %v", err)
}
