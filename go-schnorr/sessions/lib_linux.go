//go:build linux

package session

/*
#cgo LDFLAGS: -L../../includes/linux -llibgoschnorr
#include "../../includes/go-schnorr.h"
#include <stdlib.h>
*/
import "C"
