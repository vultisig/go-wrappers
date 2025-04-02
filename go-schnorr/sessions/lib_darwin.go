//go:build darwin

package session

/*
#cgo LDFLAGS: -L../../includes/darwin -lgoschnorr
#include "../../includes/go-schnorr.h"
#include <stdlib.h>
*/
import "C"
