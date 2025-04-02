//go:build linux

package session

/*
#cgo CFLAGS: -I../../includes
#cgo LDFLAGS: -L../../includes/linux -llibgodkls
#include "../../includes/go-dkls.h"
#include <stdlib.h>
*/
import "C"
