//go:build linux

package session

/*
#cgo LDFLAGS: -L../../includes/linux -lgodkls
#include "../../includes/go-dkls.h"
#include <stdlib.h>
*/
import "C"
