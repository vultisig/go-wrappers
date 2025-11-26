//go:build darwin

package session

/*
#cgo LDFLAGS: -L../../includes/darwin -lgodkls -Wl,-rpath,${SRCDIR}/../../includes/darwin
#include "../../includes/go-dkls.h"
#include <stdlib.h>
*/
import "C"
