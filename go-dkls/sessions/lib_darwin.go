//go:build darwin

package session

/*
#cgo LDFLAGS: -L../../includes/darwin -lgodkls
#include "../../includes/go-dkls.h"
#include <stdlib.h>
*/
import "C"
