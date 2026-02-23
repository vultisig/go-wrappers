//go:build darwin

package mldsa

/*
#cgo LDFLAGS: -L../includes/darwin -lvscore
#include "../includes/vs-core.h"
#include <stdlib.h>
*/
import "C"
