//go:build linux

package mldsa

/*
#cgo LDFLAGS: -L../includes/linux -Wl,-rpath,../includes/linux -lvscore
#include "../includes/vs-core.h"
#include <stdlib.h>
*/
import "C"
