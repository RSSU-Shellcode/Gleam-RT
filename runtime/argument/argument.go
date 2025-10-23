//go:build windows

package argument

import (
	"golang.org/x/sys/windows"
)

var (
	modGleamRT = windows.NewLazyDLL("GleamRT.dll")

	procASGetValue   = modGleamRT.NewProc("AS_GetValue")
	procASGetPointer = modGleamRT.NewProc("AS_GetPointer")
	procASErase      = modGleamRT.NewProc("AS_Erase")
	procASEraseAll   = modGleamRT.NewProc("AS_EraseAll")
)
