//go:build windows

package argument

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modGleamRT = windows.NewLazyDLL("GleamRT.dll")

	procGetValue   = modGleamRT.NewProc("AS_GetValue")
	procGetPointer = modGleamRT.NewProc("AS_GetPointer")
	procErase      = modGleamRT.NewProc("AS_Erase")
	procEraseAll   = modGleamRT.NewProc("AS_EraseAll")
)

// GetValue is used to get argument value by id.
func GetValue(id uint32) ([]byte, bool) {
	var size uint32
	ret, _, _ := procGetValue.Call(
		uintptr(id), 0, uintptr(unsafe.Pointer(&size)),
	) // #nosec
	if ret == 0 {
		return nil, false
	}
	value := make([]byte, size)
	ret, _, _ = procGetValue.Call(
		uintptr(id), uintptr(unsafe.Pointer(&value[0])), uintptr(unsafe.Pointer(&size)),
	) // #nosec
	if ret == 0 {
		return nil, false
	}
	return value, true
}

// GetPointer is used to get argument pointer by id.
func GetPointer(id uint32) (uintptr, uint32, bool) {
	var (
		ptr  uintptr
		size uint32
	)
	ret, _, _ := procGetPointer.Call(
		uintptr(id), uintptr(unsafe.Pointer(&ptr)), uintptr(unsafe.Pointer(&size)),
	) // #nosec
	if ret == 0 {
		return 0, 0, false
	}
	return ptr, size, true
}

// Erase is used to erase argument by id.
func Erase(id uint32) bool {
	ret, _, _ := procErase.Call(uintptr(id))
	return ret != 0
}

// EraseAll is used to erase all arguments.
func EraseAll() {
	_, _, _ = procEraseAll.Call()
}
