//go:build windows

package storage

import (
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modGleamRT = windows.NewLazyDLL("GleamRT.dll")

	procSetValue   = modGleamRT.NewProc("IS_SetValue")
	procGetValue   = modGleamRT.NewProc("IS_GetValue")
	procGetPointer = modGleamRT.NewProc("IS_GetPointer")
	procDelete     = modGleamRT.NewProc("IS_Delete")
	procDeleteAll  = modGleamRT.NewProc("IS_DeleteAll")
)

// SetValue is used to store value to in-memory storage by id.
func SetValue(id int, value []byte) error {
	var (
		ret uintptr
		err error
	)
	if len(value) == 0 {
		ret, _, err = procSetValue.Call(
			uintptr(id), 0, uintptr(len(value)),
		) // #nosec

	} else {
		ret, _, err = procSetValue.Call(
			uintptr(id), uintptr(unsafe.Pointer(&value[0])), uintptr(len(value)),
		) // #nosec
	}
	if ret != 0 {
		en := uintptr(err.(syscall.Errno))
		return fmt.Errorf("failed to call storage.SetValue: 0x%08X", en)
	}
	return nil
}

// GetValue is used to get value from in-memory storage by id.
func GetValue(id int) ([]byte, error) {
	var size uint32
	ret, _, err := procGetValue.Call(
		uintptr(id), 0, uintptr(unsafe.Pointer(&size)),
	) // #nosec
	if ret == 0 {
		en := uintptr(err.(syscall.Errno))
		return nil, fmt.Errorf("failed to call storage.GetValue: 0x%08X", en)
	}
	if size == 0 {
		return nil, nil
	}
	value := make([]byte, size)
	ret, _, err = procGetValue.Call(
		uintptr(id), uintptr(unsafe.Pointer(&value[0])), uintptr(unsafe.Pointer(&size)),
	) // #nosec
	if ret == 0 {
		en := uintptr(err.(syscall.Errno))
		return nil, fmt.Errorf("failed to call storage.GetValue: 0x%08X", en)
	}
	return value, nil
}

// GetPointer is used to get value pointer from in-memory storage by id.
func GetPointer(id int) (uintptr, uint32, error) {
	var (
		ptr  uintptr
		size uint32
	)
	ret, _, err := procGetPointer.Call(
		uintptr(id), uintptr(unsafe.Pointer(&ptr)), uintptr(unsafe.Pointer(&size)),
	) // #nosec
	if ret == 0 {
		en := uintptr(err.(syscall.Errno))
		return 0, 0, fmt.Errorf("failed to call storage.GetPointer: 0x%08X", en)
	}
	return ptr, size, nil
}

// Delete is used to delete value in in-memory storage by id.
func Delete(id int) error {
	return nil
}

// DeleteAll is used to delete all values in in-memory storage.
func DeleteAll() error {
	return nil
}
