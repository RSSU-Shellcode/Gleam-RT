//go:build windows

package gleamrt

import (
	"syscall"
	"unsafe"

	"github.com/RSSU-Shellcode/GRT-Develop/metric"

	"golang.org/x/sys/windows"
)

var (
	modGleamRT = windows.NewLazyDLL("GleamRT.dll")

	procGetProcAddressByName   = modGleamRT.NewProc("GetProcAddressByName")
	procGetProcAddressByHash   = modGleamRT.NewProc("GetProcAddressByHash")
	procGetProcAddressByHashML = modGleamRT.NewProc("GetProcAddressByHashML")
	procGetProcAddressOriginal = modGleamRT.NewProc("GetProcAddressOriginal")
	procExitProcess            = modGleamRT.NewProc("ExitProcess")

	procGetPEB   = modGleamRT.NewProc("GetPEB")
	procGetTEB   = modGleamRT.NewProc("GetTEB")
	procGetIMOML = modGleamRT.NewProc("GetIMOML")

	procGetMetrics = modGleamRT.NewProc("GetMetrics")
)

// GetProcAddressByName is used to get procedure address by name.
func GetProcAddressByName(hModule uintptr, name string, redirect bool) (uintptr, error) {
	namePtr, err := syscall.BytePtrFromString(name)
	if err != nil {
		return 0, err
	}
	ret, _, err := procGetProcAddressByName.Call(
		hModule, uintptr(unsafe.Pointer(namePtr)), boolToUintptr(redirect),
	) // #nosec
	if ret == 0 {
		return 0, err
	}
	return ret, nil
}

// GetProcAddressByHash is used to get procedure address by hash.
func GetProcAddressByHash(mHash, pHash, hKey uint, redirect bool) (uintptr, error) {
	ret, _, err := procGetProcAddressByHash.Call(
		uintptr(mHash), uintptr(pHash), uintptr(hKey), boolToUintptr(redirect),
	) // #nosec
	if ret == 0 {
		return 0, err
	}
	return ret, nil
}

// GetProcAddressByHashML is used to get procedure address by hash with list.
func GetProcAddressByHashML(list uintptr, mHash, pHash, hKey uint, redirect bool) (uintptr, error) {
	ret, _, err := procGetProcAddressByHashML.Call(
		list, uintptr(mHash), uintptr(pHash), uintptr(hKey), boolToUintptr(redirect),
	) // #nosec
	if ret == 0 {
		return 0, err
	}
	return ret, nil
}

// GetProcAddressOriginal is used to call original GetProcAddress.
func GetProcAddressOriginal(hModule uintptr, name string) (uintptr, error) {
	namePtr, err := syscall.BytePtrFromString(name)
	if err != nil {
		return 0, err
	}
	ret, _, err := procGetProcAddressOriginal.Call(
		hModule, uintptr(unsafe.Pointer(namePtr)),
	) // #nosec
	if ret == 0 {
		return 0, err
	}
	return ret, nil
}

// ExitProcess is used to call original ExitProcess.
func ExitProcess(code int) {
	_, _, _ = procExitProcess.Call(uintptr(code))
}

// GetPEB is used to get process environment block.
func GetPEB() uintptr {
	ret, _, _ := procGetPEB.Call()
	return ret
}

// GetTEB is used to get thread environment block.
func GetTEB() uintptr {
	ret, _, _ := procGetTEB.Call()
	return ret
}

// GetIMOML is used to get in-memory order module list.
func GetIMOML() uintptr {
	ret, _, _ := procGetIMOML.Call()
	return ret
}

// GetMetrics is used to get runtime metrics.
func GetMetrics() (*metric.Metrics, error) {
	var metrics metric.Metrics
	ret, _, err := procGetMetrics.Call(
		uintptr(unsafe.Pointer(&metrics)),
	) // #nosec
	if ret != windows.NO_ERROR {
		return nil, err
	}
	return &metrics, nil
}

func boolToUintptr(b bool) uintptr {
	if b {
		return 1
	}
	return 0
}
