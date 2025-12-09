//go:build windows

package gleamrt

import (
	"fmt"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/RSSU-Shellcode/GRT-Develop/metric"
)

var (
	modGleamRT = windows.NewLazyDLL("GleamRT.dll")

	procInit = modGleamRT.NewProc("RT_Init")

	procGetProcAddressByName   = modGleamRT.NewProc("RT_GetProcAddressByName")
	procGetProcAddressByHash   = modGleamRT.NewProc("RT_GetProcAddressByHash")
	procGetProcAddressByHashML = modGleamRT.NewProc("RT_GetProcAddressByHashML")
	procGetProcAddressOriginal = modGleamRT.NewProc("RT_GetProcAddressOriginal")

	procGetPEB   = modGleamRT.NewProc("RT_GetPEB")
	procGetTEB   = modGleamRT.NewProc("RT_GetTEB")
	procGetIMOML = modGleamRT.NewProc("RT_GetIMOML")

	procGetMetrics = modGleamRT.NewProc("RT_GetMetrics")
	procSleep      = modGleamRT.NewProc("RT_Sleep")

	procExitProcess = modGleamRT.NewProc("RT_ExitProcess")
)

// Init is used to initialize runtime dll(only for test).
func Init(opts *Options) error {
	ret, _, err := procInit.Call(uintptr(unsafe.Pointer(opts)))
	if ret == 0 {
		return fmt.Errorf("failed to initialize runtime: 0x%8X", err.(syscall.Errno))
	}
	return nil
}

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
		return 0, fmt.Errorf("failed to call GetProcAddressByName: 0x%8X", err.(syscall.Errno))
	}
	return ret, nil
}

// GetProcAddressByHash is used to get procedure address by hash.
func GetProcAddressByHash(mHash, pHash, hKey uint, redirect bool) (uintptr, error) {
	ret, _, err := procGetProcAddressByHash.Call(
		uintptr(mHash), uintptr(pHash), uintptr(hKey), boolToUintptr(redirect),
	) // #nosec
	if ret == 0 {
		return 0, fmt.Errorf("failed to call GetProcAddressByHash: 0x%8X", err.(syscall.Errno))
	}
	return ret, nil
}

// GetProcAddressByHashML is used to get procedure address by hash with list.
func GetProcAddressByHashML(list uintptr, mHash, pHash, hKey uint, redirect bool) (uintptr, error) {
	ret, _, err := procGetProcAddressByHashML.Call(
		list, uintptr(mHash), uintptr(pHash), uintptr(hKey), boolToUintptr(redirect),
	) // #nosec
	if ret == 0 {
		return 0, fmt.Errorf("failed to call GetProcAddressByHashML: 0x%8X", err.(syscall.Errno))
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
		return 0, fmt.Errorf("failed to call GetProcAddressOriginal: 0x%8X", err.(syscall.Errno))
	}
	return ret, nil
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
	ret, _, err := procGetMetrics.Call(uintptr(unsafe.Pointer(&metrics))) // #nosec
	if ret != windows.NO_ERROR {
		return nil, fmt.Errorf("failed to call GetMetrics: 0x%8X", err.(syscall.Errno))
	}
	return &metrics, nil
}

// Sleep is used to hide and sleep, it is the core method.
func Sleep(d time.Duration) error {
	ret, _, err := procSleep.Call(uintptr(d.Milliseconds()))
	if ret != windows.NO_ERROR {
		return fmt.Errorf("failed to call Sleep: 0x%8X", err.(syscall.Errno))
	}
	return nil
}

// ExitProcess is used to call original ExitProcess.
func ExitProcess(code int) {
	_, _, _ = procExitProcess.Call(uintptr(code))
}

func boolToUintptr(b bool) uintptr {
	if b {
		return 1
	}
	return 0
}
