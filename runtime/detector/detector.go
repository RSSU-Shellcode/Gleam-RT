//go:build windows

package detector

import (
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/RSSU-Shellcode/GRT-Develop/metric"
)

var (
	modGleamRT = windows.NewLazyDLL("GleamRT.dll")

	procDetect = modGleamRT.NewProc("DT_Detect")
	procStatus = modGleamRT.NewProc("DT_Status")
)

// Status contains detector status.
type Status struct {
	IsEnabled        bool  `json:"is_enabled"`
	HasDebugger      bool  `json:"has_debugger"`
	HasMemoryScanner bool  `json:"has_memory_scanner"`
	InSandbox        bool  `json:"in_sandbox"`
	InVirtualMachine bool  `json:"in_virtual_machine"`
	InEmulator       bool  `json:"in_emulator"`
	IsAccelerated    bool  `json:"is_accelerated"`
	SafeRank         int32 `json:"safe_rank"`
}

// Detect is used to detect current environment.
func Detect() error {
	ret, _, err := procDetect.Call()
	if ret == 0 {
		en := uintptr(err.(syscall.Errno))
		return fmt.Errorf("failed to call detector.Detect: 0x%08X", en)
	}
	return nil
}

// GetStatus is used to get detector status.
func GetStatus() (*Status, error) {
	var status metric.DTStatus
	ret, _, err := procStatus.Call(uintptr(unsafe.Pointer(&status))) // #nosec
	if ret == 0 {
		en := uintptr(err.(syscall.Errno))
		return nil, fmt.Errorf("failed to call detector.Status: 0x%08X", en)
	}
	s := Status{
		IsEnabled:        status.IsEnabled.ToBool(),
		HasDebugger:      status.HasDebugger.ToBool(),
		HasMemoryScanner: status.HasMemoryScanner.ToBool(),
		InSandbox:        status.InSandbox.ToBool(),
		InVirtualMachine: status.InVirtualMachine.ToBool(),
		InEmulator:       status.InEmulator.ToBool(),
		IsAccelerated:    status.IsAccelerated.ToBool(),
		SafeRank:         status.SafeRank,
	}
	return &s, nil
}
