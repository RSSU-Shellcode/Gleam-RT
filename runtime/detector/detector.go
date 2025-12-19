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
	IsEnabled        bool  `toml:"is_enabled"         json:"is_enabled"`
	HasDebugger      bool  `toml:"has_debugger"       json:"has_debugger"`
	HasMemoryScanner bool  `toml:"has_memory_scanner" json:"has_memory_scanner"`
	InSandbox        bool  `toml:"in_sandbox"         json:"in_sandbox"`
	InVirtualMachine bool  `toml:"in_virtual_machine" json:"in_virtual_machine"`
	InEmulator       bool  `toml:"in_emulator"        json:"in_emulator"`
	IsAccelerated    bool  `toml:"is_accelerated"     json:"is_accelerated"`
	SafeRank         int32 `toml:"safe_rank"          json:"safe_rank"`
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
	ret, _, err := procStatus.Call(uintptr(unsafe.Pointer(&status)))
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
