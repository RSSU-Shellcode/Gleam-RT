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

// Detect is used to detect current environment.
func Detect() error {
	ret, _, err := procDetect.Call()
	if ret == 0 {
		en := uintptr(err.(syscall.Errno))
		return fmt.Errorf("failed to call detector.Detect: 0x%08X", en)
	}
	return nil
}

// Status is used to get detector status.
func Status() (*metric.DTStatus, error) {
	var status metric.DTStatus
	ret, _, err := procStatus.Call(uintptr(unsafe.Pointer(&status)))
	if ret == 0 {
		en := uintptr(err.(syscall.Errno))
		return nil, fmt.Errorf("failed to call detector.Status: 0x%08X", en)
	}
	return &status, nil
}
