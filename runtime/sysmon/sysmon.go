//go:build windows

package sysmon

import (
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/RSSU-Shellcode/GRT-Develop/metric"
)

var (
	modGleamRT = windows.NewLazyDLL("GleamRT.dll")

	procStatus = modGleamRT.NewProc("SM_Status")
)

// Status contains sysmon status.
type Status struct {
	IsEnabled  bool  `json:"is_enabled"`
	NumNormal  int64 `json:"num_normal"`
	NumRecover int64 `json:"num_recover"`
	NumPanic   int64 `json:"num_panic"`
}

// GetStatus is used to get sysmon status.
func GetStatus() (*Status, error) {
	var status metric.SMStatus
	ret, _, err := procStatus.Call(uintptr(unsafe.Pointer(&status))) // #nosec
	if ret == 0 {
		en := uintptr(err.(syscall.Errno))
		return nil, fmt.Errorf("failed to call sysmon.Status: 0x%08X", en)
	}
	s := Status{
		IsEnabled:  status.IsEnabled.ToBool(),
		NumNormal:  status.NumNormal,
		NumRecover: status.NumRecover,
		NumPanic:   status.NumPanic,
	}
	return &s, nil
}
