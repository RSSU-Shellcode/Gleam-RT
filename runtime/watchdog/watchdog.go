//go:build windows

package watchdog

import (
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/RSSU-Shellcode/GRT-Develop/metric"
)

var (
	modGleamRT = windows.NewLazyDLL("GleamRT.dll")

	procKick      = modGleamRT.NewProc("WD_Kick")
	procEnable    = modGleamRT.NewProc("WD_Enable")
	procDisable   = modGleamRT.NewProc("WD_Disable")
	procIsEnabled = modGleamRT.NewProc("WD_IsEnabled")
	procStatus    = modGleamRT.NewProc("WD_Status")
)

// Status contains watchdog status.
type Status struct {
	IsEnabled bool  `json:"is_enabled"`
	NumKick   int64 `json:"num_kick"`
	NumNormal int64 `json:"num_normal"`
	NumReset  int64 `json:"num_reset"`
}

// Kick is used to kick to the watchdog for report alive.
func Kick() error {
	ret, _, _ := procKick.Call()
	if ret != 0 {
		return fmt.Errorf("failed to call watchdog.Kick: 0x%08X", ret)
	}
	return nil
}

// Enable is used to enable watchdog.
func Enable() error {
	ret, _, _ := procEnable.Call()
	if ret != 0 {
		return fmt.Errorf("failed to call watchdog.Enable: 0x%08X", ret)
	}
	return nil
}

// Disable is used to disable watchdog.
func Disable() error {
	ret, _, _ := procDisable.Call()
	if ret != 0 {
		return fmt.Errorf("failed to call watchdog.Disable: 0x%08X", ret)
	}
	return nil
}

// IsEnabled is used to check the watchdog is enabled.
func IsEnabled() bool {
	ret, _, _ := procIsEnabled.Call()
	return ret != 0
}

// GetStatus is used to get watchdog status.
func GetStatus() (*Status, error) {
	var status metric.WDStatus
	ret, _, err := procStatus.Call(uintptr(unsafe.Pointer(&status))) // #nosec
	if ret == 0 {
		en := uintptr(err.(syscall.Errno))
		return nil, fmt.Errorf("failed to call watchdog.Status: 0x%08X", en)
	}
	s := Status{
		IsEnabled: status.IsEnabled.ToBool(),
		NumKick:   status.NumKick,
		NumNormal: status.NumNormal,
		NumReset:  status.NumReset,
	}
	return &s, nil
}
