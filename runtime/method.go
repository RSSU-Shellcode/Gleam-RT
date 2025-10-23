package gleamrt

import (
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
