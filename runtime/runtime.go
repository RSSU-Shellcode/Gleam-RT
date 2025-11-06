//go:build windows

package gleamrt

import (
	"fmt"
	"runtime"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/RSSU-Shellcode/GRT-Develop/metric"
)

const (
	null    = 0
	noError = 0
)

type errno struct {
	method string
	errno  uintptr
}

func (e *errno) Error() string {
	return fmt.Sprintf("RuntimeM.%s return errno: 0x%08X", e.method, e.errno)
}

// Options contains options about initialize runtime.
type Options struct {
	BootInstAddress     uintptr `toml:"boot_inst_address"     json:"boot_inst_address"`
	EnableSecurityMode  bool    `toml:"enable_security_mode"  json:"enable_security_mode"`
	DisableDetector     bool    `toml:"disable_detector"      json:"disable_detector"`
	DisableSysmon       bool    `toml:"disable_sysmon"        json:"disable_sysmon"`
	DisableWatchdog     bool    `toml:"disable_watchdog"      json:"disable_watchdog"`
	NotEraseInstruction bool    `toml:"not_erase_instruction" json:"not_erase_instruction"`
	NotAdjustProtect    bool    `toml:"not_adjust_protect"    json:"not_adjust_protect"`
	TrackCurrentThread  bool    `toml:"track_current_thread"  json:"track_current_thread"`
}

// RuntimeM contains exported methods of runtime.
type RuntimeM struct {
	HashAPI struct {
		FindAPI   uintptr
		FindAPIML uintptr
		FindAPIA  uintptr
		FindAPIW  uintptr
	}

	Library struct {
		LoadA   uintptr
		LoadW   uintptr
		LoadExA uintptr
		LoadExW uintptr
		Free    uintptr
		GetProc uintptr

		Lock    uintptr
		Unlock  uintptr
		Status  uintptr
		FreeAll uintptr
	}

	Memory struct {
		Alloc   uintptr
		Calloc  uintptr
		Realloc uintptr
		Free    uintptr
		Size    uintptr
		Cap     uintptr

		Lock    uintptr
		Unlock  uintptr
		Status  uintptr
		FreeAll uintptr
	}

	Thread struct {
		New   uintptr
		Exit  uintptr
		Sleep uintptr

		Lock    uintptr
		Unlock  uintptr
		Status  uintptr
		KillAll uintptr
	}

	Resource struct {
		LockMutex           uintptr
		UnlockMutex         uintptr
		LockEvent           uintptr
		UnlockEvent         uintptr
		LockSemaphore       uintptr
		UnlockSemaphore     uintptr
		LockWaitableTimer   uintptr
		UnlockWaitableTimer uintptr
		LockFile            uintptr
		UnlockFile          uintptr

		Status  uintptr
		FreeAll uintptr
	}

	Argument struct {
		GetValue   uintptr
		GetPointer uintptr
		Erase      uintptr
		EraseAll   uintptr
	}

	Storage struct {
		SetValue   uintptr
		GetValue   uintptr
		GetPointer uintptr
		Delete     uintptr
		DeleteAll  uintptr
	}

	WinBase struct {
		ANSIToUTF16  uintptr
		UTF16ToANSI  uintptr
		ANSIToUTF16N uintptr
		UTF16ToANSIN uintptr
	}

	WinFile struct {
		ReadFileA  uintptr
		ReadFileW  uintptr
		WriteFileA uintptr
		WriteFileW uintptr
	}

	WinHTTP struct {
		Init uintptr
		Get  uintptr
		Post uintptr
		Do   uintptr

		FreeDLL uintptr
	}

	WinCrypto struct {
		RandBuffer uintptr
		Hash       uintptr
		HMAC       uintptr
		AESEncrypt uintptr
		AESDecrypt uintptr
		RSAGenKey  uintptr
		RSAPubKey  uintptr
		RSASign    uintptr
		RSAVerify  uintptr
		RSAEncrypt uintptr
		RSADecrypt uintptr

		FreeDLL uintptr
	}

	Random struct {
		Buffer  uintptr
		Bool    uintptr
		Int64   uintptr
		Uint64  uintptr
		Int64N  uintptr
		Uint64N uintptr
	}

	Crypto struct {
		Encrypt uintptr
		Decrypt uintptr
	}

	Compressor struct {
		Compress   uintptr
		Decompress uintptr
	}

	Serialization struct {
		Serialize   uintptr
		Unserialize uintptr
	}

	MemScanner struct {
		ScanByValue   uintptr
		ScanByPattern uintptr
		BinToPattern  uintptr
	}

	Procedure struct {
		GetProcByName   uintptr
		GetProcByHash   uintptr
		GetProcByHashML uintptr
	}

	Detector struct {
		Detect uintptr
		Status uintptr
	}

	Sysmon struct {
		Status   uintptr
		Pause    uintptr
		Continue uintptr
	}

	Watchdog struct {
		SetHandler uintptr
		Kick       uintptr
		Enable     uintptr
		Disable    uintptr
		IsEnabled  uintptr
		Status     uintptr
		Pause      uintptr
		Continue   uintptr
	}

	Env struct {
		GetPEB   uintptr
		GetTEB   uintptr
		GetIMOML uintptr
	}

	Raw struct {
		GetProcAddress uintptr
		ExitProcess    uintptr
	}

	Core struct {
		Sleep   uintptr
		Hide    uintptr
		Recover uintptr
		Metrics uintptr
		Cleanup uintptr
		Exit    uintptr
		Stop    uintptr
	}

	Data struct {
		Mutex uintptr
	}
}

// NewRuntime is used to create runtime from initialized instance.
// It will copy memory for prevent runtime encrypt memory page when
// call runtime methods or call SleepHR.
func NewRuntime(ptr uintptr) *RuntimeM {
	rt := *(*RuntimeM)(unsafe.Pointer(ptr)) // #nosec
	return &rt
}

// InitRuntime is used to initialize runtime from shellcode instance.
// Each shellcode instance can only initialize once.
func InitRuntime(addr uintptr, opts *Options) (*RuntimeM, error) {
	ptr, _, err := syscall.SyscallN(addr, uintptr(unsafe.Pointer(opts))) // #nosec
	if ptr == null {
		return nil, fmt.Errorf("failed to initialize runtime: 0x%X", err)
	}
	return NewRuntime(ptr), nil
}

func (rt *RuntimeM) lock() {
	runtime.LockOSThread()
	hMutex := windows.Handle(rt.Data.Mutex)
	_, err := windows.WaitForSingleObject(hMutex, windows.INFINITE)
	if err != nil {
		panic(fmt.Sprintf("failed to lock runtime mutex: %s", err))
	}
}

func (rt *RuntimeM) unlock() {
	hMutex := windows.Handle(rt.Data.Mutex)
	err := windows.ReleaseMutex(hMutex)
	if err != nil {
		panic(fmt.Sprintf("failed to release runtime mutex: %s", err))
	}
	runtime.UnlockOSThread()
}

// Sleep is used to sleep and hide runtime.
func (rt *RuntimeM) Sleep(d time.Duration) error {
	rt.lock()
	defer rt.unlock()
	ret, _, _ := syscall.SyscallN(rt.Core.Sleep, uintptr(d.Milliseconds()))
	if ret != noError {
		return &errno{method: "Core.Sleep", errno: ret}
	}
	return nil
}

// Metrics is used to get runtime metric about core modules.
func (rt *RuntimeM) Metrics() (*metric.Metrics, error) {
	rt.lock()
	defer rt.unlock()
	metrics := metric.Metrics{}
	ret, _, _ := syscall.SyscallN(rt.Core.Metrics, uintptr(unsafe.Pointer(&metrics))) // #nosec
	if ret != noError {
		return nil, &errno{method: "Core.Metrics", errno: ret}
	}
	return &metrics, nil
}

// Cleanup is used to clean all tracked object except locked.
func (rt *RuntimeM) Cleanup() error {
	rt.lock()
	defer rt.unlock()
	ret, _, _ := syscall.SyscallN(rt.Core.Cleanup) // #nosec
	if ret != noError {
		return &errno{method: "Core.Cleanup", errno: ret}
	}
	return nil
}

// Exit is used to exit runtime.
func (rt *RuntimeM) Exit() error {
	rt.lock()
	// defer rt.unlock() runtime will close the mutex
	ret, _, _ := syscall.SyscallN(rt.Core.Exit) // #nosec
	if ret != noError {
		return &errno{method: "Core.Exit", errno: ret}
	}
	return nil
}
