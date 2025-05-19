//go:build windows

package gleamrt

import (
	"fmt"
	"syscall"
	"time"
	"unsafe"
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

// LTStatus contains status about library tracker.
type LTStatus struct {
	NumModules int64 `toml:"num_modules" json:"num_modules"`
}

// MTStatus contains status about memory tracker.
type MTStatus struct {
	NumGlobals int64 `toml:"num_globals" json:"num_globals"`
	NumLocals  int64 `toml:"num_locals"  json:"num_locals"`
	NumBlocks  int64 `toml:"num_blocks"  json:"num_blocks"`
	NumRegions int64 `toml:"num_regions" json:"num_regions"`
	NumPages   int64 `toml:"num_pages"   json:"num_pages"`
	NumHeaps   int64 `toml:"num_heaps"   json:"num_heaps"`
}

// TTStatus contains status about thread tracker.
type TTStatus struct {
	NumThreads  int64 `toml:"num_threads"   json:"num_threads"`
	NumTLSIndex int64 `toml:"num_tls_index" json:"num_tls_index"`
	NumSuspend  int64 `toml:"num_suspend"   json:"num_suspend"`
}

// RTStatus contains status about resource tracker.
type RTStatus struct {
	NumMutexs         int64 `toml:"num_mutexs"          json:"num_mutexs"`
	NumEvents         int64 `toml:"num_events"          json:"num_events"`
	NumSemaphores     int64 `toml:"num_semaphores"      json:"num_semaphores"`
	NumWaitableTimers int64 `toml:"num_waitable_timers" json:"num_waitable_timers"`
	NumFiles          int64 `toml:"num_files"           json:"num_files"`
	NumDirectories    int64 `toml:"num_directories"     json:"num_directories"`
	NumIOCPs          int64 `toml:"num_iocps"           json:"num_iocps"`
	NumKeys           int64 `toml:"num_keys"            json:"num_keys"`
	NumSockets        int64 `toml:"num_sockets"         json:"num_sockets"`
}

// SMStatus contains status about sysmon.
type SMStatus struct {
	NumNormal  int64 `toml:"num_normal"  json:"num_normal"`
	NumRecover int64 `toml:"num_recover" json:"num_recover"`
	NumPanic   int64 `toml:"num_panic"   json:"num_panic"`
}

// WDStatus contains status about watchdog.
type WDStatus struct {
	NumKick   int64 `toml:"num_kick"   json:"num_kick"`
	NumNormal int64 `toml:"num_normal" json:"num_normal"`
	NumReset  int64 `toml:"num_reset"  json:"num_reset"`
}

// Metrics contains status about runtime submodules.
type Metrics struct {
	Library  LTStatus `toml:"library"  json:"library"`
	Memory   MTStatus `toml:"memory"   json:"memory"`
	Thread   TTStatus `toml:"thread"   json:"thread"`
	Resource RTStatus `toml:"resource" json:"resource"`
	Sysmon   SMStatus `toml:"sysmon"   json:"sysmon"`
	Watchdog WDStatus `toml:"watchdog" json:"watchdog"`
}

// Options contains options about initialize runtime.
type Options struct {
	BootInstAddress     uintptr `toml:"boot_inst_address"     json:"boot_inst_address"`
	NotEraseInstruction bool    `toml:"not_erase_instruction" json:"not_erase_instruction"`
	NotAdjustProtect    bool    `toml:"not_adjust_protect"    json:"not_adjust_protect"`
	TrackCurrentThread  bool    `toml:"track_current_thread"  json:"track_current_thread"`
}

// RuntimeM contains exported methods of runtime.
type RuntimeM struct {
	HashAPI struct {
		FindAPI  uintptr
		FindAPIA uintptr
		FindAPIW uintptr
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
		LockMutex   uintptr
		UnlockMutex uintptr
		Status      uintptr
		FreeAll     uintptr
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
		Get  uintptr
		Post uintptr
		Do   uintptr

		Init uintptr
		Free uintptr
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
		GetProcOriginal uintptr
	}

	Sysmon struct {
		Status   uintptr
		Pause    uintptr
		Continue uintptr
	}

	Watchdog struct {
		Kick       uintptr
		Enable     uintptr
		Disable    uintptr
		IsEnabled  uintptr
		SetHandler uintptr
		Status     uintptr
		Pause      uintptr
		Continue   uintptr
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

	ExitProcess uintptr
}

// InitRuntime is used to initialize runtime from shellcode instance.
// Each shellcode instance can only initialize once.
func InitRuntime(addr uintptr, opts *Options) (*RuntimeM, error) {
	ret, _, err := syscall.SyscallN(addr, uintptr(unsafe.Pointer(opts))) // #nosec
	if ret == null {
		return nil, fmt.Errorf("failed to initialize runtime: 0x%X", err)
	}
	return (*RuntimeM)(unsafe.Pointer(ret)), nil // #nosec
}

// Sleep is used to sleep and hide runtime.
func (rt *RuntimeM) Sleep(d time.Duration) error {
	ret, _, _ := syscall.SyscallN(rt.Core.Sleep, uintptr(d.Milliseconds()))
	if ret != noError {
		return &errno{method: "Core.Sleep", errno: ret}
	}
	return nil
}

// Metrics is used to get runtime metric about core modules.
func (rt *RuntimeM) Metrics() (*Metrics, error) {
	metrics := Metrics{}
	ret, _, _ := syscall.SyscallN(rt.Core.Metrics, uintptr(unsafe.Pointer(&metrics))) // #nosec
	if ret != noError {
		return nil, &errno{method: "Core.Metrics", errno: ret}
	}
	return &metrics, nil
}

// Cleanup is used to clean all tracked object except locked.
func (rt *RuntimeM) Cleanup() error {
	ret, _, _ := syscall.SyscallN(rt.Core.Cleanup) // #nosec
	if ret != noError {
		return &errno{method: "Core.Cleanup", errno: ret}
	}
	return nil
}

// Exit is used to exit runtime.
func (rt *RuntimeM) Exit() error {
	ret, _, _ := syscall.SyscallN(rt.Core.Exit) // #nosec
	if ret != noError {
		return &errno{method: "Core.Exit", errno: ret}
	}
	return nil
}
