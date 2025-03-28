package gleamrt

import (
	"fmt"
	"syscall"
	"time"
	"unsafe"
)

type errno struct {
	proc string
	num  uintptr
}

func (e *errno) Error() string {
	return fmt.Sprintf("RuntimeM.%s return errno: 0x%08X", e.proc, e.num)
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
	NumSockets        int64 `toml:"num_sockets"         json:"num_sockets"`
}

// Metrics contains status about core modules.
type Metrics struct {
	Library  LTStatus `toml:"library"  json:"library"`
	Memory   MTStatus `toml:"memory"   json:"memory"`
	Thread   TTStatus `toml:"thread"   json:"thread"`
	Resource RTStatus `toml:"resource" json:"resource"`
}

// RuntimeOpts contains options about initialize runtime.
type RuntimeOpts struct {
	BootInstAddress     uintptr `toml:"boot_inst_address"     json:"boot_inst_address"`
	NotEraseInstruction bool    `toml:"not_erase_instruction" json:"not_erase_instruction"`
	NotAdjustProtect    bool    `toml:"not_adjust_protect"    json:"not_adjust_protect"`
	TrackCurrentThread  bool    `toml:"track_current_thread"  json:"track_current_thread"`
}

// RuntimeM contains exported runtime methods.
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

	IAT struct {
		GetProcByName   uintptr
		GetProcByHash   uintptr
		GetProcOriginal uintptr
	}

	Core struct {
		Sleep   uintptr
		Hide    uintptr
		Recover uintptr
		Metrics uintptr
		Cleanup uintptr
		Exit    uintptr
	}

	Data struct {
		Mutex uintptr
	}

	ExitProcess uintptr
}

// Sleep is used to sleep and hide runtime.
func (rt *RuntimeM) Sleep(d time.Duration) error {
	ms := uintptr(d.Milliseconds())
	ret, _, _ := syscall.SyscallN(rt.Core.Sleep, ms)
	if ret == 0 {
		return nil
	}
	return &errno{proc: "Core.Sleep", num: ret}
}

// Metrics is used to get runtime metric about core modules.
func (rt *RuntimeM) Metrics() (*Metrics, error) {
	metrics := Metrics{}
	ret, _, _ := syscall.SyscallN(rt.Core.Metrics, uintptr(unsafe.Pointer(&metrics)))
	if ret == 0 {
		return &metrics, nil
	}
	return nil, &errno{proc: "Core.Metrics", num: ret}
}

// Cleanup is used to clean all tracked object except locked.
func (rt *RuntimeM) Cleanup() error {
	ret, _, _ := syscall.SyscallN(rt.Core.Cleanup)
	if ret == 0 {
		return nil
	}
	return &errno{proc: "Core.Cleanup", num: ret}
}

// Exit is used to exit runtime.
func (rt *RuntimeM) Exit() error {
	ret, _, _ := syscall.SyscallN(rt.Core.Exit)
	if ret == 0 {
		return nil
	}
	return &errno{proc: "Core.Exit", num: ret}
}
