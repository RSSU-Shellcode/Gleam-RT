//go:build windows

package gleamrt

import (
	"os"
	"runtime"
	"testing"
	"time"
	"unsafe"

	"github.com/davecgh/go-spew/spew"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
)

func init() {
	var src string
	switch runtime.GOARCH {
	case "386":
		src = "../dist/GleamRT_x86.dll"
	case "amd64":
		src = "../dist/GleamRT_x64.dll"
	}
	dll, err := os.ReadFile(src)
	if err != nil {
		panic(err)
	}
	err = os.WriteFile("GleamRT.dll", dll, 0644)
	if err != nil {
		panic(err)
	}
}

func TestMain(m *testing.M) {
	err := Initialize(nil)
	if err != nil {
		panic(err)
	}

	code := m.Run()

	err = Uninitialize()
	if err != nil {
		panic(err)
	}

	err = windows.FreeLibrary(windows.Handle(modGleamRT.Handle()))
	if err != nil {
		panic(err)
	}
	err = os.Remove("GleamRT.dll")
	if err != nil {
		panic(err)
	}

	os.Exit(code)
}

func TestInitialize(t *testing.T) {
	err := Initialize(nil)
	require.NoError(t, err)
}

func TestGetProcAddressByName(t *testing.T) {
	libKernel32, err := windows.LoadLibrary("kernel32.dll")
	require.NoError(t, err)
	hKernel32 := uintptr(libKernel32)

	VirtualAlloc, err := windows.GetProcAddress(libKernel32, "VirtualAlloc")
	require.NoError(t, err)

	t.Run("redirected", func(t *testing.T) {
		proc, err := GetProcAddressByName(hKernel32, "VirtualAlloc", true)
		require.NoError(t, err)
		require.NotZero(t, proc)
		require.NotEqual(t, VirtualAlloc, proc)
	})

	t.Run("not redirected", func(t *testing.T) {
		proc, err := GetProcAddressByName(hKernel32, "VirtualAlloc", false)
		require.NoError(t, err)
		require.Equal(t, VirtualAlloc, proc)
	})

	t.Run("not found procedure", func(t *testing.T) {
		proc, err := GetProcAddressByName(hKernel32, "NotFound", false)
		require.EqualError(t, err, "failed to call GetProcAddressByName: 0x0000007F")
		require.Zero(t, proc)
	})

	t.Run("not found method", func(t *testing.T) {
		proc, err := GetProcAddressByName(Handle, "NotFound", false)
		require.EqualError(t, err, "failed to call GetProcAddressByName: 0xFF000304")
		require.Zero(t, proc)
	})
}

func TestGetProcAddressByHash(t *testing.T) {
	hKernel32, err := windows.LoadLibrary("kernel32.dll")
	require.NoError(t, err)
	VirtualAlloc, err := windows.GetProcAddress(hKernel32, "VirtualAlloc")
	require.NoError(t, err)

	var (
		mHash uint64
		pHash uint64
		hhKey uint64
	)
	switch runtime.GOARCH {
	case "386":
		mHash = 0xED38BE94
		pHash = 0x2EC158C4
		hhKey = 0xB33593DB
	case "amd64":
		mHash = 0x01D79EDD3081D078
		pHash = 0x447B8E23EA19AFBF
		hhKey = 0xC733FDBD9B57119F
	}

	t.Run("redirected", func(t *testing.T) {
		proc, err := GetProcAddressByHash(uint(mHash), uint(pHash), uint(hhKey), true)
		require.NoError(t, err)
		require.NotZero(t, proc)
		require.NotEqual(t, VirtualAlloc, proc)
	})

	t.Run("not redirected", func(t *testing.T) {
		proc, err := GetProcAddressByHash(uint(mHash), uint(pHash), uint(hhKey), false)
		require.NoError(t, err)
		require.Equal(t, VirtualAlloc, proc)
	})

	t.Run("not found", func(t *testing.T) {
		proc, err := GetProcAddressByHash(0x1111, 0x2222, 0x3333, false)
		require.EqualError(t, err, "failed to call GetProcAddressByHash: 0xFF000303")
		require.Zero(t, proc)
	})
}

func TestGetProcAddressByHashML(t *testing.T) {
	hKernel32, err := windows.LoadLibrary("kernel32.dll")
	require.NoError(t, err)
	VirtualAlloc, err := windows.GetProcAddress(hKernel32, "VirtualAlloc")
	require.NoError(t, err)

	list := GetIMOML()
	var (
		mHash uint64
		pHash uint64
		hhKey uint64
	)
	switch runtime.GOARCH {
	case "386":
		mHash = 0xED38BE94
		pHash = 0x2EC158C4
		hhKey = 0xB33593DB
	case "amd64":
		mHash = 0x01D79EDD3081D078
		pHash = 0x447B8E23EA19AFBF
		hhKey = 0xC733FDBD9B57119F
	}

	t.Run("redirected", func(t *testing.T) {
		proc, err := GetProcAddressByHashML(list, uint(mHash), uint(pHash), uint(hhKey), true)
		require.NoError(t, err)
		require.NotZero(t, proc)
		require.NotEqual(t, VirtualAlloc, proc)
	})

	t.Run("not redirected", func(t *testing.T) {
		proc, err := GetProcAddressByHashML(list, uint(mHash), uint(pHash), uint(hhKey), false)
		require.NoError(t, err)
		require.Equal(t, VirtualAlloc, proc)
	})

	t.Run("not found", func(t *testing.T) {
		proc, err := GetProcAddressByHashML(list, 0x1111, 0x2222, 0x3333, false)
		require.EqualError(t, err, "failed to call GetProcAddressByHashML: 0xFF000303")
		require.Zero(t, proc)
	})
}

func TestGetProcAddressOriginal(t *testing.T) {
	libKernel32, err := windows.LoadLibrary("kernel32.dll")
	require.NoError(t, err)
	hKernel32 := uintptr(libKernel32)

	t.Run("common", func(t *testing.T) {
		VirtualAlloc, err := windows.GetProcAddress(libKernel32, "VirtualAlloc")
		require.NoError(t, err)

		proc, err := GetProcAddressOriginal(hKernel32, "VirtualAlloc")
		require.NoError(t, err)
		require.Equal(t, VirtualAlloc, proc)
	})

	t.Run("not found", func(t *testing.T) {
		proc, err := GetProcAddressOriginal(hKernel32, "NotFound")
		require.EqualError(t, err, "failed to call GetProcAddressOriginal: 0x0000007F")
		require.Zero(t, proc)
	})
}

func TestGetPEB(t *testing.T) {
	peb := windows.RtlGetCurrentPeb()
	expect := uintptr(unsafe.Pointer(peb)) // #nosec
	actual := GetPEB()
	require.Equal(t, expect, actual)
}

func TestGetTEB(t *testing.T) {
	teb := GetTEB()
	require.NotZero(t, teb)
}

func TestGetIMOML(t *testing.T) {
	actual := GetIMOML()

	peb := windows.RtlGetCurrentPeb()
	addr := uintptr(unsafe.Pointer(peb)) // #nosec

	t.Run("x86", func(t *testing.T) {
		if runtime.GOARCH != "386" {
			return
		}

		ldr := *(*uintptr)(unsafe.Pointer(addr + 0x0C)) // #nosec
		mod := *(*uintptr)(unsafe.Pointer(ldr + 0x14))  // #nosec
		require.Equal(t, mod, actual)
	})

	t.Run("x64", func(t *testing.T) {
		if runtime.GOARCH != "amd64" {
			return
		}

		ldr := *(*uintptr)(unsafe.Pointer(addr + 0x18)) // #nosec
		mod := *(*uintptr)(unsafe.Pointer(ldr + 0x20))  // #nosec
		require.Equal(t, mod, actual)
	})
}

func TestGetMetrics(t *testing.T) {
	metrics, err := GetMetrics()
	require.NoError(t, err)
	spew.Dump(metrics)
}

func TestSleep(t *testing.T) {
	now := time.Now()

	err := Sleep(time.Second)
	require.NoError(t, err)

	d := time.Since(now)
	require.Greater(t, d, time.Second)
}
