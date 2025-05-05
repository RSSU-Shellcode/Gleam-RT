//go:build windows

package gleamrt

import (
	"fmt"
	"os"
	"runtime"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"github.com/davecgh/go-spew/spew"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
)

var (
	testRTx86 []byte
	testRTx64 []byte
)

func init() {
	var err error
	testRTx86, err = os.ReadFile("../dist/GleamRT_x86.bin")
	if err != nil {
		panic(err)
	}
	testRTx64, err = os.ReadFile("../dist/GleamRT_x64.bin")
	if err != nil {
		panic(err)
	}
}

func TestRuntime(t *testing.T) {
	// load runtime shellcode
	var sc []byte
	switch runtime.GOARCH {
	case "386":
		sc = testRTx86
	case "amd64":
		sc = testRTx64
	default:
		t.Fatal("unsupported architecture")
	}
	addr := loadShellcode(t, sc)
	fmt.Printf("Runtime: 0x%X\n", addr)

	Runtime, err := InitRuntime(addr, nil)
	require.NoError(t, err)

	t.Run("Sleep", func(t *testing.T) {
		now := time.Now()

		err = Runtime.Sleep(time.Second)
		require.NoError(t, err)

		require.GreaterOrEqual(t, time.Since(now).Milliseconds(), int64(1000))
	})

	t.Run("Metrics", func(t *testing.T) {
		mem, _, en := syscall.SyscallN(Runtime.Memory.Alloc, 8192)
		if mem == 0 {
			t.Fatal(en)
		}

		metrics, err := Runtime.Metrics()
		require.NoError(t, err)
		spew.Dump(metrics)
		require.Equal(t, int64(1), metrics.Memory.NumRegions)
		require.Equal(t, int64(3), metrics.Memory.NumPages)
		require.NotZero(t, metrics.Sysmon.NumNormal)

		ret, _, en := syscall.SyscallN(Runtime.Memory.Free, mem)
		if ret != 1 {
			t.Fatal(en)
		}

		metrics, err = Runtime.Metrics()
		require.NoError(t, err)
		spew.Dump(metrics)
		require.Zero(t, metrics.Memory.NumRegions)
		require.Zero(t, metrics.Memory.NumPages)
		require.NotZero(t, metrics.Sysmon.NumNormal)
	})

	t.Run("Cleanup", func(t *testing.T) {
		mem, _, en := syscall.SyscallN(Runtime.Memory.Alloc, 8192)
		if mem == 0 {
			t.Fatal(en)
		}

		err = Runtime.Cleanup()
		require.NoError(t, err)

		metrics, err := Runtime.Metrics()
		require.NoError(t, err)
		require.Zero(t, metrics.Memory.NumRegions)
		require.Zero(t, metrics.Memory.NumPages)
		require.NotZero(t, metrics.Sysmon.NumNormal)
	})

	err = Runtime.Exit()
	require.NoError(t, err)
}

func loadShellcode(t *testing.T, sc []byte) uintptr {
	size := uintptr(len(sc))
	mType := uint32(windows.MEM_COMMIT | windows.MEM_RESERVE)
	mProtect := uint32(windows.PAGE_EXECUTE_READWRITE)
	scAddr, err := windows.VirtualAlloc(0, size, mType, mProtect)
	require.NoError(t, err)
	dst := unsafe.Slice((*byte)(unsafe.Pointer(scAddr)), size)
	copy(dst, sc)
	return scAddr
}
