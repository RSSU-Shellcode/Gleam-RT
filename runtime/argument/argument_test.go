//go:build windows

package argument

import (
	"os"
	"runtime"
	"testing"
	"unsafe"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"

	"github.com/RSSU-Shellcode/Gleam-RT/runtime"
)

func init() {
	var src string
	switch runtime.GOARCH {
	case "386":
		src = "../../dist/GleamRT_x86.dll"
	case "amd64":
		src = "../../dist/GleamRT_x64.dll"
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
	err := gleamrt.Initialize(nil)
	if err != nil {
		panic(err)
	}

	code := m.Run()

	err = gleamrt.Uninitialize()
	if err != nil {
		panic(err)
	}

	// must free twice for runtime package
	err = windows.FreeLibrary(windows.Handle(modGleamRT.Handle()))
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

// reference: script/args_gen.go

func TestGetValue(t *testing.T) {
	t.Run("common", func(t *testing.T) {
		data, exist := GetValue(0)
		require.True(t, exist, "argument 0 is not exists")

		expected := []byte{0x78, 0x56, 0x34, 0x12}
		require.Equal(t, expected, data)
	})

	t.Run("not exists", func(t *testing.T) {
		data, exist := GetValue(123)
		require.False(t, exist)
		require.Nil(t, data)
	})

	t.Run("empty data", func(t *testing.T) {
		data, exist := GetValue(2)
		require.True(t, exist, "argument 2 is not exists")
		require.Nil(t, data)
	})
}

func TestGetPointer(t *testing.T) {
	t.Run("common", func(t *testing.T) {
		ptr, size, exist := GetPointer(1)
		require.True(t, exist, "argument 1 is not exists")
		require.Equal(t, uint32(12), size)
		require.NotZero(t, ptr)

		expected := "aaaabbbbccc\x00"
		actual := unsafe.String((*byte)(unsafe.Pointer(ptr)), int(size)) // #nosec
		require.Equal(t, expected, actual)
	})

	t.Run("not exists", func(t *testing.T) {
		ptr, size, exist := GetPointer(123)
		require.False(t, exist)
		require.Zero(t, size)
		require.Zero(t, ptr)
	})
}

func TestErase(t *testing.T) {
	t.Run("common", func(t *testing.T) {
		ok := Erase(0)
		require.True(t, ok)

		data, exist := GetValue(0)
		require.False(t, exist, "argument 0 is still exists")
		require.Nil(t, data)
	})

	t.Run("not exists", func(t *testing.T) {
		ok := Erase(123)
		require.False(t, ok)
	})

	t.Run("erase twice", func(t *testing.T) {
		ok := Erase(0)
		require.True(t, ok)
		ok = Erase(0)
		require.True(t, ok)
	})
}

func TestEraseAll(t *testing.T) {
	t.Run("common", func(t *testing.T) {
		EraseAll()

		data, exist := GetValue(1)
		require.False(t, exist, "argument 1 is still exists")
		require.Nil(t, data)
	})

	t.Run("erase twice", func(t *testing.T) {
		EraseAll()
		EraseAll()
	})
}
