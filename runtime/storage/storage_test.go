package storage

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

func TestSetValue(t *testing.T) {
	t.Run("add value", func(t *testing.T) {
		data := []byte("secret")
		err := SetValue(0, data)
		require.NoError(t, err)
	})

	t.Run("set value", func(t *testing.T) {
		data1 := []byte("secret1")
		err := SetValue(1, data1)
		require.NoError(t, err)

		data2 := []byte("secret2")
		err = SetValue(1, data2)
		require.NoError(t, err)
	})

	t.Run("set empty value", func(t *testing.T) {
		err := SetValue(123, nil)
		require.EqualError(t, err, "failed to call storage.SetValue: 0xC6000102")
	})

	t.Run("delete value", func(t *testing.T) {
		data := []byte("secret")
		err := SetValue(5, data)
		require.NoError(t, err)

		err = SetValue(5, nil)
		require.NoError(t, err)
	})
}

func TestGetValue(t *testing.T) {
	t.Run("common", func(t *testing.T) {
		data := []byte("secret")
		err := SetValue(0, data)
		require.NoError(t, err)

		val, err := GetValue(0)
		require.NoError(t, err)
		require.Equal(t, data, val)
	})

	t.Run("not exists", func(t *testing.T) {
		val, err := GetValue(123)
		require.EqualError(t, err, "failed to call storage.GetValue: 0xC6000105")
		require.Nil(t, val)
	})
}

func TestGetPointer(t *testing.T) {
	t.Run("common", func(t *testing.T) {
		data := []byte("secret")
		err := SetValue(0, data)
		require.NoError(t, err)

		ptr, size, err := GetPointer(0)
		require.NoError(t, err)
		require.Equal(t, uint32(6), size)
		require.NotZero(t, ptr)

		expected := "secret"
		actual := unsafe.String((*byte)(unsafe.Pointer(ptr)), int(size)) // #nosec
		require.Equal(t, expected, actual)
	})

	t.Run("not exists", func(t *testing.T) {
		ptr, size, err := GetPointer(123)
		require.EqualError(t, err, "failed to call storage.GetPointer: 0xC6000105")
		require.Zero(t, size)
		require.Zero(t, ptr)
	})
}
