//go:build windows

package argument

import (
	"os"
	"runtime"
	"testing"

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
