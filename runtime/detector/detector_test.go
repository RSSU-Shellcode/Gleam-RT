//go:build windows

package detector

import (
	"os"
	"runtime"
	"testing"

	"github.com/davecgh/go-spew/spew"
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

func TestDetect(t *testing.T) {
	err := Detect()
	require.NoError(t, err)
}

func TestGetStatus(t *testing.T) {
	status, err := GetStatus()
	require.NoError(t, err)

	require.True(t, status.IsEnabled)
	spew.Dump(status)
}
