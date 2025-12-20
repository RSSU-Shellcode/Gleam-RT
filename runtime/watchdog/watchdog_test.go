package watchdog

import (
	"os"
	"runtime"
	"syscall"
	"testing"
	"time"

	"github.com/davecgh/go-spew/spew"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"

	"github.com/RSSU-Shellcode/Gleam-RT/runtime"
)

var procSetHandler = modGleamRT.NewProc("WD_SetHandler")

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

	// for enable watchdog
	testSetHandler(func() uintptr {
		return 0
	})

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

func testSetHandler(handler interface{}) {
	_, _, _ = procSetHandler.Call(syscall.NewCallback(handler))
}

func TestKick(t *testing.T) {
	err := Kick()
	require.NoError(t, err)
}

func TestEnable(t *testing.T) {
	err := Enable()
	require.NoError(t, err)

	err = Enable()
	require.NoError(t, err)
}

func TestDisable(t *testing.T) {
	err := Enable()
	require.NoError(t, err)

	err = Disable()
	require.NoError(t, err)

	err = Disable()
	require.NoError(t, err)
}

func TestIsEnabled(t *testing.T) {
	err := Disable()
	require.NoError(t, err)

	enabled := IsEnabled()
	require.False(t, enabled)

	err = Enable()
	require.NoError(t, err)

	enabled = IsEnabled()
	require.True(t, enabled)

	err = Disable()
	require.NoError(t, err)
}

func TestGetStatus(t *testing.T) {
	err := Enable()
	require.NoError(t, err)

	err = Kick()
	require.NoError(t, err)

	status, err := GetStatus()
	require.NoError(t, err)

	require.True(t, status.IsEnabled)
	require.NotZero(t, status.NumKick)
	spew.Dump(status)

	// TODO not disable before exit runtime
	err = Disable()
	require.NoError(t, err)
}

func TestWatchdog(t *testing.T) {
	signal := make(chan struct{}, 1)
	resetHandler := func() uintptr {
		signal <- struct{}{}
		return 0
	}
	testSetHandler(resetHandler)

	err := Enable()
	require.NoError(t, err)

	// wait reset signal
	select {
	case <-signal:
	case <-time.After(30 * time.Second):
		t.Fatal("timed out waiting for reset signal")
	}

	err = Disable()
	require.NoError(t, err)
}
