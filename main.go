package main

import (
	"fmt"
	"syscall"
	"unsafe"

	"github.com/ContinuumLLC/platform-asset-plugin/src/currentuser"
	"golang.org/x/sys/windows"
)

// Text string type value
type Text string

var (
	advapi32DLL                               = syscall.NewLazyDLL("advapi32.dll")
	impersonateProc                           = advapi32DLL.NewProc("ImpersonateLoggedOnUser")
	modadvapi32             *windows.LazyDLL  = windows.NewLazySystemDLL("advapi32.dll")
	procCreateProcessAsUser *windows.LazyProc = modadvapi32.NewProc("CreateProcessAsUserW")
)

func impersonateUser(token syscall.Token) error {
	rc, _, ec := syscall.Syscall(impersonateProc.Addr(), 1, uintptr(token), 0, 0)
	if rc == 0 {
		return error(ec)
	}
	return nil
}

func main() {
	token, err := currentuser.CurrentUserHandel()
	fmt.Println(*token, err)
	fmt.Println(impersonateUser(*token))

	si := new(syscall.StartupInfo)
	pi := new(syscall.ProcessInformation)

	returnCode, _, err := procCreateProcessAsUser.Call(
		uintptr(*token),
		uintptr(unsafe.Pointer(nil)),
		uintptr(unsafe.Pointer(Text("C:/Program Files (x86)/ITSPlatform/plugin/asset/platform-asset-plugin.exe").WChars())),
		0,
		0,
		0,
		uintptr(unsafe.Pointer(nil)),
		uintptr(unsafe.Pointer(nil)),
		uintptr(unsafe.Pointer(Text("C:\\Program Files (x86)\\ITSPlatform").WChars())),
		uintptr(unsafe.Pointer(&si)),
		uintptr(unsafe.Pointer(&pi)),
	)

	if returnCode == 0 {
		fmt.Errorf("create process as user: %s", err)
	}
}

func (t Text) Chars() *uint8 {
	if t == "" {
		return nil
	}
	return StringToCharPtr(string(t))
}

// StringToCharPtr converts a go string into a null-terminated string
// The string should be an ASCII-encoded, not UTF-8.
func StringToCharPtr(str string) *uint8 {
	if str == "" {
		n := []uint8{0}
		return &n[0]
	}
	chars := append([]byte(str), 0) // null terminated
	return &chars[0]
}

func (t Text) WChars() *uint16 {
	if t == "" {
		return nil
	}
	bs, _ := syscall.UTF16FromString(string(t))
	return &bs[0]
}
