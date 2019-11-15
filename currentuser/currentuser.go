package currentuser

import (
	"os/user"
	"syscall"
	"unsafe"

	"github.com/pkg/errors"
	"golang.org/x/sys/windows"
)

type Process uintptr

const PROCESS_ALL_ACCESS = 0x1F0FFF
const TH32CS_SNAPPROCESS = 0x00000002

type WindowsProcess struct {
	ProcessID       int
	ParentProcessID int
	Exe             string
}

var (
	modadvapi32          *windows.LazyDLL  = windows.NewLazySystemDLL("advapi32.dll")
	procDuplicateTokenEx *windows.LazyProc = modadvapi32.NewProc("DuplicateTokenEx")
)

// Open handel from aprocess, verify returned handle is for current user
func decodeProcess(pid int) (*syscall.Token, error) {
	var (
		userToken syscall.Token = 0
	)

	handle, err := syscall.OpenProcess(syscall.TOKEN_ALL_ACCESS, false, uint32(pid))
	if err != nil {
		return nil, errors.Wrapf(err, "OpenProcess failed for pid=%v", pid)
	}
	defer syscall.CloseHandle(handle)

	// Find process token via win32.
	var token syscall.Token
	err = syscall.OpenProcessToken(handle, syscall.TOKEN_ALL_ACCESS, &token)
	if err != nil {
		return nil, errors.Wrapf(err, "OpenProcessToken failed for pid=%v", pid)
	}

	// Find the token user.
	tokenUser, err := token.GetTokenUser()
	if err != nil {
		return nil, errors.Wrapf(err, "GetTokenInformation failed for pid=%v", pid)
	}

	// get Session ID of process creator
	sid, sidErr := tokenUser.User.Sid.String()
	if sidErr != nil {
		return nil, errors.Wrapf(err, "failed while looking up account name for pid=%v", pid)
	}

	// Get current User
	currentUser, err := user.Current()

	// Check current user SID with process creator SID ( Making sure handle received is correct )
	if sid == currentUser.Uid {
		// Need to duplicate token
		returnCode, _, err := procDuplicateTokenEx.Call(
			uintptr(token),
			0,
			0,
			uintptr(1), // SecurityAnonymous
			uintptr(1), // PRIMARY_TOKEN
			uintptr(unsafe.Pointer(&userToken)),
		)

		if returnCode == 0 {
			return nil, errors.Wrapf(err, "failed to duplicate process token handle for pid=%v", pid)
		}
	}

	// Close token to prevent handle leaks.
	err = token.Close()
	if err != nil {
		return nil, errors.Wrapf(err, "failed while closing process token handle for pid=%v", pid)
	}

	return &userToken, nil
}

// CurrentUserHandel ...
func CurrentUserHandel() (*syscall.Token, error) {
	handle, err := windows.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(handle)

	var entry windows.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))
	// get the first process
	err = windows.Process32First(handle, &entry)
	if err != nil {
		return nil, err
	}

	for {
		newProcess := newWindowsProcess(&entry)
		// We can user other processes also to get handle
		if newProcess.Exe == "explorer.exe" {
			// Get handle by passing ProcessID
			token, err := decodeProcess(newProcess.ProcessID)
			if err != nil {
				return nil, err
			}
			if token != nil {
				return token, nil
			}
			// Look for another explorer.exe (if any)
			continue
		}
		err = windows.Process32Next(handle, &entry)
		if err != nil {
			return nil, err
		}
	}
}

func newWindowsProcess(e *windows.ProcessEntry32) WindowsProcess {
	// Find when the string ends for decoding
	end := 0
	for {
		if e.ExeFile[end] == 0 {
			break
		}
		end++
	}

	return WindowsProcess{
		ProcessID:       int(e.ProcessID),
		ParentProcessID: int(e.ParentProcessID),
		Exe:             syscall.UTF16ToString(e.ExeFile[:end]),
	}
}
