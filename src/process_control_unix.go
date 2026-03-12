//go:build !windows

package main

import (
	"errors"
	"os"
	"syscall"
)

func isProcessRunning(pid int) (bool, error) {
	err := syscall.Kill(pid, syscall.Signal(0))
	if err == nil {
		return true, nil
	}
	if errors.Is(err, syscall.ESRCH) {
		return false, nil
	}
	if errors.Is(err, syscall.EPERM) {
		return true, nil
	}
	return false, err
}

func terminateProcess(pid int) error {
	err := syscall.Kill(pid, syscall.SIGTERM)
	if err == nil {
		return nil
	}
	if errors.Is(err, syscall.ESRCH) {
		return os.ErrProcessDone
	}
	return err
}
