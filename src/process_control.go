package main

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	processStopTimeout  = 8 * time.Second
	processPollInterval = 200 * time.Millisecond
)

func resolveAction(actionFlag string, args []string) (string, error) {
	action := strings.ToLower(strings.TrimSpace(actionFlag))
	if action == "" && len(args) > 0 {
		action = strings.ToLower(strings.TrimSpace(args[0]))
	}
	switch action {
	case "", "status", "stop", "restart":
		return action, nil
	default:
		return "", fmt.Errorf("action 参数仅支持 status、stop、restart")
	}
}

func readPIDFile(pidFilePath string) (int, error) {
	data, err := os.ReadFile(pidFilePath)
	if err != nil {
		return 0, err
	}
	value := strings.TrimSpace(string(data))
	if value == "" {
		return 0, fmt.Errorf("PID 文件为空")
	}
	pid, err := strconv.Atoi(value)
	if err != nil || pid <= 0 {
		return 0, fmt.Errorf("PID 文件内容无效")
	}
	return pid, nil
}

func readRunningPID(pidFilePath string) (int, bool, error) {
	pid, err := readPIDFile(pidFilePath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return 0, false, nil
		}
		_ = os.Remove(pidFilePath)
		return 0, false, nil
	}

	running, err := isProcessRunning(pid)
	if err != nil {
		return pid, false, err
	}
	if !running {
		_ = os.Remove(pidFilePath)
		return pid, false, nil
	}
	return pid, true, nil
}

func waitForProcessExit(pid int, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		running, err := isProcessRunning(pid)
		if err != nil {
			return err
		}
		if !running {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("等待进程 %d 退出超时", pid)
		}
		time.Sleep(processPollInterval)
	}
}

func stopProcessByPIDFile(pidFilePath string) (int, bool, error) {
	pid, running, err := readRunningPID(pidFilePath)
	if err != nil {
		return 0, false, err
	}
	if !running {
		return pid, false, nil
	}

	if err := terminateProcess(pid); err != nil {
		if errors.Is(err, os.ErrProcessDone) {
			if removeErr := os.Remove(pidFilePath); removeErr != nil && !os.IsNotExist(removeErr) {
				return pid, true, removeErr
			}
			return pid, true, nil
		}
		return pid, true, err
	}
	if err := waitForProcessExit(pid, processStopTimeout); err != nil {
		return pid, true, err
	}
	if err := os.Remove(pidFilePath); err != nil && !os.IsNotExist(err) {
		return pid, true, err
	}
	return pid, true, nil
}

func printProcessStatus(pidFilePath string) int {
	pid, running, err := readRunningPID(pidFilePath)
	if err != nil {
		fmt.Printf("读取进程状态失败: %v\n", err)
		return 1
	}
	if running {
		fmt.Printf("程序正在运行，PID=%d，PID 文件：%s\n", pid, pidFilePath)
		return 0
	}
	if pid > 0 {
		fmt.Printf("PID 文件存在但进程未运行，已清理失效 PID 文件：%s\n", pidFilePath)
	} else {
		fmt.Printf("程序未启动，PID 文件：%s\n", pidFilePath)
	}
	return 1
}

func ensureSingleInstance(pidFilePath string) error {
	pid, running, err := readRunningPID(pidFilePath)
	if err != nil {
		return err
	}
	if running {
		return fmt.Errorf("检测到程序已在运行，PID=%d，PID 文件：%s", pid, pidFilePath)
	}
	return nil
}
