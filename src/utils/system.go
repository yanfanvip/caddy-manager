package utils

import (
	"fmt"
	"os"
	"runtime"
	"time"

	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/host"
	"github.com/shirou/gopsutil/v3/net"
)

var (
	startTime = time.Now()
	lastNetIO *net.IOCountersStat
)

// GetServerStatus 获取服务器状态
func GetServerStatus() (map[string]interface{}, error) {
	status := make(map[string]interface{})

	// 运行时间
	status["uptime"] = formatUptime(time.Since(startTime))

	// 当前程序内存占用
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)
	status["memory_used"] = memStats.Alloc
	status["memory_total"] = memStats.Sys
	status["memory_percent"] = 0

	// CPU使用率
	cpuPercent, err := cpu.Percent(time.Second, false)
	if err != nil {
		return nil, err
	}
	if len(cpuPercent) > 0 {
		status["cpu_usage"] = cpuPercent[0]
	} else {
		status["cpu_usage"] = 0
	}

	// 网络IO
	netIO, err := net.IOCounters(false)
	if err != nil {
		return nil, err
	}
	if len(netIO) > 0 {
		status["network_in"] = netIO[0].BytesRecv
		status["network_out"] = netIO[0].BytesSent

		// 计算速率
		if lastNetIO != nil {
			if netIO[0].BytesRecv >= lastNetIO.BytesRecv {
				status["network_in_rate"] = netIO[0].BytesRecv - lastNetIO.BytesRecv
			} else {
				status["network_in_rate"] = 0
			}
			if netIO[0].BytesSent >= lastNetIO.BytesSent {
				status["network_out_rate"] = netIO[0].BytesSent - lastNetIO.BytesSent
			} else {
				status["network_out_rate"] = 0
			}
		} else {
			status["network_in_rate"] = 0
			status["network_out_rate"] = 0
		}
		lastNetIO = &netIO[0]
	}

	// 主机信息
	hostInfo, err := host.Info()
	if err != nil {
		return nil, err
	}
	status["hostname"] = hostInfo.Hostname
	status["os"] = hostInfo.OS
	status["platform"] = hostInfo.Platform

	return status, nil
}

// FormatBytes 格式化字节大小
func FormatBytes(bytes uint64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := uint64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}

// GetHostname 获取主机名
func GetHostname() string {
	hostname, _ := os.Hostname()
	return hostname
}

// GetGoVersion 获取Go版本
func GetGoVersion() string {
	return runtime.Version()
}

func formatUptime(duration time.Duration) string {
	if duration < time.Minute {
		return fmt.Sprintf("%d秒", int(duration.Seconds()))
	}
	if duration < time.Hour {
		return fmt.Sprintf("%d分钟", int(duration.Minutes()))
	}
	if duration < 24*time.Hour {
		return fmt.Sprintf("%d小时", int(duration.Hours()))
	}

	days := int(duration / (24 * time.Hour))
	hours := int(duration % (24 * time.Hour) / time.Hour)
	return fmt.Sprintf("%d天 %d小时", days, hours)
}
