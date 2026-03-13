package handlers

import (
	"encoding/json"
	"net/http"
	"strconv"

	"caddy-panel/security"
)

// SecurityLogsResponse 安全日志响应
type SecurityLogsResponse struct {
	Logs     interface{} `json:"logs"`
	Total    int         `json:"total"`
	Page     int         `json:"page"`
	PageSize int         `json:"page_size"`
}

// HandleGetSecurityLogs 获取安全日志列表
func HandleGetSecurityLogs(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()

	// 获取查询参数
	logType := query.Get("type")
	level := query.Get("level")
	keyword := query.Get("keyword")
	pageStr := query.Get("page")
	pageSizeStr := query.Get("page_size")

	page := 1
	pageSize := 50
	if p, err := strconv.Atoi(pageStr); err == nil && p > 0 {
		page = p
	}
	if ps, err := strconv.Atoi(pageSizeStr); err == nil && ps > 0 && ps <= 200 {
		pageSize = ps
	}

	// 查询日志
	logs, total := security.GetAuditLogger().QueryLogs(logType, level, keyword, page, pageSize)

	// 返回响应
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(SecurityLogsResponse{
		Logs:     logs,
		Total:    total,
		Page:     page,
		PageSize: pageSize,
	})
}

// HandleGetSecurityLogStats 获取安全日志统计
func HandleGetSecurityLogStats(w http.ResponseWriter, r *http.Request) {
	stats := security.GetAuditLogger().GetStats()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}

// HandleClearSecurityLogs 清空安全日志
func HandleClearSecurityLogs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	security.GetAuditLogger().ClearLogs()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}
