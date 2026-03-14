package handlers

import (
	"encoding/json"
	"net"
	"net/http"
	"strings"

	"fnproxy/utils"
)

// GeoIPResult IP 归属查询结果
type GeoIPResult struct {
	IP          string `json:"ip"`
	CountryCode string `json:"country_code"`
	CountryName string `json:"country_name"`
	IsMainland  bool   `json:"is_mainland"`
}

// HandleGeoIPLookup 查询 IP 归属国家
// GET /api/geoip?ip=1.2.3.4
// POST /api/geoip  body: {"ips": ["1.2.3.4", "5.6.7.8"]}
func HandleGeoIPLookup(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		handleGeoIPSingle(w, r)
	case http.MethodPost:
		handleGeoIPBatch(w, r)
	default:
		WriteError(w, http.StatusMethodNotAllowed, "Method not allowed")
	}
}

func handleGeoIPSingle(w http.ResponseWriter, r *http.Request) {
	ip := strings.TrimSpace(r.URL.Query().Get("ip"))
	if ip == "" {
		// 返回请求方自身 IP
		ip = getRequestClientIP(r)
	}
	result := lookupIPInfo(ip)
	WriteSuccess(w, result)
}

type batchGeoIPRequest struct {
	IPs []string `json:"ips"`
}

func handleGeoIPBatch(w http.ResponseWriter, r *http.Request) {
	var req batchGeoIPRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteError(w, http.StatusBadRequest, "请求格式错误: "+err.Error())
		return
	}
	if len(req.IPs) == 0 {
		WriteError(w, http.StatusBadRequest, "IPs 不能为空")
		return
	}
	if len(req.IPs) > 100 {
		WriteError(w, http.StatusBadRequest, "单次最多查询 100 个 IP")
		return
	}

	results := make([]GeoIPResult, 0, len(req.IPs))
	for _, ip := range req.IPs {
		ip = strings.TrimSpace(ip)
		if ip == "" {
			continue
		}
		results = append(results, lookupIPInfo(ip))
	}
	WriteSuccess(w, results)
}

func lookupIPInfo(ip string) GeoIPResult {
	// 若传入的是 CIDR，取网络地址部分
	if strings.Contains(ip, "/") {
		parsed, _, err := net.ParseCIDR(ip)
		if err == nil {
			ip = parsed.String()
		}
	}
	code, name := utils.LookupCountry(ip)
	return GeoIPResult{
		IP:          ip,
		CountryCode: code,
		CountryName: name,
		IsMainland:  code == "CN",
	}
}

func getRequestClientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		if ip := strings.TrimSpace(parts[0]); ip != "" {
			return ip
		}
	}
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
