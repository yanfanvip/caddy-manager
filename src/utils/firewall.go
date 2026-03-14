package utils

import (
	"net"
	"net/http"
	"sort"
	"strings"

	"fnproxy/config"
	"fnproxy/models"
)

// FirewallMiddleware 防火墙中间件（最高优先级）
func FirewallMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cfg := config.GetManager()
		firewallCfg := cfg.GetFirewallConfig()

		// 防火墙未启用，直接放行
		if !firewallCfg.Enabled {
			next.ServeHTTP(w, r)
			return
		}

		// 获取客户端IP
		clientIP := firewallGetClientIP(r)

		// localhost 永远允许访问
		if ip := net.ParseIP(clientIP); ip != nil && ip.IsLoopback() {
			next.ServeHTTP(w, r)
			return
		}

		// 获取客户端国家
		country := firewallGetCountryByIP(clientIP)

		// 匹配规则
		action := firewallMatchRules(clientIP, country, firewallCfg)

		switch action {
		case models.FirewallActionDeny:
			firewallDropConnection(w)
			return
		case models.FirewallActionAllow:
			next.ServeHTTP(w, r)
		default:
			if firewallCfg.DefaultDeny {
				firewallDropConnection(w)
			} else {
				next.ServeHTTP(w, r)
			}
		}
	})
}

// firewallDropConnection 直接关闭连接，不返回任何数据（DROP 行为）
func firewallDropConnection(w http.ResponseWriter) {
	// 优先通过 Hijack 接管并关闭底层 TCP 连接，客户端收到 RST
	if hijacker, ok := w.(http.Hijacker); ok {
		if conn, _, err := hijacker.Hijack(); err == nil {
			conn.Close()
			return
		}
	}
	// HTTP/2 或不支持 Hijack 时：发送空响应体，并通知对端关闭连接
	w.Header().Set("Connection", "close")
	w.WriteHeader(http.StatusNoContent)
}

func firewallGetClientIP(r *http.Request) string {
	xff := r.Header.Get("X-Forwarded-For")
	if xff != "" {
		ips := firewallSplitIPs(xff)
		if len(ips) > 0 {
			return ips[0]
		}
	}
	xri := r.Header.Get("X-Real-IP")
	if xri != "" {
		return xri
	}
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return ip
}

func firewallSplitIPs(xff string) []string {
	var ips []string
	for _, ip := range strings.Split(xff, ",") {
		ip = strings.TrimSpace(ip)
		if ip != "" && ip != "unknown" {
			ips = append(ips, ip)
		}
	}
	return ips
}

func firewallGetCountryByIP(ip string) string {
	code, _ := LookupCountry(ip)
	return code
}

func firewallMatchRules(clientIP, country string, cfg *models.FirewallConfig) models.FirewallAction {
	rules := cfg.Rules
	if len(rules) == 0 {
		return ""
	}

	sortedRules := make([]models.FirewallRule, len(rules))
	copy(sortedRules, rules)
	sort.Slice(sortedRules, func(i, j int) bool {
		return sortedRules[i].Priority < sortedRules[j].Priority
	})

	for _, rule := range sortedRules {
		if !rule.Enabled {
			continue
		}
		if rule.Type == models.FirewallRuleTypeIP {
			if firewallMatchIPRule(clientIP, rule.IPs) {
				return rule.Action
			}
		}
		if rule.Type == models.FirewallRuleTypeCountry {
			if firewallMatchCountryRule(country, rule.Countries) {
				return rule.Action
			}
		}
	}
	return ""
}

func firewallMatchIPRule(clientIP string, ips []string) bool {
	if len(ips) == 0 {
		return false
	}
	client := net.ParseIP(clientIP)
	if client == nil {
		return false
	}
	for _, ipRange := range ips {
		ipRange = strings.TrimSpace(ipRange)
		if ipRange == "" {
			continue
		}
		_, ipNet, err := net.ParseCIDR(ipRange)
		if err != nil {
			if ipRange == clientIP {
				return true
			}
			continue
		}
		if ipNet.Contains(client) {
			return true
		}
	}
	return false
}

func firewallMatchCountryRule(country string, countries []string) bool {
	if country == "" || len(countries) == 0 {
		return false
	}
	for _, c := range countries {
		if c == country {
			return true
		}
	}
	return false
}
