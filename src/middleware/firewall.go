package middleware

import (
	"net/http"

	"fnproxy/utils"
)

// FirewallMiddleware 防火墙中间件（优先级最高，覆盖所有连接）
// 核心逻辑在 utils.FirewallMiddleware，避免与 fnproxy 包循环依赖
func FirewallMiddleware(next http.Handler) http.Handler {
	return utils.FirewallMiddleware(next)
}
