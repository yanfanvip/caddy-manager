package handlers

import (
	"encoding/json"
	"net/http"
	"time"

	"caddy-panel/caddy"
	"caddy-panel/config"
	"caddy-panel/security"
	"caddy-panel/utils"
)

// LoginRequest 登录请求
type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// LoginResponse 登录响应
type LoginResponse struct {
	Token string `json:"token"`
	User  struct {
		Username string `json:"username"`
		Role     string `json:"role"`
	} `json:"user"`
}

// LoginHandler 登录处理器
func LoginHandler(w http.ResponseWriter, r *http.Request) {
	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	user := config.GetManager().GetUserByUsername(req.Username)
	if user == nil {
		WriteError(w, http.StatusUnauthorized, "Invalid credentials")
		return
	}
	if !user.Enabled {
		WriteError(w, http.StatusForbidden, "User is disabled")
		return
	}

	// 验证密码
	if !security.ComparePassword(user.Password, req.Password) {
		WriteError(w, http.StatusUnauthorized, "Invalid credentials")
		return
	}

	tokenString, err := utils.GenerateToken(user.Username, user.Role, 24*time.Hour)
	if err != nil {
		WriteError(w, http.StatusInternalServerError, "Failed to generate token")
		return
	}

	utils.SetAuthCookie(w, tokenString, r.TLS != nil, 24*time.Hour)

	resp := LoginResponse{
		Token: tokenString,
	}
	resp.User.Username = user.Username
	resp.User.Role = user.Role

	WriteSuccess(w, resp)
}

func AuthPublicKeyHandler(w http.ResponseWriter, r *http.Request) {
	WriteSuccess(w, map[string]string{
		"public_key": caddy.GetServer().GetOAuthPublicKeyPEM(),
	})
}

// LogoutHandler 登出处理器
func LogoutHandler(w http.ResponseWriter, r *http.Request) {
	// JWT是无状态的，客户端只需删除token
	WriteSuccess(w, map[string]string{"message": "Logged out successfully"})
}

// GetCurrentUserHandler 获取当前用户信息
func GetCurrentUserHandler(w http.ResponseWriter, r *http.Request) {
	claims, ok := r.Context().Value("claims").(*utils.Claims)
	if !ok {
		WriteError(w, http.StatusUnauthorized, "Unauthorized")
		return
	}

	user := config.GetManager().GetUserByUsername(claims.Username)
	if user == nil {
		WriteError(w, http.StatusNotFound, "User not found")
		return
	}

	WriteSuccess(w, map[string]interface{}{
		"username": user.Username,
		"email":    user.Email,
		"enabled":  user.Enabled,
		"role":     user.Role,
	})
}

// ValidateToken 验证JWT token
func ValidateToken(tokenString string) (*utils.Claims, error) {
	return utils.ValidateToken(tokenString)
}
