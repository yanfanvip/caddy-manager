package models

import (
	"time"
)

// ServerStatus 服务器状态
type ServerStatus struct {
	Uptime        string  `json:"uptime"`
	MemoryUsed    uint64  `json:"memory_used"`
	MemoryTotal   uint64  `json:"memory_total"`
	MemoryPercent float64 `json:"memory_percent"`
	NetworkIn     uint64  `json:"network_in"`
	NetworkOut    uint64  `json:"network_out"`
	CPUUsage      float64 `json:"cpu_usage"`
}

// NetworkSample 网络采样点
type NetworkSample struct {
	Timestamp time.Time `json:"timestamp"`
	InRate    float64   `json:"in_rate"`
	OutRate   float64   `json:"out_rate"`
}

// RuntimeStats 运行时统计
type RuntimeStats struct {
	RequestCount      uint64    `json:"request_count"`
	ActiveConnections int64     `json:"active_connections"`
	BytesInTotal      uint64    `json:"bytes_in_total"`
	BytesOutTotal     uint64    `json:"bytes_out_total"`
	BytesInRate       float64   `json:"bytes_in_rate"`
	BytesOutRate      float64   `json:"bytes_out_rate"`
	LastSeenAt        time.Time `json:"last_seen_at"`
}

// ListenerRuntimeStats 端口监听运行时统计
type ListenerRuntimeStats struct {
	ListenerID string `json:"listener_id"`
	Port       int    `json:"port"`
	RuntimeStats
}

// ServiceRuntimeStats 服务运行时统计
type ServiceRuntimeStats struct {
	ServiceID   string      `json:"service_id"`
	ListenerID  string      `json:"listener_id"`
	ServiceName string      `json:"service_name"`
	Domain      string      `json:"domain"`
	Type        ServiceType `json:"type"`
	RuntimeStats
}

// AccessLogEntry 访问日志
type AccessLogEntry struct {
	ID           string    `json:"id"`
	Timestamp    time.Time `json:"timestamp"`
	ListenerID   string    `json:"listener_id"`
	ListenerPort int       `json:"listener_port"`
	ServiceID    string    `json:"service_id"`
	ServiceName  string    `json:"service_name"`
	Host         string    `json:"host"`
	Method       string    `json:"method"`
	Path         string    `json:"path"`
	StatusCode   int       `json:"status_code"`
	DurationMS   int64     `json:"duration_ms"`
	BytesIn      uint64    `json:"bytes_in"`
	BytesOut     uint64    `json:"bytes_out"`
	RemoteAddr   string    `json:"remote_addr"`
	Username     string    `json:"username"`
}

// PortListener 端口监听配置
type PortListener struct {
	ID        string    `json:"id"`
	Port      int       `json:"port"`
	Protocol  string    `json:"protocol"` // http, https
	Enabled   bool      `json:"enabled"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// ServiceType 服务类型
type ServiceType string

const (
	ServiceTypeReverseProxy ServiceType = "reverse_proxy"
	ServiceTypeStatic       ServiceType = "static"
	ServiceTypeRedirect     ServiceType = "redirect"
	ServiceTypeURLJump      ServiceType = "url_jump"
	ServiceTypeTextOutput   ServiceType = "text_output"
)

// ServiceConfig 服务配置
type ServiceConfig struct {
	ID            string      `json:"id"`
	PortID        string      `json:"port_id"`
	Name          string      `json:"name"` // 服务名称
	Type          ServiceType `json:"type"`
	Domain        string      `json:"domain"`                   // 域名(支持*匹配)
	SortOrder     int         `json:"sort_order,omitempty"`     // 同端口下的显示/匹配顺序
	CertificateID string      `json:"certificate_id,omitempty"` // 显式绑定证书
	Enabled       bool        `json:"enabled"`
	Config        interface{} `json:"config"`       // 具体配置
	RequireAuth   bool        `json:"require_auth"` // 是否需要认证
	CreatedAt     time.Time   `json:"created_at"`
	UpdatedAt     time.Time   `json:"updated_at"`
}

// ReverseProxyConfig 反向代理配置
type ReverseProxyConfig struct {
	Name        string `json:"name"`         // 服务名称
	Domain      string `json:"domain"`       // 域名(支持*匹配)
	Upstream    string `json:"upstream"`     // 上游服务器地址
	Timeout     int    `json:"timeout"`      // 超时设置(秒)
	OAuth       bool   `json:"oauth"`        // 是否开启OAuth认证
	AccessLog   bool   `json:"access_log"`   // 记录访问日志
	HealthCheck bool   `json:"health_check"` // 健康检查
}

// StaticConfig 静态文件配置
type StaticConfig struct {
	Root      string `json:"root"`       // 根目录
	Index     string `json:"index"`      // 默认索引文件
	Browse    bool   `json:"browse"`     // 是否允许目录浏览
	OAuth     bool   `json:"oauth"`      // 是否开启OAuth认证
	AccessLog bool   `json:"access_log"` // 记录访问日志
}

// RedirectConfig 重定向配置
type RedirectConfig struct {
	To        string `json:"to"`         // 重定向目标
	OAuth     bool   `json:"oauth"`      // 是否开启OAuth认证
	AccessLog bool   `json:"access_log"` // 记录访问日志
}

// URLJumpConfig URL跳转配置
type URLJumpConfig struct {
	TargetURL    string `json:"target_url"`    // 目标URL
	OAuth        bool   `json:"oauth"`         // 是否开启OAuth认证
	AccessLog    bool   `json:"access_log"`    // 记录访问日志
	PreservePath bool   `json:"preserve_path"` // 是否保留路径
}

// TextOutputConfig 文本输出配置
type TextOutputConfig struct {
	ContentType string `json:"content_type"` // Content-Type
	Body        string `json:"body"`         // 响应内容
	StatusCode  int    `json:"status_code"`  // HTTP状态码
	OAuth       bool   `json:"oauth"`        // 是否开启OAuth认证
	AccessLog   bool   `json:"access_log"`   // 记录访问日志
}

// CertificateSource 证书来源
type CertificateSource string

const (
	CertificateSourceACME     CertificateSource = "acme"
	CertificateSourceImported CertificateSource = "imported"
	CertificateSourceFileSync CertificateSource = "file_sync"
)

// CertificateChallengeType 证书校验方式
type CertificateChallengeType string

const (
	CertificateChallengeHTTP CertificateChallengeType = "http01"
	CertificateChallengeDNS  CertificateChallengeType = "dns01"
)

// CertificateDNSProvider DNS 服务商
type CertificateDNSProvider string

const (
	CertificateDNSTencentCloud CertificateDNSProvider = "tencentcloud"
	CertificateDNSAliDNS       CertificateDNSProvider = "alidns"
	CertificateDNSCloudflare   CertificateDNSProvider = "cloudflare"
)

// CertificateStatus 证书状态
type CertificateStatus string

const (
	CertificateStatusPending CertificateStatus = "pending"
	CertificateStatusValid   CertificateStatus = "valid"
	CertificateStatusRenew   CertificateStatus = "renewing"
	CertificateStatusError   CertificateStatus = "error"
	CertificateStatusExpired CertificateStatus = "expired"
)

// CertificateDNSConfig DNS 验证配置
type CertificateDNSConfig struct {
	TencentSecretID     string `json:"tencent_secret_id,omitempty"`
	TencentSecretKey    string `json:"tencent_secret_key,omitempty"`
	TencentSessionToken string `json:"tencent_session_token,omitempty"`
	TencentRegion       string `json:"tencent_region,omitempty"`

	AliAccessKey     string `json:"ali_access_key,omitempty"`
	AliSecretKey     string `json:"ali_secret_key,omitempty"`
	AliSecurityToken string `json:"ali_security_token,omitempty"`
	AliRegionID      string `json:"ali_region_id,omitempty"`
	AliRAMRole       string `json:"ali_ram_role,omitempty"`

	CloudflareEmail       string `json:"cloudflare_email,omitempty"`
	CloudflareAPIKey      string `json:"cloudflare_api_key,omitempty"`
	CloudflareDNSAPIToken string `json:"cloudflare_dns_api_token,omitempty"`
	CloudflareZoneToken   string `json:"cloudflare_zone_token,omitempty"`
}

// CertificateConfig 证书配置
type CertificateConfig struct {
	ID              string                   `json:"id"`
	Name            string                   `json:"name"`
	Domains         []string                 `json:"domains"`
	Source          CertificateSource        `json:"source"`
	ChallengeType   CertificateChallengeType `json:"challenge_type"`
	DNSProvider     CertificateDNSProvider   `json:"dns_provider,omitempty"`
	DNSConfig       CertificateDNSConfig     `json:"dns_config,omitempty"`
	AccountEmail    string                   `json:"account_email,omitempty"`
	AutoRenew       bool                     `json:"auto_renew"`
	RenewBeforeDays int                      `json:"renew_before_days"`

	CertPath         string `json:"cert_path"`
	KeyPath          string `json:"key_path"`
	SourceConfigPath string `json:"source_config_path,omitempty"`
	AccountKeyPath   string `json:"account_key_path,omitempty"`
	RegistrationURI  string `json:"registration_uri,omitempty"`
	CertURL          string `json:"cert_url,omitempty"`
	CertStableURL    string `json:"cert_stable_url,omitempty"`

	Issuer            string            `json:"issuer,omitempty"`
	Status            CertificateStatus `json:"status"`
	LastError         string            `json:"last_error,omitempty"`
	LastIssuedAt      *time.Time        `json:"last_issued_at,omitempty"`
	LastRenewedAt     *time.Time        `json:"last_renewed_at,omitempty"`
	LastSyncedAt      *time.Time        `json:"last_synced_at,omitempty"`
	CertFileUpdatedAt *time.Time        `json:"cert_file_updated_at,omitempty"`
	KeyFileUpdatedAt  *time.Time        `json:"key_file_updated_at,omitempty"`
	ExpiresAt         *time.Time        `json:"expires_at,omitempty"`
	NextRenewAt       *time.Time        `json:"next_renew_at,omitempty"`
	CreatedAt         time.Time         `json:"created_at"`
	UpdatedAt         time.Time         `json:"updated_at"`
}

// User 用户
type User struct {
	ID        string    `json:"id"`
	Username  string    `json:"username"`
	Password  string    `json:"password"` // 加密存储
	Token     string    `json:"token,omitempty"`
	Email     string    `json:"email"`
	Enabled   bool      `json:"enabled"`
	Role      string    `json:"role"` // admin, user
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// SSHConnection SSH连接配置
type SSHConnection struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Host      string    `json:"host"`
	Port      int       `json:"port"`
	Username  string    `json:"username"`
	Password  string    `json:"password"`
	WorkDir   string    `json:"work_dir"`
	IsLocal   bool      `json:"is_local"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// TerminalManagedSession 终端托管会话
type TerminalManagedSession struct {
	ID            string    `json:"id"`
	ConnectionID  string    `json:"connection_id"`
	Name          string    `json:"name"`
	Host          string    `json:"host"`
	Port          int       `json:"port"`
	Username      string    `json:"username"`
	WorkDir       string    `json:"work_dir"`
	IsLocal       bool      `json:"is_local"`
	Attached      bool      `json:"attached"`
	Status        string    `json:"status"`
	CreatedAt     time.Time `json:"created_at"`
	LastHeartbeat time.Time `json:"last_heartbeat"`
}

// GlobalConfig 全局配置
type GlobalConfig struct {
	AdminPort                      int    `json:"admin_port"`                        // 管理后台端口
	DefaultAuth                    bool   `json:"default_auth"`                      // 默认启用认证
	LogLevel                       string `json:"log_level"`                         // 日志级别
	LogFile                        string `json:"log_file"`                          // 日志文件路径
	LogRetentionDays               int    `json:"log_retention_days"`                // 日志保留天数
	MaxAccessLogEntries            int    `json:"max_access_log_entries"`            // 最大访问日志条数
	CertificateConfigPath          string `json:"certificate_config_path"`           // 外部证书配置文件路径
	CertificateSyncIntervalSeconds int    `json:"certificate_sync_interval_seconds"` // 外部证书同步周期
}

// AppConfig 应用配置
type AppConfig struct {
	Global    GlobalConfig        `json:"global"`
	Listeners []PortListener      `json:"listeners"`
	Services  []ServiceConfig     `json:"services"`
	Certs     []CertificateConfig `json:"certs"`
	Users     []User              `json:"users"`
	SSH       []SSHConnection     `json:"ssh"`
}
