package caddy

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"caddy-panel/config"
	"caddy-panel/models"
	"caddy-panel/security"
	"caddy-panel/utils"
)

// Server Caddy服务器管理
type Server struct {
	mu                sync.RWMutex
	ctx               context.Context
	cancel            context.CancelFunc
	servers           map[string]*http.Server
	proxies           map[string]*httputil.ReverseProxy
	lastGood          map[string]listenerSnapshot
	oauthPrivateKey   *rsa.PrivateKey
	oauthPublicKeyPEM string
}

type serviceRoute struct {
	service models.ServiceConfig
	handler http.Handler
}

type listenerSnapshot struct {
	listener models.PortListener
	services []models.ServiceConfig
}

type responseRecorder struct {
	http.ResponseWriter
	statusCode int
	bytesOut   uint64
}

type oauthLoginPayload struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Remember bool   `json:"remember"`
}

type deterministicReader struct {
	seed    []byte
	counter uint64
	buffer  []byte
}

func (r *responseRecorder) WriteHeader(statusCode int) {
	r.statusCode = statusCode
	r.ResponseWriter.WriteHeader(statusCode)
}

func (r *responseRecorder) Write(data []byte) (int, error) {
	if r.statusCode == 0 {
		r.statusCode = http.StatusOK
	}
	n, err := r.ResponseWriter.Write(data)
	r.bytesOut += uint64(n)
	return n, err
}

func (r *responseRecorder) Flush() {
	if flusher, ok := r.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}

func (r *responseRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hijacker, ok := r.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, fmt.Errorf("response writer does not support hijacking")
	}
	return hijacker.Hijack()
}

func (r *responseRecorder) Push(target string, opts *http.PushOptions) error {
	pusher, ok := r.ResponseWriter.(http.Pusher)
	if !ok {
		return http.ErrNotSupported
	}
	return pusher.Push(target, opts)
}

func (r *deterministicReader) Read(p []byte) (int, error) {
	filled := 0
	for filled < len(p) {
		if len(r.buffer) == 0 {
			blockInput := append([]byte{}, r.seed...)
			counterBytes := []byte{
				byte(r.counter >> 56), byte(r.counter >> 48), byte(r.counter >> 40), byte(r.counter >> 32),
				byte(r.counter >> 24), byte(r.counter >> 16), byte(r.counter >> 8), byte(r.counter),
			}
			blockInput = append(blockInput, counterBytes...)
			sum := sha256.Sum256(blockInput)
			r.buffer = sum[:]
			r.counter++
		}
		copied := copy(p[filled:], r.buffer)
		filled += copied
		r.buffer = r.buffer[copied:]
	}
	return filled, nil
}

var instance *Server
var once sync.Once

const defaultSecureSecret = security.DefaultSecureSecret

// GetServer 获取Caddy服务器单例
func GetServer() *Server {
	once.Do(func() {
		privateKey, publicKeyPEM := mustGenerateOAuthKeyPair(defaultSecureSecret)
		ctx, cancel := context.WithCancel(context.Background())
		instance = &Server{
			ctx:               ctx,
			cancel:            cancel,
			servers:           make(map[string]*http.Server),
			proxies:           make(map[string]*httputil.ReverseProxy),
			lastGood:          make(map[string]listenerSnapshot),
			oauthPrivateKey:   privateKey,
			oauthPublicKeyPEM: publicKeyPEM,
		}
	})
	return instance
}

// Start 启动所有配置的监听
func (s *Server) Start() error {
	cfg := config.GetManager().GetConfig()
	var startupErrors []string

	for _, listener := range cfg.Listeners {
		if listener.Enabled {
			if err := s.StartListener(listener); err != nil {
				startupErrors = append(startupErrors, fmt.Sprintf("端口 %d(%s): %v", listener.Port, listener.Protocol, err))
			}
		}
	}
	if len(startupErrors) > 0 {
		return fmt.Errorf("%s", strings.Join(startupErrors, "; "))
	}
	return nil
}

// Stop 停止所有服务器
func (s *Server) Stop() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.cancel()

	for _, server := range s.servers {
		server.Shutdown(context.Background())
	}

	s.servers = make(map[string]*http.Server)
	s.proxies = make(map[string]*httputil.ReverseProxy)
	s.lastGood = make(map[string]listenerSnapshot)
	return nil
}

// Restart 重启服务器
func (s *Server) Restart() error {
	if err := s.Stop(); err != nil {
		return err
	}
	return s.Start()
}

// StartListener 启动指定监听器
func (s *Server) StartListener(listener models.PortListener) error {
	cfg := config.GetManager()
	services := cfg.GetServicesByPort(listener.ID)
	return s.applyListenerConfig(listener, services)
}

// StopListener 停止指定监听器
func (s *Server) StopListener(listenerID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if server, exists := s.servers[listenerID]; exists {
		if err := server.Shutdown(context.Background()); err != nil {
			return err
		}
		delete(s.servers, listenerID)
	}
	if snapshot, exists := s.lastGood[listenerID]; exists {
		s.cleanupListenerProxiesLocked(snapshot.services)
		delete(s.lastGood, listenerID)
	}
	return nil
}

func cloneServices(services []models.ServiceConfig) []models.ServiceConfig {
	if len(services) == 0 {
		return nil
	}
	cloned := make([]models.ServiceConfig, len(services))
	copy(cloned, services)
	return cloned
}

func (s *Server) cleanupListenerProxiesLocked(services []models.ServiceConfig) {
	for _, service := range services {
		delete(s.proxies, service.ID)
	}
}

func (s *Server) buildListenerRoutes(listener models.PortListener, services []models.ServiceConfig) ([]serviceRoute, map[string]*httputil.ReverseProxy, error) {
	routes := make([]serviceRoute, 0, len(services))
	proxies := make(map[string]*httputil.ReverseProxy)
	for _, service := range services {
		if !service.Enabled {
			continue
		}
		handler, err := s.createHandler(service, proxies)
		if err != nil {
			serviceName := strings.TrimSpace(service.Name)
			if serviceName == "" {
				serviceName = service.ID
			}
			return nil, nil, fmt.Errorf("服务规则 %q 配置错误: %w", serviceName, err)
		}
		routes = append(routes, serviceRoute{
			service: service,
			handler: s.wrapServiceHandler(listener, service, handler),
		})
	}
	return routes, proxies, nil
}

func (s *Server) buildHTTPServer(listener models.PortListener, routes []serviceRoute) *http.Server {
	addr := fmt.Sprintf(":%d", listener.Port)
	return &http.Server{
		Addr: addr,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if utils.GetCertificateManager().ServeHTTPChallenge(w, r) {
				return
			}
			if s.handleOAuthRequest(listener, w, r) {
				return
			}
			host := normalizeHost(r.Host)
			if route := matchServiceRoute(routes, host); route != nil {
				route.handler.ServeHTTP(w, r)
				return
			}
			http.NotFound(w, r)
		}),
	}
}

func (s *Server) createNetListener(listener models.PortListener) (net.Listener, error) {
	addr := fmt.Sprintf(":%d", listener.Port)
	baseListener, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	if listener.Protocol != "https" {
		return baseListener, nil
	}
	tlsConfig := &tls.Config{
		GetCertificate: utils.GetCertificateManager().GetTLSCertificateForListener(listener.ID),
	}
	return tls.NewListener(baseListener, tlsConfig), nil
}

func (s *Server) serveListener(server *http.Server, listener models.PortListener, netListener net.Listener) {
	go func() {
		if err := server.Serve(netListener); err != nil && err != http.ErrServerClosed {
			fmt.Printf("Server error on port %d: %v\n", listener.Port, err)
		}
	}()
}

func (s *Server) restoreSnapshotLocked(snapshot listenerSnapshot) error {
	routes, proxies, err := s.buildListenerRoutes(snapshot.listener, snapshot.services)
	if err != nil {
		return err
	}
	server := s.buildHTTPServer(snapshot.listener, routes)
	netListener, err := s.createNetListener(snapshot.listener)
	if err != nil {
		return err
	}
	s.servers[snapshot.listener.ID] = server
	s.cleanupListenerProxiesLocked(snapshot.services)
	for id, proxy := range proxies {
		s.proxies[id] = proxy
	}
	s.serveListener(server, snapshot.listener, netListener)
	return nil
}

func (s *Server) applyListenerConfig(listener models.PortListener, services []models.ServiceConfig) error {
	routes, proxies, err := s.buildListenerRoutes(listener, services)
	if err != nil {
		return err
	}
	server := s.buildHTTPServer(listener, routes)

	s.mu.Lock()
	defer s.mu.Unlock()

	previousSnapshot, hasPrevious := s.lastGood[listener.ID]
	if existing, exists := s.servers[listener.ID]; exists {
		if err := existing.Shutdown(context.Background()); err != nil {
			return err
		}
		delete(s.servers, listener.ID)
	}
	if hasPrevious {
		s.cleanupListenerProxiesLocked(previousSnapshot.services)
	}

	netListener, err := s.createNetListener(listener)
	if err != nil {
		if hasPrevious {
			if rollbackErr := s.restoreSnapshotLocked(previousSnapshot); rollbackErr != nil {
				return fmt.Errorf("重载失败: %v；回滚到上一次正确配置也失败: %v", err, rollbackErr)
			}
			return fmt.Errorf("重载失败，已回滚到上一次正确配置: %w", err)
		}
		return err
	}

	s.servers[listener.ID] = server
	for id, proxy := range proxies {
		s.proxies[id] = proxy
	}
	s.lastGood[listener.ID] = listenerSnapshot{
		listener: listener,
		services: cloneServices(services),
	}
	s.serveListener(server, listener, netListener)
	return nil
}

func (s *Server) ReloadListener(listenerID string) error {
	listener := config.GetManager().GetListener(listenerID)
	if listener == nil {
		return fmt.Errorf("listener not found")
	}
	return s.StartListener(*listener)
}

func (s *Server) IsListenerRunning(listenerID string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, exists := s.servers[listenerID]
	return exists
}

// createHandler 根据服务配置创建处理器
func (s *Server) createHandler(service models.ServiceConfig, proxies map[string]*httputil.ReverseProxy) (http.Handler, error) {
	switch service.Type {
	case models.ServiceTypeReverseProxy:
		return s.createReverseProxyHandler(service, proxies)
	case models.ServiceTypeStatic:
		return s.createStaticHandler(service)
	case models.ServiceTypeRedirect:
		return s.createRedirectHandler(service)
	case models.ServiceTypeURLJump:
		return s.createURLJumpHandler(service)
	case models.ServiceTypeTextOutput:
		return s.createTextOutputHandler(service)
	default:
		return nil, fmt.Errorf("不支持的服务类型: %s", service.Type)
	}
}

// createReverseProxyHandler 创建反向代理处理器
func (s *Server) createReverseProxyHandler(service models.ServiceConfig, proxies map[string]*httputil.ReverseProxy) (http.Handler, error) {
	configData, err := json.Marshal(service.Config)
	if err != nil {
		return nil, err
	}

	var cfg models.ReverseProxyConfig
	if err := json.Unmarshal(configData, &cfg); err != nil {
		return nil, err
	}
	if strings.TrimSpace(cfg.Upstream) == "" {
		return nil, fmt.Errorf("代理地址不能为空")
	}

	targetURL, err := normalizeReverseProxyUpstream(cfg.Upstream)
	if err != nil {
		return nil, err
	}

	proxy := httputil.NewSingleHostReverseProxy(targetURL)
	proxies[service.ID] = proxy

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxy.ServeHTTP(w, r)
	}), nil
}

func normalizeReverseProxyUpstream(raw string) (*url.URL, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, fmt.Errorf("代理地址不能为空")
	}
	targetURL, err := url.Parse(raw)
	if err != nil {
		return nil, err
	}
	switch strings.ToLower(targetURL.Scheme) {
	case "ws":
		targetURL.Scheme = "http"
	case "wss":
		targetURL.Scheme = "https"
	}
	if targetURL.Scheme == "" || targetURL.Host == "" {
		return nil, fmt.Errorf("代理地址格式无效: %s", raw)
	}
	return targetURL, nil
}

// createStaticHandler 创建静态文件处理器
func (s *Server) createStaticHandler(service models.ServiceConfig) (http.Handler, error) {
	configData, err := json.Marshal(service.Config)
	if err != nil {
		return nil, err
	}

	var cfg models.StaticConfig
	if err := json.Unmarshal(configData, &cfg); err != nil {
		return nil, err
	}
	if strings.TrimSpace(cfg.Root) == "" {
		return nil, fmt.Errorf("静态目录不能为空")
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		relativePath := strings.TrimPrefix(r.URL.Path, "/")
		fullPath := filepath.Join(cfg.Root, filepath.FromSlash(relativePath))
		info, err := os.Stat(fullPath)
		if err != nil {
			http.NotFound(w, r)
			return
		}

		if info.IsDir() {
			if cfg.Browse {
				if !strings.HasSuffix(r.URL.Path, "/") {
					http.Redirect(w, r, r.URL.Path+"/", http.StatusMovedPermanently)
					return
				}
				renderDirectoryBrowser(w, r, fullPath)
				return
			}
			indexName := strings.TrimSpace(cfg.Index)
			if indexName != "" {
				indexPath := filepath.Join(fullPath, filepath.FromSlash(indexName))
				indexInfo, indexErr := os.Stat(indexPath)
				if indexErr == nil && !indexInfo.IsDir() {
					serveStaticFile(w, r, indexPath)
					return
				}
			}
			http.NotFound(w, r)
			return
		}

		serveStaticFile(w, r, fullPath)
	}), nil
}

type directoryEntryView struct {
	Name    string
	Href    string
	Size    string
	ModTime string
	IsDir   bool
}

func renderDirectoryBrowser(w http.ResponseWriter, r *http.Request, fullPath string) {
	entries, err := os.ReadDir(fullPath)
	if err != nil {
		http.Error(w, "读取目录失败", http.StatusInternalServerError)
		return
	}

	items := make([]directoryEntryView, 0, len(entries))
	basePath := r.URL.Path
	if !strings.HasSuffix(basePath, "/") {
		basePath += "/"
	}

	sort.SliceStable(entries, func(i, j int) bool {
		leftDir := entries[i].IsDir()
		rightDir := entries[j].IsDir()
		if leftDir != rightDir {
			return leftDir
		}
		return strings.ToLower(entries[i].Name()) < strings.ToLower(entries[j].Name())
	})

	for _, entry := range entries {
		info, infoErr := entry.Info()
		if infoErr != nil {
			continue
		}
		name := entry.Name()
		href := basePath + url.PathEscape(name)
		if entry.IsDir() {
			href += "/"
		}
		items = append(items, directoryEntryView{
			Name:    name,
			Href:    href,
			Size:    formatDirectoryEntrySize(info),
			ModTime: info.ModTime().Format("2006-01-02 15:04:05"),
			IsDir:   entry.IsDir(),
		})
	}

	parentHref := ""
	cleanPath := path.Clean("/" + strings.TrimPrefix(r.URL.Path, "/"))
	if cleanPath != "/" {
		parentHref = path.Dir(cleanPath)
		if parentHref == "." {
			parentHref = "/"
		}
		if !strings.HasSuffix(parentHref, "/") {
			parentHref += "/"
		}
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>文件浏览器 - %s</title>
<style>
body{margin:0;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;background:#f8fafc;color:#0f172a}
.page{max-width:1100px;margin:0 auto;padding:28px 18px 40px}
.header{display:flex;justify-content:space-between;align-items:flex-start;gap:16px;margin-bottom:20px;flex-wrap:wrap}
.title{font-size:28px;font-weight:800;line-height:1.2}
.path{margin-top:6px;color:#475569;font-size:14px;word-break:break-all}
.tip{color:#64748b;font-size:13px}
.card{background:#fff;border:1px solid #e2e8f0;border-radius:18px;box-shadow:0 10px 30px rgba(15,23,42,.06);overflow:hidden}
.toolbar{display:flex;justify-content:space-between;align-items:center;padding:16px 18px;border-bottom:1px solid #e2e8f0;background:#f8fafc;gap:12px;flex-wrap:wrap}
.back{display:inline-flex;align-items:center;gap:8px;color:#2563eb;text-decoration:none;font-weight:700}
.table{width:100%%;border-collapse:collapse}
.table th,.table td{padding:14px 18px;text-align:left;border-bottom:1px solid #eef2f7;font-size:14px}
.table th{background:#fff;color:#475569;font-size:12px;text-transform:uppercase;letter-spacing:.04em}
.name-link{display:inline-flex;align-items:center;gap:10px;color:#0f172a;text-decoration:none;font-weight:600}
.name-link:hover{color:#2563eb}
.icon{width:24px;text-align:center}
.type-dir{color:#2563eb}
.type-file{color:#64748b}
.muted{color:#64748b}
.empty{padding:34px 18px;text-align:center;color:#64748b}
@media (max-width: 720px){
.page{padding:18px 12px 28px}
.title{font-size:22px}
.table th,.table td{padding:12px 10px;font-size:13px}
.table th:nth-child(3),.table td:nth-child(3){display:none}
}
</style>
</head>
<body>
<div class="page">
  <div class="header">
    <div>
      <div class="title">文件浏览器</div>
      <div class="path">%s</div>
    </div>
  </div>
  <div class="card">
    <div class="toolbar">
      <div>共 %d 项</div>
      %s
    </div>
    %s
  </div>
</div>
</body>
</html>`,
		htmlEscape(strings.TrimPrefix(r.URL.Path, "/")),
		htmlEscape(r.URL.Path),
		len(items),
		directoryParentLink(parentHref),
		directoryTableHTML(items),
	)
}

func directoryParentLink(parentHref string) string {
	if parentHref == "" {
		return `<span class="muted">已在根目录</span>`
	}
	return `<a class="back" href="` + htmlEscape(parentHref) + `">← 返回上级目录</a>`
}

func directoryTableHTML(items []directoryEntryView) string {
	if len(items) == 0 {
		return `<div class="empty">当前目录为空</div>`
	}
	var builder strings.Builder
	builder.WriteString(`<table class="table"><thead><tr><th>名称</th><th>类型</th><th>大小</th><th>更新时间</th></tr></thead><tbody>`)
	for _, item := range items {
		icon := "📄"
		typeLabel := "文件"
		typeClass := "type-file"
		if item.IsDir {
			icon = "📁"
			typeLabel = "文件夹"
			typeClass = "type-dir"
		}
		builder.WriteString(`<tr>`)
		builder.WriteString(`<td><a class="name-link" href="` + htmlEscape(item.Href) + `"><span class="icon">` + icon + `</span><span>` + htmlEscape(item.Name) + `</span></a></td>`)
		builder.WriteString(`<td class="` + typeClass + `">` + typeLabel + `</td>`)
		builder.WriteString(`<td class="muted">` + htmlEscape(item.Size) + `</td>`)
		builder.WriteString(`<td class="muted">` + htmlEscape(item.ModTime) + `</td>`)
		builder.WriteString(`</tr>`)
	}
	builder.WriteString(`</tbody></table>`)
	return builder.String()
}

func formatDirectoryEntrySize(info os.FileInfo) string {
	if info.IsDir() {
		return "-"
	}
	size := info.Size()
	const unit = 1024
	if size < unit {
		return fmt.Sprintf("%d B", size)
	}
	div, exp := int64(unit), 0
	for n := size / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(size)/float64(div), "KMGTPE"[exp])
}

func serveStaticFile(w http.ResponseWriter, r *http.Request, filePath string) {
	file, err := os.Open(filePath)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil || info.IsDir() {
		http.NotFound(w, r)
		return
	}

	http.ServeContent(w, r, info.Name(), info.ModTime(), file)
}

// createRedirectHandler 创建重定向处理器
func (s *Server) createRedirectHandler(service models.ServiceConfig) (http.Handler, error) {
	configData, err := json.Marshal(service.Config)
	if err != nil {
		return nil, err
	}

	var cfg models.RedirectConfig
	if err := json.Unmarshal(configData, &cfg); err != nil {
		return nil, err
	}
	if strings.TrimSpace(cfg.To) == "" {
		return nil, fmt.Errorf("重定向地址不能为空")
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 默认使用302临时重定向
		code := http.StatusFound
		http.Redirect(w, r, cfg.To, code)
	}), nil
}

// createURLJumpHandler 创建URL跳转处理器
func (s *Server) createURLJumpHandler(service models.ServiceConfig) (http.Handler, error) {
	configData, err := json.Marshal(service.Config)
	if err != nil {
		return nil, err
	}

	var cfg models.URLJumpConfig
	if err := json.Unmarshal(configData, &cfg); err != nil {
		return nil, err
	}
	if strings.TrimSpace(cfg.TargetURL) == "" {
		return nil, fmt.Errorf("跳转地址不能为空")
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		target := cfg.TargetURL
		if cfg.PreservePath {
			u, _ := url.Parse(target)
			u.Path = r.URL.Path
			target = u.String()
		}
		http.Redirect(w, r, target, http.StatusFound)
	}), nil
}

// createTextOutputHandler 创建文本输出处理器
func (s *Server) createTextOutputHandler(service models.ServiceConfig) (http.Handler, error) {
	configData, err := json.Marshal(service.Config)
	if err != nil {
		return nil, err
	}

	var cfg models.TextOutputConfig
	if err := json.Unmarshal(configData, &cfg); err != nil {
		return nil, err
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		contentType := cfg.ContentType
		if contentType == "" {
			contentType = "text/plain; charset=utf-8"
		}
		w.Header().Set("Content-Type", contentType)

		statusCode := cfg.StatusCode
		if statusCode == 0 {
			statusCode = http.StatusOK
		}
		w.WriteHeader(statusCode)
		w.Write([]byte(cfg.Body))
	}), nil
}

func (s *Server) wrapServiceHandler(listener models.PortListener, service models.ServiceConfig, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		username := getAuthenticatedUsername(r)
		if serviceOAuthEnabled(service) && username == "" {
			target := r.URL.RequestURI()
			if target == "" {
				target = "/"
			}
			http.Redirect(w, r, "/OAuth?redirect="+url.QueryEscape(target), http.StatusFound)
			return
		}

		start := time.Now()
		utils.GetMonitor().BeginRequest(listener, service)
		recorder := &responseRecorder{ResponseWriter: w}
		next.ServeHTTP(recorder, r)
		if recorder.statusCode == 0 {
			recorder.statusCode = http.StatusOK
		}
		utils.GetMonitor().RecordRequest(listener, service, r, recorder.statusCode, recorder.bytesOut, time.Since(start), username, serviceAccessLogEnabled(service))
	})
}

func (s *Server) handleOAuthRequest(listener models.PortListener, w http.ResponseWriter, r *http.Request) bool {
	if r.URL.Path != "/OAuth" && r.URL.Path != "/_oauth/login" {
		return false
	}

	switch r.URL.Path {
	case "/_oauth/login":
		target := "/OAuth"
		if redirect := r.URL.RawQuery; redirect != "" {
			target += "?" + redirect
		}
		http.Redirect(w, r, target, http.StatusMovedPermanently)
		return true
	case "/OAuth":
		if r.Method == http.MethodGet {
			if getAuthenticatedUsername(r) != "" {
				return false
			}
			s.renderOAuthLoginPage(w, r, "")
			return true
		}
		if r.Method == http.MethodPost {
			s.handleOAuthLogin(w, r)
			return true
		}
	}

	http.NotFound(w, r)
	return true
}

func (s *Server) renderOAuthLoginPage(w http.ResponseWriter, r *http.Request, errMsg string) {
	redirectTarget := r.URL.Query().Get("redirect")
	if redirectTarget == "" {
		redirectTarget = "/"
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>OAuth 登录</title>
<style>
:root{color-scheme:light}
*{box-sizing:border-box}
body{margin:0;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;background:
radial-gradient(circle at top left,rgba(99,102,241,.26),transparent 32%%),
radial-gradient(circle at top right,rgba(14,165,233,.22),transparent 28%%),
linear-gradient(160deg,#0f172a,#1e293b 55%%,#111827);min-height:100vh;color:#0f172a}
.shell{min-height:100vh;display:flex;align-items:center;justify-content:center;padding:24px}
.card{width:100%%;max-width:980px;display:grid;grid-template-columns:minmax(0,1.05fr) minmax(0,.95fr);background:rgba(255,255,255,.96);border:1px solid rgba(255,255,255,.22);backdrop-filter:blur(14px);border-radius:28px;overflow:hidden;box-shadow:0 30px 90px rgba(15,23,42,.34)}
.hero{padding:42px 38px;background:linear-gradient(180deg,rgba(79,70,229,.96),rgba(37,99,235,.92));color:#fff;display:flex;flex-direction:column;justify-content:space-between;gap:28px}
.hero-badge{display:inline-flex;align-items:center;gap:8px;width:max-content;padding:8px 12px;border-radius:999px;background:rgba(255,255,255,.16);font-size:12px;font-weight:700;letter-spacing:.04em;text-transform:uppercase}
.hero h1{margin:0;font-size:36px;line-height:1.12;font-weight:800}
.hero p{margin:12px 0 0;font-size:15px;line-height:1.7;color:rgba(255,255,255,.88)}
.hero-list{display:grid;gap:12px}
.hero-item{display:flex;align-items:flex-start;gap:10px;font-size:14px;line-height:1.6;color:rgba(255,255,255,.9)}
.hero-item strong{color:#fff}
.form-wrap{padding:38px 34px;display:flex;align-items:center;justify-content:center;background:linear-gradient(180deg,#ffffff,#f8fafc)}
.form-inner{width:100%%;max-width:400px}
.eyebrow{display:inline-flex;align-items:center;padding:6px 10px;border-radius:999px;background:#eef2ff;color:#4338ca;font-size:12px;font-weight:700}
.form-title{margin:14px 0 6px;font-size:28px;font-weight:800;color:#0f172a}
.form-desc{margin:0 0 22px;color:#64748b;font-size:14px;line-height:1.7}
.error{background:#fef2f2;color:#b91c1c;padding:12px 14px;border-radius:14px;margin-bottom:16px;font-size:14px;border:1px solid #fecaca}
.field{margin-bottom:16px}
.field-header{display:flex;align-items:center;justify-content:space-between;gap:8px;margin-bottom:8px}
.field label{font-size:13px;color:#334155;font-weight:700}
.field-hint{font-size:12px;color:#94a3b8}
.input{width:100%%;padding:14px 15px;border:1px solid #dbe4f0;border-radius:14px;font-size:14px;transition:border-color .2s,box-shadow .2s;background:#fff}
.input:focus{outline:none;border-color:#6366f1;box-shadow:0 0 0 4px rgba(99,102,241,.14)}
.row{display:flex;align-items:center;justify-content:space-between;gap:14px;margin:4px 0 20px;flex-wrap:wrap}
.remember{display:inline-flex;align-items:center;gap:10px;color:#334155;font-size:14px;font-weight:600}
.remember input{width:16px;height:16px;accent-color:#4f46e5}
.remember-desc{font-size:12px;color:#64748b}
.btn{width:100%%;border:none;border-radius:14px;padding:14px 18px;background:linear-gradient(135deg,#4f46e5,#2563eb);color:#fff;font-size:15px;font-weight:800;cursor:pointer;box-shadow:0 12px 26px rgba(79,70,229,.28);transition:transform .18s,box-shadow .18s,opacity .18s}
.btn:hover{transform:translateY(-1px);box-shadow:0 16px 30px rgba(79,70,229,.34)}
.btn:disabled{opacity:.72;cursor:not-allowed;transform:none}
@media (max-width: 900px){
.shell{padding:14px}
.card{grid-template-columns:1fr;border-radius:22px}
.hero{padding:26px 22px;gap:20px}
.hero h1{font-size:28px}
.form-wrap{padding:24px 18px 22px}
.form-title{font-size:24px}
}
@media (max-width: 480px){
.hero h1{font-size:24px}
.hero p,.hero-item,.form-desc{font-size:13px}
.input{padding:13px 14px;font-size:14px}
.btn{padding:13px 16px}
}
</style>
</head>
<body>
<div class="shell">
  <div class="card">
    <section class="hero">
      <div>
        <div class="hero-badge">OAuth Secure Access</div>
        <h1>安全访问受保护服务</h1>
        <p>当前服务已启用 OAuth 访问控制。请登录后继续访问，凭据会在浏览器端使用公钥加密后再提交到服务端。</p>
      </div>
      <div class="hero-list">
        <div class="hero-item"><span>•</span><span><strong>服务地址登录：</strong>统一使用当前服务地址下的 <code>/OAuth</code> 入口。</span></div>
        <div class="hero-item"><span>•</span><span><strong>移动端友好：</strong>页面针对小屏设备做了自适应布局与触控优化。</span></div>
        <div class="hero-item"><span>•</span><span><strong>记住我：</strong>勾选后 JWT 有效期 30 天，否则默认 1 天。</span></div>
      </div>
    </section>
    <section class="form-wrap">
      <div class="form-inner">
        <div class="eyebrow">服务认证</div>
        <h2 class="form-title">登录继续访问</h2>
        <p class="form-desc">输入用户名和密码后，系统会加密提交凭据并在验证成功后跳转回原始访问地址。</p>
        %s
        <form id="oauthLoginForm" method="post" action="/OAuth">
          <input type="hidden" name="payload" id="oauthPayload">
          <input type="hidden" name="redirect" value="%s">
          <div class="field">
            <div class="field-header">
              <label for="oauthUsername">用户名</label>
            </div>
            <input class="input" type="text" id="oauthUsername" placeholder="请输入用户名" autocomplete="username" required>
          </div>
          <div class="field">
            <div class="field-header">
              <label for="oauthPassword">密码</label>
            </div>
            <input class="input" type="password" id="oauthPassword" placeholder="请输入密码" autocomplete="current-password" required>
          </div>
          <div class="row">
            <label class="remember">
              <input type="checkbox" id="oauthRemember">
              <span>记住我</span>
            </label>
            <div class="remember-desc">勾选后保持 30 天，否则保持 1 天</div>
          </div>
          <button class="btn" type="submit" id="oauthSubmitBtn">登录并继续</button>
        </form>
      </div>
    </section>
  </div>
</div>
<script>
const oauthPublicKeyPem = %s;
const oauthForm = document.getElementById('oauthLoginForm');
const oauthPayloadInput = document.getElementById('oauthPayload');
const oauthSubmitBtn = document.getElementById('oauthSubmitBtn');

function pemToArrayBuffer(pem) {
  const cleaned = pem.replace(/-----BEGIN PUBLIC KEY-----|-----END PUBLIC KEY-----|\s+/g, '');
  const binary = atob(cleaned);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes.buffer;
}

function arrayBufferToBase64Url(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) binary += String.fromCharCode(bytes[i]);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

oauthForm.addEventListener('submit', async (event) => {
  event.preventDefault();
  const username = document.getElementById('oauthUsername').value.trim();
  const password = document.getElementById('oauthPassword').value;
  const remember = document.getElementById('oauthRemember').checked;
  if (!username || !password) {
    oauthForm.submit();
    return;
  }
  if (!window.crypto || !window.crypto.subtle) {
    alert('当前环境不支持加密登录，请使用 HTTPS 或现代浏览器访问。');
    return;
  }
  try {
    oauthSubmitBtn.disabled = true;
    oauthSubmitBtn.textContent = '正在加密并登录...';
    const publicKey = await window.crypto.subtle.importKey(
      'spki',
      pemToArrayBuffer(oauthPublicKeyPem),
      { name: 'RSA-OAEP', hash: 'SHA-256' },
      false,
      ['encrypt']
    );
    const payload = JSON.stringify({ username, password, remember });
    const encrypted = await window.crypto.subtle.encrypt(
      { name: 'RSA-OAEP' },
      publicKey,
      new TextEncoder().encode(payload)
    );
    oauthPayloadInput.value = arrayBufferToBase64Url(encrypted);
    oauthForm.submit();
  } catch (error) {
    console.error(error);
    alert('登录加密失败，请稍后重试。');
    oauthSubmitBtn.disabled = false;
    oauthSubmitBtn.textContent = '登录并继续';
  }
});
</script>
</body>
</html>`, oauthErrorHTML(errMsg), htmlEscape(redirectTarget), strconv.Quote(s.oauthPublicKeyPEM))
}

func (s *Server) handleOAuthLogin(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		fmt.Printf("OAuth 登录失败[表单解析失败] remote=%s err=%v\n", r.RemoteAddr, err)
		s.renderOAuthLoginPage(w, r, "表单解析失败")
		return
	}

	payload, err := s.parseOAuthLoginPayload(r)
	if err != nil {
		fmt.Printf("OAuth 登录失败[解密失败] remote=%s err=%v\n", r.RemoteAddr, err)
		s.renderOAuthLoginPage(w, r, err.Error())
		return
	}

	username := strings.TrimSpace(payload.Username)
	password := payload.Password
	redirectTarget := r.FormValue("redirect")
	if redirectTarget == "" {
		redirectTarget = "/"
	}
	usedEncryptedPayload := strings.TrimSpace(r.FormValue("payload")) != ""

	user := config.GetManager().GetUserByUsername(username)
	if user == nil {
		fmt.Printf("OAuth 登录失败[用户不存在] remote=%s username=%s redirect=%s\n", r.RemoteAddr, username, redirectTarget)
		s.renderOAuthLoginPage(w, r, "用户名或密码错误")
		return
	}
	if !user.Enabled {
		fmt.Printf("OAuth 登录失败[用户被禁用] remote=%s username=%s redirect=%s\n", r.RemoteAddr, username, redirectTarget)
		s.renderOAuthLoginPage(w, r, "用户已被禁用")
		return
	}
	if !security.ComparePassword(user.Password, password) {
		fmt.Printf(
			"OAuth 登录失败[密码错误] remote=%s username=%s redirect=%s password_len=%d encrypted_payload=%t stored_secure_hash=%t default_admin_match=%t\n",
			r.RemoteAddr,
			username,
			redirectTarget,
			len(password),
			usedEncryptedPayload,
			security.IsSecurePasswordHash(user.Password),
			username == "admin" && security.ComparePassword(user.Password, "admin"),
		)
		s.renderOAuthLoginPage(w, r, "用户名或密码错误")
		return
	}

	tokenTTL := 24 * time.Hour
	if payload.Remember {
		tokenTTL = 30 * 24 * time.Hour
	}
	token, err := utils.GenerateToken(user.Username, user.Role, tokenTTL)
	if err != nil {
		fmt.Printf("OAuth 登录失败[令牌生成失败] remote=%s username=%s err=%v\n", r.RemoteAddr, username, err)
		s.renderOAuthLoginPage(w, r, "生成登录令牌失败")
		return
	}

	utils.SetAuthCookie(w, token, r.TLS != nil, tokenTTL)
	fmt.Printf("OAuth 登录成功 remote=%s username=%s remember=%t redirect=%s\n", r.RemoteAddr, username, payload.Remember, redirectTarget)
	http.Redirect(w, r, redirectTarget, http.StatusFound)
}

// ReloadService 重新加载服务
func (s *Server) ReloadService(service models.ServiceConfig) error {
	return s.ReloadListener(service.PortID)
}

// ExportConfig 导出配置为JSON
func (s *Server) ExportConfig() (map[string]interface{}, error) {
	cfg := config.GetManager().GetConfig()

	result := map[string]interface{}{
		"listeners": cfg.Listeners,
		"services":  cfg.Services,
	}

	return result, nil
}

func normalizeHost(host string) string {
	if h, _, err := net.SplitHostPort(host); err == nil {
		return strings.ToLower(h)
	}
	return strings.ToLower(host)
}

func matchServiceRoute(routes []serviceRoute, host string) *serviceRoute {
	var wildcardMatch *serviceRoute
	var defaultMatch *serviceRoute

	for i := range routes {
		domain := strings.TrimSpace(strings.ToLower(routes[i].service.Domain))
		if domain == "" || domain == "*" {
			if defaultMatch == nil {
				defaultMatch = &routes[i]
			}
			continue
		}

		if domain == host {
			return &routes[i]
		}

		if matchDomainPattern(domain, host) && wildcardMatch == nil {
			wildcardMatch = &routes[i]
		}
	}

	if wildcardMatch != nil {
		return wildcardMatch
	}
	return defaultMatch
}

func matchDomainPattern(pattern, host string) bool {
	if pattern == host {
		return true
	}

	if !strings.Contains(pattern, "*") {
		return false
	}

	quoted := regexp.QuoteMeta(pattern)
	regexPattern := "^" + strings.ReplaceAll(quoted, "\\*", ".*") + "$"
	matched, err := regexp.MatchString(regexPattern, host)
	if err != nil {
		return false
	}
	return matched
}

func serviceOAuthEnabled(service models.ServiceConfig) bool {
	return getServiceBoolOption(service.Config, "oauth", false) || service.RequireAuth
}

func serviceAccessLogEnabled(service models.ServiceConfig) bool {
	return getServiceBoolOption(service.Config, "access_log", true)
}

func getServiceBoolOption(configValue interface{}, key string, defaultValue bool) bool {
	data, err := json.Marshal(configValue)
	if err != nil {
		return defaultValue
	}

	var values map[string]interface{}
	if err := json.Unmarshal(data, &values); err != nil {
		return defaultValue
	}

	value, ok := values[key]
	if !ok {
		return defaultValue
	}

	typed, ok := value.(bool)
	if !ok {
		return defaultValue
	}
	return typed
}

func getAuthenticatedUsername(r *http.Request) string {
	claims, err := utils.GetAuthClaimsFromRequest(r)
	if err != nil || claims == nil {
		return ""
	}
	return claims.Username
}

func mustGenerateOAuthKeyPair(secret string) (*rsa.PrivateKey, string) {
	secret = security.NormalizeSecureSecret(secret)
	seed := sha256.Sum256([]byte(secret))
	privateKey, err := rsa.GenerateKey(&deterministicReader{seed: seed[:]}, 2048)
	if err != nil {
		panic(fmt.Sprintf("generate oauth rsa key failed: %v", err))
	}
	publicDER, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		panic(fmt.Sprintf("marshal oauth public key failed: %v", err))
	}
	publicPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicDER,
	})
	return privateKey, string(publicPEM)
}

func (s *Server) SetSecureSecret(secret string) {
	secret = security.NormalizeSecureSecret(secret)
	privateKey, publicKeyPEM := mustGenerateOAuthKeyPair(secret)
	s.mu.Lock()
	s.oauthPrivateKey = privateKey
	s.oauthPublicKeyPEM = publicKeyPEM
	s.mu.Unlock()
}

func (s *Server) GetOAuthPublicKeyPEM() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.oauthPublicKeyPEM
}

func (s *Server) DecryptSecurePayload(payload string) ([]byte, error) {
	s.mu.RLock()
	privateKey := s.oauthPrivateKey
	s.mu.RUnlock()
	if privateKey == nil {
		return nil, fmt.Errorf("未初始化安全密钥")
	}

	payload = strings.TrimSpace(payload)
	if payload == "" {
		return nil, fmt.Errorf("缺少加密数据")
	}

	cipherBytes, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		cipherBytes, err = base64.StdEncoding.DecodeString(payload)
		if err != nil {
			return nil, fmt.Errorf("登录数据解码失败")
		}
	}

	plainBytes, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, privateKey, cipherBytes, nil)
	if err != nil {
		return nil, fmt.Errorf("登录数据解密失败")
	}
	return plainBytes, nil
}

func (s *Server) parseOAuthLoginPayload(r *http.Request) (*oauthLoginPayload, error) {
	encryptedPayload := strings.TrimSpace(r.FormValue("payload"))
	if encryptedPayload == "" {
		username := strings.TrimSpace(r.FormValue("username"))
		password := r.FormValue("password")
		if username == "" || password == "" {
			return nil, fmt.Errorf("请填写用户名和密码")
		}
		return &oauthLoginPayload{
			Username: username,
			Password: password,
			Remember: r.FormValue("remember") == "true" || r.FormValue("remember") == "on",
		}, nil
	}

	plainBytes, err := s.DecryptSecurePayload(encryptedPayload)
	if err != nil {
		return nil, err
	}

	var payload oauthLoginPayload
	if err := json.Unmarshal(plainBytes, &payload); err != nil {
		return nil, fmt.Errorf("登录数据解析失败")
	}
	if strings.TrimSpace(payload.Username) == "" || payload.Password == "" {
		return nil, fmt.Errorf("请填写用户名和密码")
	}
	return &payload, nil
}

func oauthErrorHTML(message string) string {
	if message == "" {
		return ""
	}
	return `<div class="error">` + htmlEscape(message) + `</div>`
}

func htmlEscape(value string) string {
	replacer := strings.NewReplacer(
		"&", "&amp;",
		`"`, "&quot;",
		"<", "&lt;",
		">", "&gt;",
		"'", "&#39;",
	)
	return replacer.Replace(value)
}
