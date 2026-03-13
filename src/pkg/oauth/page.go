package oauth

import (
	_ "embed"
	"fmt"
	"html"
	"io"
	"net/http"
	"strconv"
)

//go:embed forge.min.js
var forgeMinJS string

// RenderLoginPage 渲染 OAuth 登录页面
func RenderLoginPage(w http.ResponseWriter, redirectTarget string, errMsg string, publicKeyPEM string) {
	if redirectTarget == "" {
		redirectTarget = "/"
	}

	errorHTML := ""
	if errMsg != "" {
		errorHTML = fmt.Sprintf(`<div class="error">%s</div>`, html.EscapeString(errMsg))
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
.hero{display:none}
.form-wrap{padding:24px 18px 22px}
.form-title{font-size:24px}
}
@media (max-width: 480px){
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
        <div class="hero-item"><span>•</span><span><strong>统一认证：</strong>管理后台与代理服务共用 OAuth 认证体系。</span></div>
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
        <form id="oauthLoginForm" method="post" action="">
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
<script>`, errorHTML, html.EscapeString(redirectTarget))
	io.WriteString(w, forgeMinJS)
	fmt.Fprintf(w, `</script>
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

async function encryptPayload(payload) {
  if (window.crypto && window.crypto.subtle) {
    try {
      const publicKey = await window.crypto.subtle.importKey(
        'spki', pemToArrayBuffer(oauthPublicKeyPem),
        { name: 'RSA-OAEP', hash: 'SHA-256' }, false, ['encrypt']
      );
      const encrypted = await window.crypto.subtle.encrypt(
        { name: 'RSA-OAEP' }, publicKey, new TextEncoder().encode(payload)
      );
      return arrayBufferToBase64Url(encrypted);
    } catch (e) { console.warn('Web Crypto 失败, 回退到 forge:', e); }
  }
  const pk = forge.pki.publicKeyFromPem(oauthPublicKeyPem);
  const enc = pk.encrypt(payload, 'RSA-OAEP', { md: forge.md.sha256.create(), mgf1: { md: forge.md.sha256.create() } });
  return forge.util.encode64(enc).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
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
  try {
    oauthSubmitBtn.disabled = true;
    oauthSubmitBtn.textContent = '正在加密并登录...';
    const payload = JSON.stringify({ username, password, remember });
    oauthPayloadInput.value = await encryptPayload(payload);
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
</html>`, strconv.Quote(publicKeyPEM))
}
