package http

import (
	"bufio"
	"encoding/json"
	"fmt"
	"math/rand"
	"net"
	"net/textproto"
	"net/url"
	"strings"
	"time"

	"github.com/Laji-HoneyPot/honeypot/internal/core/log"
	"github.com/Laji-HoneyPot/honeypot/internal/core/store"
)

// Server 模拟 HTTP 服务（nginx 指纹 + 面包屑引流 + 浏览器反制 JS 注入）
// 核心设计：页面中嵌入天然不可见的"面包屑"链接（HTML注释、robots.txt隐藏路径等），
// 正常用户无动机访问这些路径，只有扫描器和攻击者才会触碰，实现访问者即攻击者的判定。
// 每次响应自动注入浏览器指纹采集 JS，实现被动式溯源。
type Server struct {
	logger      *log.Logger
	store       *store.Store
	breadcrumbs []string // 面包屑路径列表
	// 浏览器反制 JS Payload，在每个 HTML 页面中自动注入
	fingerprintJS       string
	countermeasureCB    CountermeasureCallback // 面包屑触发时的额外反制 JS 回调
	decoyPageCB         DecoyPageCallback      // 诱饵页面回调（JSP/CS 等完整页面）
	customTemplates     []CustomTemplate       // YAML 自定义响应模板
	capturePostCallback CapturePostCallback
}

// CustomTemplate 自定义 HTTP 响应模板
type CustomTemplate struct {
	Path         string `yaml:"path"`
	Status       int    `yaml:"status"`
	ContentType  string `yaml:"content_type"`
	Body         string `yaml:"body"`
	IsBreadcrumb bool   `yaml:"is_breadcrumb"`
}

// New 创建 HTTP 蜜罐，st 可选（传 nil 则跳过 UA 补录）
func New(logger *log.Logger, st *store.Store) *Server {
	breadcrumbs := []string{
		"/admin/config.php",
		"/wp-admin/install.php",
		"/.git/config",
		"/api/v1/internal/users",
		"/backup/database.sql",
		"/debug/pprof/",
		"/actuator/env",
		"/actuator/heapdump",
		"/actuator/mappings",
		"/actuator/beans",
		"/actuator/configprops",
		"/swagger-ui.html",
		"/swagger-ui/index.html",
		"/v2/api-docs",
		"/swagger-resources",
		"/shell.jsp",
		"/cmd.jsp",
		"/test.jsp",
		"/druid/index.html",
		"/phpmyadmin/index.php",
		"/nacos/v1/auth/login",
		"/nacos/v1/cs/configs",
		"/consul/v1/agent/services",
		"/kibana/app/home",
		"/grafana/login",
		"/jenkins/script",
		"/solr/admin/cores",
		"/.env",
		"/.DS_Store",
		"/config/application.yml",
		// 敏感文件读取路径（高风险）
		"/etc/passwd",
		"/etc/shadow",
		"/etc/hosts",
		"/proc/self/environ",
		"/proc/self/cmdline",
		"/root/.ssh/id_rsa",
		"/root/.ssh/authorized_keys",
		"/etc/ssl/private/ssl-cert-snakeoil.key",
		"/etc/kubernetes/admin.conf",
		"/var/log/auth.log",
		// 加密分区/外部存储探测
		"/etc/crypttab",
		"/dev/mapper/control",
		"/mnt/external/backup",
		"/media/usb/config.ini",
		// 路径穿越探测
		"/../../../../etc/passwd",
		"/....//....//....//etc/passwd",
		"/..;/..;/..;/etc/passwd",
		// 扩展配置泄露
		"/.aws/credentials",
		"/.kube/config",
		"/.docker/config.json",
		"/id_rsa",
		"/id_ed25519",
	}
	fpJS := buildFingerprintJS()
	return &Server{
		logger:        logger,
		store:         st,
		breadcrumbs:   breadcrumbs,
		fingerprintJS: fpJS,
	}
}

// CapturePostCallback POST 请求体捕获回调 — 用于记录登录凭据等敏感数据
type CapturePostCallback func(remoteIP, path, contentType, body string)

// BreadcrumbCallback 面包屑触发回调
type BreadcrumbCallback func(remoteIP, path, userAgent string)

// CountermeasureCallback 反制 Payload 注入回调
// 参数：path（请求路径）、userAgent（浏览器 UA）、remoteIP（攻击者 IP）
// 返回：要注入的反制 JS 代码（完整 <script> 标签或纯 JS）
type CountermeasureCallback func(path, userAgent, remoteIP string) string

// DecoyPageCallback 诱饵页面回调 — 返回完整 HTML/JSP 页面响应
// 参数：decoyType（诱饵类型，如 "behinder", "cs"）、path（请求路径）
// 返回：完整 HTTP 响应体
type DecoyPageCallback func(decoyType, path string) string

// Handle 处理一个 TCP 连接，模拟 HTTP 交互。
// onBreadcrumb 为面包屑触发回调，传入 nil 时不触发。
func (s *Server) Handle(conn net.Conn, onBreadcrumb BreadcrumbCallback) {
	defer conn.Close()

	remote := conn.RemoteAddr().String()
	conn.SetDeadline(time.Now().Add(30 * time.Second))
	reader := bufio.NewReader(conn)
	tp := textproto.NewReader(reader)

	for {
		line, err := tp.ReadLine()
		if err != nil {
			return
		}

		parts := strings.Fields(line)
		if len(parts) < 2 {
			return
		}
		method, path := parts[0], parts[1]
		httpVersion := "HTTP/1.1"
		if len(parts) >= 3 {
			httpVersion = parts[2]
		}

		headers, err := tp.ReadMIMEHeader()
		if err != nil {
			return
		}

		// 读取 POST/PUT 请求体（捕获登录凭据等）
		var postBody string
		if method == "POST" || method == "PUT" || method == "PATCH" {
			cl := headers.Get("Content-Length")
			if cl != "" {
				clen := 0
				fmt.Sscanf(cl, "%d", &clen)
				if clen > 0 && clen < 65536 { // 限制 64KB
					bodyBytes := make([]byte, clen)
					n, _ := reader.Read(bodyBytes)
					if n > 0 {
						postBody = string(bodyBytes[:n])
						s.logger.Infow("http post body captured",
							"remote", remote,
							"method", method,
							"path", path,
							"content_type", headers.Get("Content-Type"),
							"body_len", n,
						)
						if s.store != nil {
							s.store.RecordPostBody(remote, path, headers.Get("Content-Type"), postBody)
						}
						if s.capturePostCallback != nil {
							s.capturePostCallback(remote, path, headers.Get("Content-Type"), postBody)
						}
					}
				}
			}
		}

		ua := headers.Get("User-Agent")
		if postBody != "" {
			s.logger.Infow("http request",
				"remote", remote,
				"method", method,
				"path", path,
				"user-agent", ua,
				"post_body_len", len(postBody),
			)
		} else {
			s.logger.Infow("http request",
				"remote", remote,
				"method", method,
				"path", path,
				"user-agent", ua,
			)
		}

		// 补录 UA 到连接记录（TCP 层记录时 UA 尚未解析）
		if s.store != nil && ua != "" {
			s.store.UpdateConnectionUA(remote, "HTTP", ua)
		}

		// 检测是否为面包屑路径 — 触碰即判定为攻击者
		breadcrumbTriggered := false

		// /api/collect 指纹采集端点 — 拦截并入库（浏览器被动指纹 + 反制载荷均通过此路径上报）
		if strings.HasPrefix(path, "/api/collect") {
			s.handleCollectFingerprint(conn, remote, path, httpVersion, ua)
			return // 采集后关闭连接（Image 信标无需 keep-alive）
		}

		if s.isBreadcrumb(path) {
			breadcrumbTriggered = true
			s.logger.Warnw("BREADCRUMB TRIGGERED - ATTACKER DETECTED",
				"remote", remote,
				"path", path,
				"user-agent", ua,
			)
			if onBreadcrumb != nil {
				onBreadcrumb(remote, path, ua)
			}
		}

		// 随机延迟 50-150ms 对抗时序分析
		time.Sleep(time.Duration(50+rand.Intn(100)) * time.Millisecond)

		resp := s.buildResponse(method, path, httpVersion, headers, breadcrumbTriggered, ua, remote)
		if _, err := conn.Write([]byte(resp)); err != nil {
			s.logger.Debugw("http write error", "remote", remote, "error", err)
			return
		}

		// HTTP/1.0 请求后关闭连接
		if strings.HasPrefix(strings.ToUpper(httpVersion), "HTTP/1.0") {
			return
		}
	}
}

// SetCountermeasureCallback 设置面包屑触发的反制 JS 注入回调
func (s *Server) SetCountermeasureCallback(fn CountermeasureCallback) {
	s.countermeasureCB = fn
}

// SetDecoyPageCallback 设置诱饵页面回调（如冰蝎 JSP、Cobalt Strike 反制页面）
func (s *Server) SetDecoyPageCallback(fn DecoyPageCallback) {
	s.decoyPageCB = fn
}

// SetCapturePostCallback 设置 POST 请求体捕获回调
func (s *Server) SetCapturePostCallback(fn CapturePostCallback) {
	s.capturePostCallback = fn
}

// handleCollectFingerprint 处理浏览器指纹采集请求。
// 浏览器被动指纹 JS 和反制载荷均通过 new Image().src='/api/collect?d=...' 上报，
// 该请求发往 HTTP 蜜罐端口而非 API 服务器端口，因此需要在蜜罐层拦截并入库。
func (s *Server) handleCollectFingerprint(conn net.Conn, remote, path, _, ua string) {
	// 解析查询参数 ?d=<url-encoded-json>
	qIdx := strings.Index(path, "?")
	if qIdx < 0 {
		return
	}
	query := path[qIdx+1:]
	// 提取 d= 参数
	rawData := ""
	for _, pair := range strings.Split(query, "&") {
		kv := strings.SplitN(pair, "=", 2)
		if len(kv) == 2 && kv[0] == "d" {
			rawData = kv[1]
			break
		}
	}
	if rawData == "" {
		return
	}

	// URL 解码 — JS 端使用 encodeURIComponent 编码，必须解码后才能正确入库
	decoded, err := url.QueryUnescape(rawData)
	if err != nil {
		decoded = rawData // 解码失败保留原始数据
	}

	host, _, _ := net.SplitHostPort(remote)

	// 尝试从 JSON 数据中提取追踪 ID（反制载荷会带 tid 字段）
	trackingID := ""
	var fpData map[string]interface{}
	if json.Unmarshal([]byte(decoded), &fpData) == nil {
		if tid, ok := fpData["tid"].(string); ok && tid != "" {
			trackingID = tid
		}
	}
	if trackingID == "" {
		trackingID = "hp-" + fmt.Sprintf("%x", time.Now().UnixNano())[:8]
	}

	if s.store != nil {
		s.store.RecordFingerprint(trackingID, host, ua, decoded)
		s.logger.Infow("fingerprint collected via honeypot",
			"remote", remote,
			"tracking_id", trackingID,
			"data_len", len(decoded),
		)
	}

	// 返回 1x1 透明 GIF（模拟 /api/collect 在 API 服务器的行为）
	transparentGIF := []byte{
		'G', 'I', 'F', '8', '9', 'a', // GIF89a
		0x01, 0x00, 0x01, 0x00, 0x80, 0x01, 0x00, // width=1 height=1
		0x00, 0x00, 0x00, // transparent bg
		0x21, 0xf9, 0x04, 0x01, 0x00, 0x00, 0x00, 0x00, // Graphic Control Extension
		0x2c, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, // Image Descriptor
		0x02, 0x02, 0x4c, 0x01, 0x00, // Image Data
		0x3b, // Trailer
	}

	now := time.Now().UTC()
	resp := fmt.Sprintf(
		"HTTP/1.1 200 OK\r\n"+
			"Date: %s\r\n"+
			"Server: nginx/1.24.0\r\n"+
			"Content-Type: image/gif\r\n"+
			"Content-Length: %d\r\n"+
			"Cache-Control: no-cache, no-store, must-revalidate\r\n"+
			"Pragma: no-cache\r\n"+
			"Expires: 0\r\n"+
			"Set-Cookie: _hp_track=%s; Path=/; Max-Age=31536000; SameSite=Lax\r\n"+
			"\r\n",
		now.Format("Mon, 02 Jan 2006 15:04:05 GMT"),
		len(transparentGIF),
		trackingID,
	)
	conn.Write([]byte(resp))
	conn.Write(transparentGIF)
}

// SetCustomTemplates 设置 YAML 自定义响应模板
func (s *Server) SetCustomTemplates(templates []CustomTemplate) {
	s.customTemplates = templates
	for _, t := range templates {
		if t.IsBreadcrumb {
			s.breadcrumbs = append(s.breadcrumbs, t.Path)
		}
	}
}

// matchCustomTemplate 匹配自定义模板，返回模板和是否匹配
func (s *Server) matchCustomTemplate(path string) *CustomTemplate {
	for i := range s.customTemplates {
		t := &s.customTemplates[i]
		if strings.HasPrefix(path, t.Path) {
			return t
		}
	}
	return nil
}

func (s *Server) isBreadcrumb(path string) bool {
	for _, bc := range s.breadcrumbs {
		if strings.HasPrefix(path, bc) {
			return true
		}
	}
	return false
}

func (s *Server) buildResponse(method, path, httpVersion string, headers textproto.MIMEHeader, breadcrumbTriggered bool, ua, remote string) string {
	status := 200
	statusText := "OK"
	contentType := "text/html; charset=utf-8"
	body := s.renderPage(path)
	isDirListing := false

	// 自定义模板优先匹配（YAML 配置驱动）
	if tmpl := s.matchCustomTemplate(path); tmpl != nil {
		status = tmpl.Status
		if tmpl.ContentType != "" {
			contentType = tmpl.ContentType
		}
		body = tmpl.Body
		goto buildHeaders
	}

	if strings.Contains(path, "admin") || strings.Contains(path, "login") {
		if method == "POST" {
			contentType = "application/json"
			body = `{"error":"invalid_credentials","message":"Authentication failed. Please check your username and password.","code":"AUTH_FAILED","request_id":"` + fmt.Sprintf("%x", time.Now().UnixNano()) + `"}`
			status = 401
			statusText = "Unauthorized"
		} else {
			body = s.loginPage()
		}
	} else if strings.Contains(path, ".jsp") || strings.Contains(path, ".do") {
		// JSP/Java 端点 — 返回冰蝎反制诱饵（通过回调获取）
		if s.decoyPageCB != nil {
			body = s.decoyPageCB("behinder", path)
		} else {
			body = s.defaultJSPPage()
		}
	} else if strings.Contains(path, ".php") || strings.Contains(path, "wp-") {
		status = 404
		statusText = "Not Found"
		body = s.errorPage(404)
	} else if strings.Contains(path, "actuator") {
		// Spring Boot Actuator 未授权访问 — 返回真实 actuator JSON
		contentType = "application/vnd.spring-boot.actuator.v3+json"
		if strings.Contains(path, "heapdump") {
			contentType = "application/octet-stream"
			body = s.fakeHeapDump()
		} else {
			body = s.fakeActuatorResponse(path)
		}
	} else if strings.Contains(path, "swagger-ui") {
		// Swagger UI 页面 — HTML
		body = s.swaggerUIPage()
	} else if strings.Contains(path, "api-docs") || strings.Contains(path, "swagger-resources") {
		// Swagger API 文档 — JSON
		contentType = "application/json"
		body = s.fakeSwaggerDocs(path)
	} else if (strings.Contains(path, "api") && !strings.HasPrefix(path, "/api/collect")) || strings.Contains(path, "swagger") {
		contentType = "application/json"
		body = s.fakeAPIResponse(path)
	} else if strings.Contains(path, ".git") || strings.Contains(path, "backup") || strings.Contains(path, ".sql") {
		status = 403
		statusText = "Forbidden"
		body = s.fakeDirListing(path)
		isDirListing = true
	}

	// 面包屑触发的反制 JS 注入（在 Content-Length 计算前，确保 HTTP 兼容）
buildHeaders:
	if breadcrumbTriggered && s.countermeasureCB != nil && strings.HasPrefix(contentType, "text/html") {
		host, _, _ := net.SplitHostPort(remote)
		counterJS := s.countermeasureCB(path, ua, host)
		if idx := strings.LastIndex(body, "</body>"); idx > 0 {
			body = body[:idx] + counterJS + body[idx:]
		}
		// 记录反制事件到持久化存储
		if s.store != nil && len(counterJS) > 0 {
			payloadType := detectPayloadType(counterJS)
			preview := counterJS
			if len(preview) > 200 {
				preview = preview[:200] + "..."
			}
			s.store.RecordCountermeasure(host, path, payloadType, preview, ua, 0)
		}
	}

	bodyBytes := []byte(body)
	contentLen := len(bodyBytes)

	connHdr := "keep-alive"
	if strings.HasPrefix(strings.ToUpper(httpVersion), "HTTP/1.0") {
		connHdr = "close"
	}

	now := time.Now().UTC()
	dateStr := now.Format("Mon, 02 Jan 2006 15:04:05 GMT")
	lastMod := now.Add(-24 * time.Hour).Format("Mon, 02 Jan 2006 15:04:05 GMT")
	etag := fmt.Sprintf(`"%x-%x"`, now.Unix(), contentLen)

	var resp string
	resp = fmt.Sprintf(
		"%s %d %s\r\n"+
			"Date: %s\r\n"+
			"Server: nginx/1.24.0\r\n"+
			"Content-Type: %s\r\n"+
			"Content-Length: %d\r\n"+
			"Connection: %s\r\n"+
			"ETag: %s\r\n"+
			"Last-Modified: %s\r\n"+
			"X-Frame-Options: SAMEORIGIN\r\n"+
			"X-Content-Type-Options: nosniff\r\n"+
			"Vary: Accept-Encoding\r\n"+
			"X-Powered-By: PHP/8.1\r\n"+
			"Set-Cookie: PHPSESSID=%s; path=/\r\n",
		httpVersion, status, statusText,
		dateStr,
		contentType,
		contentLen,
		connHdr,
		etag,
		lastMod,
		s.fakeSessionID(),
	)

	// heapdump 下载: 添加 Content-Disposition 等头
	if strings.Contains(path, "heapdump") {
		for k, v := range s.heapDumpExtraHeaders() {
			resp += fmt.Sprintf("%s: %s\r\n", k, v)
		}
	} else {
		resp += fmt.Sprintf("Cache-Control: no-cache\r\n" +
			"Pragma: no-cache\r\n")
	}

	// 目录列表页加上额外的 headers（Apache 风格）
	if isDirListing {
		resp += fmt.Sprintf("Accept-Ranges: bytes\r\n")
	}

	resp += "\r\n"

	// HEAD 请求不发送 body
	if method != "HEAD" {
		resp += body
	}

	return resp
}

func (s *Server) renderPage(path string) string {
	// 主页嵌入面包屑（HTML 注释中隐藏敏感路径）
	breadcrumbLinks := ""
	for _, bc := range s.breadcrumbs {
		breadcrumbLinks += fmt.Sprintf("  <!-- <a href=\"%s\">Internal</a> -->\n", bc)
	}

	return fmt.Sprintf(`<!DOCTYPE html>
<html>
<head><title>Welcome | Laji-HoneyPot</title>
<meta name="generator" content="WordPress 6.4.3" />
%s
<script>%s</script>
</head>
<body>
<h1>Welcome to Nginx</h1>
<p>Path: %s</p>
%s
<script>%s</script>
</body>
</html>`, s.fakeRobotsTxt(), s.fingerprintJS, path, breadcrumbLinks, s.fingerprintJS)
}

// fakeRobotsTxt 在页面中嵌入伪装的 robots.txt 链接，包含面包屑路径
func (s *Server) fakeRobotsTxt() string {
	paths := strings.Join(s.breadcrumbs[:5], "\n")
	return fmt.Sprintf("<!--\nUser-agent: *\nDisallow: %s\n-->", strings.ReplaceAll(paths, "\n", "\nDisallow: "))
}

func (s *Server) loginPage() string {
	return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Sign In | Enterprise Management Console</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#f0f2f5;display:flex;justify-content:center;align-items:center;min-height:100vh}
.login-box{background:#fff;padding:40px;border-radius:8px;box-shadow:0 2px 12px rgba(0,0,0,0.1);width:380px;max-width:90%}
.login-box h2{text-align:center;color:#1a1a2e;margin-bottom:8px;font-size:22px}
.login-box .subtitle{text-align:center;color:#666;font-size:13px;margin-bottom:24px}
.form-group{margin-bottom:16px}
.form-group label{display:block;font-size:13px;color:#333;margin-bottom:6px;font-weight:500}
.form-group input{width:100%;padding:10px 12px;border:1px solid #d9d9d9;border-radius:4px;font-size:14px;transition:border-color .3s}
.form-group input:focus{border-color:#1890ff;outline:none;box-shadow:0 0 0 2px rgba(24,144,255,.2)}
.btn-login{width:100%;padding:10px;background:#1890ff;color:#fff;border:none;border-radius:4px;font-size:15px;font-weight:500;cursor:pointer;transition:background .3s}
.btn-login:hover{background:#40a9ff}
.login-footer{text-align:center;margin-top:20px;font-size:12px;color:#999}
.login-footer a{color:#1890ff;text-decoration:none}
.error-msg{background:#fff2f0;border:1px solid #ffccc7;color:#cf1322;padding:8px 12px;border-radius:4px;font-size:13px;margin-bottom:16px;display:none}
</style>
</head>
<body>
<div class="login-box">
<h2>Enterprise Console</h2>
<p class="subtitle">Internal Management System v3.2.1</p>
<div class="error-msg" id="error">Invalid credentials. Please try again.</div>
<form method="POST" action="/admin/login" onsubmit="return handleLogin()">
<div class="form-group"><label>Username</label><input type="text" name="username" placeholder="admin" autocomplete="off" /></div>
<div class="form-group"><label>Password</label><input type="password" name="password" placeholder="········" /></div>
<button type="submit" class="btn-login">Sign In</button>
</form>
<div class="login-footer">Forgot password? Contact <a href="mailto:ops@internal.local">IT Support</a><br>&copy; 2024 Internal Systems. All rights reserved.</div>
</div>
<script>
function handleLogin(){var e=document.getElementById("error");e.style.display="block";return false}
</script>
</body>
</html>`
}

func (s *Server) fakeAPIResponse(path string) string {
	return fmt.Sprintf(`{"status":"ok","path":"%s","version":"2.0.1","timestamp":"%s","internal_ip":"10.0.1.100"}`, path, time.Now().Format(time.RFC3339))
}

// fakeActuatorResponse 伪造 Spring Boot Actuator 未授权访问响应
// 根据路径返回不同的 actuator 端点数据，诱导攻击者探测更多信息
func (s *Server) fakeActuatorResponse(path string) string {
	t := time.Now().UTC().Format(time.RFC3339)

	switch {
	case strings.Contains(path, "env") || strings.Contains(path, "environment"):
		return fmt.Sprintf(`{
  "activeProfiles": ["prod"],
  "propertySources": [
    {"name": "server.ports", "properties": {"local.server.port": {"value": "8080","origin": "class path resource [application-prod.yml]"}}},
    {"name": "applicationConfig: [classpath:/application-prod.yml]", "properties": {
      "spring.datasource.url": {"value": "jdbc:mysql://10.0.1.50:3306/prod_db?useSSL=false","origin": "class path resource [application-prod.yml]"},
      "spring.datasource.username": {"value": "root","origin": "class path resource [application-prod.yml]"},
      "spring.datasource.password": {"value": "********","origin": "class path resource [application-prod.yml]"},
      "spring.redis.host": {"value": "10.0.1.60","origin": "class path resource [application-prod.yml]"},
      "spring.redis.password": {"value": "********","origin": "class path resource [application-prod.yml]"},
      "jwt.secret": {"value": "prod-jwt-secret-key-2024","origin": "class path resource [application-prod.yml]"},
      "cloud.aws.credentials.accessKey": {"value": "AKIAIOSFODNN7EXAMPLE","origin": "class path resource [application-prod.yml]"},
      "cloud.aws.credentials.secretKey": {"value": "********","origin": "class path resource [application-prod.yml]"},
      "management.endpoints.web.exposure.include": {"value": "*","origin": "class path resource [application-prod.yml]"},
      "server.error.include-stacktrace": {"value": "always","origin": "class path resource [application-prod.yml]"}
    }}
  ],
  "timestamp": "%s"
}`, t)

	case strings.Contains(path, "mappings"):
		return fmt.Sprintf(`{
  "contexts": {
    "application": {
      "mappings": {
        "dispatcherServlets": {
          "dispatcherServlet": [
            {"handler": "org.springframework.boot.actuate.endpoint.web.servlet.AbstractWebMvcEndpointHandlerMapping$OperationHandler","predicate": "{GET [/actuator/env], produces [application/vnd.spring-boot.actuator.v3+json]}"},
            {"handler": "org.springframework.boot.actuate.endpoint.web.servlet.AbstractWebMvcEndpointHandlerMapping$OperationHandler","predicate": "{GET [/actuator/heapdump], produces [application/octet-stream]}"},
            {"handler": "org.springframework.boot.actuate.endpoint.web.servlet.AbstractWebMvcEndpointHandlerMapping$OperationHandler","predicate": "{GET [/actuator/mappings], produces [application/vnd.spring-boot.actuator.v3+json]}"},
            {"handler": "com.example.internal.AdminController#deleteUser(Long)","predicate": "{POST [/api/internal/admin/users/delete]}"},
            {"handler": "com.example.internal.DataController#exportAll()","predicate": "{GET [/api/internal/data/export]}"},
            {"handler": "com.example.internal.ConfigController#getSecrets()","predicate": "{GET [/api/internal/config/secrets]}"},
            {"handler": "com.example.controller.UserController#login(UserDto)","predicate": "{POST [/api/v1/user/login]}"},
            {"handler": "com.example.controller.OrderController#list()","predicate": "{GET [/api/v1/orders]}"}
          ]
        },
        "servletFilters": [
          {"name": "securityFilterChain","class": "org.springframework.security.web.FilterChainProxy"},
          {"name": "requestContextFilter","class": "org.springframework.web.filter.RequestContextFilter"}
        ],
        "parentId": null
      }
    }
  },
  "timestamp": "%s"
}`, t)

	case strings.Contains(path, "beans"):
		return fmt.Sprintf(`{
  "contexts": {
    "application": {
      "beans": {
        "dataSource": {"aliases": [],"scope": "singleton","type": "com.zaxxer.hikari.HikariDataSource","resource": "class path resource [org/springframework/boot/autoconfigure/jdbc/DataSourceConfiguration$Hikari.class]","dependencies": ["dataSourceProperties"]},
        "jwtTokenProvider": {"aliases": [],"scope": "singleton","type": "com.example.internal.security.JwtTokenProvider","resource": "file [/app/classes/com/example/internal/security/JwtTokenProvider.class]","dependencies": ["jwtProperties","userDetailsServiceImpl"]},
        "redisTemplate": {"aliases": [],"scope": "singleton","type": "org.springframework.data.redis.core.RedisTemplate","resource": "class path resource [org/springframework/boot/autoconfigure/data/redis/RedisAutoConfiguration.class]","dependencies": ["redisConnectionFactory"]},
        "adminUserController": {"aliases": [],"scope": "singleton","type": "com.example.internal.AdminController","resource": "file [/app/classes/com/example/internal/AdminController.class]","dependencies": ["userRepository","auditLogger"]}
      },
      "parentId": null
    }
  },
  "timestamp": "%s"
}`, t)

	case strings.Contains(path, "configprops"):
		return fmt.Sprintf(`{
  "contexts": {
    "application": {
      "beans": {
        "spring.datasource-org.springframework.boot.autoconfigure.jdbc.DataSourceProperties": {
          "prefix": "spring.datasource","properties": {
            "url": "jdbc:mysql://10.0.1.50:3306/prod_db?useSSL=false",
            "username": "root",
            "password": "******",
            "driverClassName": "com.mysql.cj.jdbc.Driver",
            "hikari": {"maximumPoolSize": 50,"minimumIdle": 10,"connectionTimeout": 30000,"maxLifetime": 1800000}
          }
        },
        "spring.redis-org.springframework.boot.autoconfigure.data.redis.RedisProperties": {
          "prefix": "spring.redis","properties": {
            "host": "10.0.1.60","port": 6379,"password": "******","database": 0,"timeout": 3000
          }
        }
      },
      "parentId": null
    }
  }
}`)
	}

	return fmt.Sprintf(`{"_links":{"self":{"href":"http://localhost:8080/actuator","templated":false},"env":{"href":"http://localhost:8080/actuator/env","templated":false},"env-toMatch":{"href":"http://localhost:8080/actuator/env/{toMatch}","templated":true},"heapdump":{"href":"http://localhost:8080/actuator/heapdump","templated":false},"mappings":{"href":"http://localhost:8080/actuator/mappings","templated":false},"beans":{"href":"http://localhost:8080/actuator/beans","templated":false},"configprops":{"href":"http://localhost:8080/actuator/configprops","templated":false}}}`)
}

// fakeHeapDump 伪造一个假的 JVM heap dump 文件，内含丰富诱饵数据
//
// 反制链设计：
//
//	攻击者访问 /actuator/heapdump  →  触发面包屑（记录攻击事件）
//	→  下载 heapdump.hprof 文件  →  用 MAT/VisualVM 分析
//	→  发现堆中的"敏感凭证"  →  尝试 SSH/MySQL/Redis 登录
//	→  触碰其他蜜罐服务  →  全部被记录追踪
//
// HPROF 格式: header + 多条 STRING record (tag=0x01)，每条包含不同类别的蜜标
func (s *Server) fakeHeapDump() string {
	// ========== HPROF Header ==========
	// "JAVA PROFILE 1.0.2\0" + 4 bytes ID size + 8 bytes timestamp
	hprofHeader := []byte("JAVA PROFILE 1.0.2")
	hprofHeader = append(hprofHeader, 0)          // null terminator
	hprofHeader = append(hprofHeader, 0, 0, 0, 4) // ID size = 4
	ts := time.Now().UnixMilli()
	hprofHeader = append(hprofHeader,
		byte(ts>>56), byte(ts>>48), byte(ts>>40), byte(ts>>32),
		byte(ts>>24), byte(ts>>16), byte(ts>>8), byte(ts),
	)

	// ========== 蜜标字符串数据（模拟 JVM 堆中的对象） ==========
	// 每条 STRING record: tag(1) + time(4) + id(4) + utf8data
	// 使用递增的 string ID，模拟真实堆中字符串常量池

	baitStrings := []struct {
		id   int
		data string
	}{
		// 1. 数据库连接池配置 (HikariCP DataSource)
		{1, "HikariPool-1 - Starting... jdbc:mysql://10.0.1.50:3306/prod_db?useSSL=false&serverTimezone=UTC"},
		{2, "HikariCP - connectionTimeout=30000, maximumPoolSize=50, username=root, password=SpringBoot@Prod2024!"},

		// 2. Redis 连接配置 (Lettuce/Jedis)
		{3, "LettuceConnectionFactory - RedisURI redis://:Redis@Internal2024@10.0.1.60:6379/0"},
		{4, "RedisConfig - master=redis-master.internal.local, sentinel=10.0.1.61:26379"},

		// 3. SSH 服务配置 — 攻击者获取后可能尝试 SSH 登录，触发 SSH 蜜罐
		{5, "SshExecCommand - ssh -p 2222 deploy@10.0.1.70 -i /home/deploy/.ssh/id_rsa"},
		{6, "ServerConfig - prod-server-01 (10.0.1.70:2222) user:deploy key:/home/deploy/.ssh/deploy_key"},

		// 4. SSH 私钥片段 — 模拟对象中残留的密钥数据
		{7, `-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
NhAAAAAwEAAQAAAYEA0Z3MzFzK1Qx5kG2V7N0cKjFzrH8qPQr1W9dAeBb1R2jUvK9tF0sW
x8qLmN4oP5rS7tU9vW0xYzA1Q2sD4fG6hJ7kL8mN0oP0qR4sT5uV6wW7xX8yY0zA1B2cC3
-----END OPENSSH PRIVATE KEY-----`},

		// 5. AWS S3 凭证 — 诱导攻击者访问伪造的 S3 端点
		{8, "DefaultAWSCredentialsProviderChain - AccessKeyId=AKIAIOSFODNN7EXAMPLE, SecretKey=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY, Region=us-east-1"},
		{9, "S3Client - bucket=prod-uploads-bucket, endpoint=https://s3.us-east-1.amazonaws.com"},

		// 6. JWT 签名密钥 — 攻击者可伪造 JWT Token
		{10, "JwtTokenProvider - secret=prod-jwt-secret-key-2024-hp-hmac-sha256, expiration=86400000ms, issuer=internal-auth-service"},
		{11, "AuthToken - Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJST0xFX0FETUlOIiwiaWF0IjoxNzE5MDAwMDAwfQ.hp_fake_signature"},

		// 7. 内部 API 端点 — 诱导攻击者探测内网
		{12, "RestTemplate - GET http://10.0.1.80:8080/api/internal/admin/users?apiKey=internal-api-key-2024"},
		{13, "FeignClient - InventoryService http://inventory.internal.local:8080/api/v2/stock"},
		{14, "WebClient - POST http://10.0.1.90:8080/api/internal/data/sync"},

		// 8. Kubernetes/容器配置
		{15, "KubeConfig - server: https://10.0.1.100:6443, namespace: production, token: k8s-token-hp-eyJhbGciOiJSUzI1NiJ9..."},
		{16, "DockerRegistry - registry.internal.local:5000, user: ci-bot, pass: Docker@Registry2024"},

		// 9. 日志中的敏感信息
		{17, "ERROR - Failed to rotate secret for service=payment-gateway, key=sk-live-payment-hp-a1b2c3d4e5f6g7h8"},
		{18, "INFO - LDAP bind success: ldap://10.0.1.110:3890/dc=internal,dc=local cn=admin,dc=internal,dc=local"},
	}

	records := make([]byte, 0)
	for _, bs := range baitStrings {
		data := []byte(bs.data)
		// STRING record: tag(1) + time(4) + id(4) + data
		rec := make([]byte, 1+4+4+len(data))
		rec[0] = 0x01 // STRING tag
		// time: use current timestamp (4 bytes: seconds since epoch)
		sec := uint32(time.Now().Unix())
		rec[1] = byte(sec >> 24)
		rec[2] = byte(sec >> 16)
		rec[3] = byte(sec >> 8)
		rec[4] = byte(sec)
		// string ID
		rec[5] = byte(bs.id >> 24)
		rec[6] = byte(bs.id >> 16)
		rec[7] = byte(bs.id >> 8)
		rec[8] = byte(bs.id)
		copy(rec[9:], data)
		records = append(records, rec...)
	}

	return string(append(hprofHeader, records...))
}

// heapDumpFileName 返回 heapdump 下载文件名
func (s *Server) heapDumpFileName() string {
	return fmt.Sprintf("heapdump-%s.hprof", time.Now().Format("20060102-150405"))
}

// buildHeapDumpExtraHeaders 构建 heapdump 下载所需的额外 HTTP 头
func (s *Server) heapDumpExtraHeaders() map[string]string {
	return map[string]string{
		"Content-Disposition":       fmt.Sprintf("attachment; filename=\"%s\"", s.heapDumpFileName()),
		"Content-Transfer-Encoding": "binary",
		"Cache-Control":             "no-store, must-revalidate",
		"Pragma":                    "no-cache",
		"Expires":                   "0",
	}
}

// swaggerUIPage 伪造 Swagger UI 页面，未授权即可浏览 API
func (s *Server) swaggerUIPage() string {
	return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Swagger UI</title>
  <link rel="stylesheet" type="text/css" href="./swagger-ui.css">
  <link rel="icon" type="image/png" href="./favicon-32x32.png" sizes="32x32">
  <style>html{box-sizing:border-box;overflow:-moz-scrollbars-vertical;overflow-y:scroll}*,:after,:before{box-sizing:inherit}body{margin:0;background:#fafafa}</style>
</head>
<body>
  <div id="swagger-ui">
    <div class="swagger-ui">
      <div class="topbar">
        <div class="wrapper">
          <div class="topbar-wrapper">
            <span>Select a spec: </span>
            <select id="select">
              <option value="/v2/api-docs">Default (v2/api-docs)</option>
              <option value="/v2/api-docs?group=internal">Internal API (v2/api-docs?group=internal)</option>
              <option value="/v2/api-docs?group=admin">Admin API (v2/api-docs?group=admin)</option>
            </select>
          </div>
        </div>
      </div>
      <div id="api-doc-container">
        <div class="info">
          <hgroup class="main">
            <h2 class="title">Internal API Documentation
              <span><a href="#/"><span class="version">v2.1.0</span></a></span>
            </h2>
          </hgroup>
          <div class="description"><p>REST API for internal microservices. Authentication: Bearer token (JWT) or API Key.<br/>
          <strong>Default access: all endpoints require <code>Authorization</code> header.</strong></p></div>
        </div>
      </div>
    </div>
  </div>
  <script>
    // Swagger UI bootstrap — 加载真实 API 文档
    window.onload = function() {
      fetch('/swagger-resources')
        .then(function(r) { return r.json() })
        .then(function(data) {
          if (data && data.length) {
            var url = data[0].url || '/v2/api-docs';
            fetch(url).then(function(r) { return r.json() }).then(function(sw) {
              var pre = document.createElement('pre');
              pre.style.cssText = 'margin:20px;background:#f4f4f4;padding:15px;border-radius:4px;font-size:13px';
              pre.textContent = JSON.stringify(sw, null, 2);
              document.getElementById('api-doc-container').appendChild(pre);
            });
          }
        });
    };
  </script>
</body>
</html>`
}

// fakeSwaggerDocs 伪造 Swagger/OpenAPI 文档，泄露内网 API 端点
func (s *Server) fakeSwaggerDocs(path string) string {
	if strings.Contains(path, "swagger-resources") {
		return `[{"name":"default","url":"/v2/api-docs","swaggerVersion":"2.0","location":"/v2/api-docs"},{"name":"internal","url":"/v2/api-docs?group=internal","swaggerVersion":"2.0","location":"/v2/api-docs?group=internal"},{"name":"admin","url":"/v2/api-docs?group=admin","swaggerVersion":"2.0","location":"/v2/api-docs?group=admin"}]`
	}

	return fmt.Sprintf(`{
  "swagger": "2.0",
  "info": {"title": "Internal Service API","version": "2.1.0","description": "Backend microservice API documentation"},
  "host": "localhost:8080","basePath": "/","schemes": ["http","https"],
  "securityDefinitions": {
    "BearerAuth": {"type": "apiKey","name": "Authorization","in": "header","description": "JWT Bearer token: Bearer <token>"},
    "ApiKeyAuth": {"type": "apiKey","name": "X-API-Key","in": "header","description": "API Key for service-to-service calls"}
  },
  "paths": {
    "/api/v1/user/login": {
      "post": {
        "tags": ["User"],"summary": "User login","produces": ["application/json"],
        "parameters": [
          {"in": "body","name": "body","schema": {"$ref": "#/definitions/LoginRequest"}}
        ],
        "responses": {
          "200": {"description": "Login success","schema": {"$ref": "#/definitions/LoginResponse"}},
          "401": {"description": "Invalid credentials"}
        }
      }
    },
    "/api/v1/orders": {
      "get": {
        "tags": ["Order"],"summary": "List all orders","security": [{"BearerAuth": []},{"ApiKeyAuth": []}],
        "produces": ["application/json"],
        "responses": {"200": {"description": "Order list","schema": {"type": "array","items": {"$ref": "#/definitions/Order"}}}}
      }
    },
    "/api/internal/admin/users": {
      "get": {
        "tags": ["Admin"],"summary": "List all users (internal)","security": [{"ApiKeyAuth": []}],
        "produces": ["application/json"],
        "responses": {"200": {"description": "User list"}}
      }
    },
    "/api/internal/admin/users/delete": {
      "post": {
        "tags": ["Admin"],"summary": "Delete user by ID (internal)","security": [{"ApiKeyAuth": []}],
        "parameters": [{"in": "query","name": "id","type": "integer","required": true}],
        "responses": {"200": {"description": "User deleted"}}
      }
    },
    "/api/internal/data/export": {
      "get": {
        "tags": ["Data"],"summary": "Export all data (internal)","security": [{"ApiKeyAuth": []}],
        "produces": ["application/octet-stream"],
        "responses": {"200": {"description": "Data export file"}}
      }
    },
    "/api/internal/config/secrets": {
      "get": {
        "tags": ["Config"],"summary": "Get internal secrets (internal)","security": [{"ApiKeyAuth": []}],
        "responses": {"200": {"description": "Secrets configuration"}}
      }
    }
  },
  "definitions": {
    "LoginRequest": {
      "type": "object","required": ["username","password"],
      "properties": {
        "username": {"type": "string","example": "admin"},
        "password": {"type": "string","example": "P@ssw0rd"}
      }
    },
    "LoginResponse": {
      "type": "object",
      "properties": {
        "token": {"type": "string","example": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."},
        "refreshToken": {"type": "string","example": "dGhpcyBpcyBhIGZha2UgcmVmcmVzaCB0b2tlbg=="},
        "expiresIn": {"type": "integer","example": 3600}
      }
    },
    "Order": {
      "type": "object",
      "properties": {
        "id": {"type": "integer"},"userId": {"type": "integer"},"amount": {"type": "number"},"status": {"type": "string"}
      }
    }
  },
  "timestamp": "%s"
}`, time.Now().UTC().Format(time.RFC3339))
}

func (s *Server) errorPage(code int) string {
	return fmt.Sprintf(`<!DOCTYPE html>
<html>
<head><title>%d | nginx/1.24.0</title></head>
<body><h1>%d Not Found</h1><hr><address>nginx/1.24.0</address></body>
</html>`, code, code)
}

func (s *Server) fakeDirListing(path string) string {
	now := time.Now()
	files := []struct {
		name string
		size string
		date string
	}{
		{"..", "-", ""},
		{"database.sql", "2.3M", now.Add(-72 * time.Hour).Format("2006-01-02 15:04")},
		{"config.php", "4.2K", now.Add(-240 * time.Hour).Format("2006-01-02 15:04")},
		{"backup.tar.gz", "15M", now.Add(-48 * time.Hour).Format("2006-01-02 15:04")},
		{"error.log", "128K", now.Add(-2 * time.Hour).Format("2006-01-02 15:04")},
		{"access.log", "1.1M", now.Add(-1 * time.Hour).Format("2006-01-02 15:04")},
		{".htaccess", "1.2K", now.Add(-720 * time.Hour).Format("2006-01-02 15:04")},
	}
	var rows string
	for _, f := range files {
		link := f.name
		if f.name != ".." {
			link = fmt.Sprintf(`<a href="%s">%s</a>`, f.name, f.name)
		}
		align := ""
		if f.name != ".." {
			align = ` align="right"`
		}
		rows += fmt.Sprintf("<tr><td valign=\"top\">%s</td><td%s>%s</td><td%s>&nbsp;&nbsp;%s</td></tr>\n",
			link, align, f.date, align, f.size)
	}
	return fmt.Sprintf(`<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">
<html>
<head><title>Index of %s</title></head>
<body>
<h1>Index of %s</h1>
<table>
<tr><th valign="top">Name</th><th valign="top">Last modified</th><th valign="top">Size</th></tr>
<tr><th colspan="3"><hr></th></tr>
%s
<tr><th colspan="3"><hr></th></tr>
</table>
<address>Apache/2.4.57 (Ubuntu) Server at localhost Port 80</address>
</body>
</html>`, path, path, rows)
}

func (s *Server) fakeSessionID() string {
	return "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6"
}

// defaultJSPPage 默认 JSP 诱饵页面 — 模拟 Tomcat/JSP 运行环境
func (s *Server) defaultJSPPage() string {
	return `<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<%@ page import="java.util.*,java.net.*" %>
<%
  String hostname = "unknown";
  String osName = System.getProperty("os.name", "Linux");
  String userName = System.getProperty("user.name", "tomcat");
  try { hostname = InetAddress.getLocalHost().getHostName(); } catch(Exception e) {}
%>
<html>
<head><title>Apache Tomcat/9.0.80 - JSP Test</title></head>
<body>
<h1>JSP Test Page</h1>
<p>Server: <%= hostname %></p>
<p>OS: <%= osName %></p>
<p>User: <%= userName %></p>
<p>Time: <%= new Date() %></p>
</body>
</html>`
}

// buildFingerprintJS 生成浏览器被动指纹采集代码（全维度增强版）
// 安全设计：全部被动采集，无 eval、无弹窗、无自动下载，try/catch 全包裹
// 采集维度：Canvas/WebGL/音频/屏幕/时区/语言/插件/设备/网络/触屏/字体/Math/行为追踪/公网IP
func buildFingerprintJS() string {
	return `(function(){
var d={},t0=Date.now();

// ---- 行为追踪：跨页面 sessionStorage 持久化 ----
try{
  var hp=sessionStorage.getItem('_hp_v');
  if(hp){var v=JSON.parse(hp);d.visits=v.n+1;d.first=v.f;d.prev=v.p;d.stay=Date.now()-v.ts;v.n++;v.p=location.pathname;v.ts=Date.now();sessionStorage.setItem('_hp_v',JSON.stringify(v))}
  else{var s={n:1,f:Date.now(),p:location.pathname,ts:Date.now()};sessionStorage.setItem('_hp_v',JSON.stringify(s));d.visits=1;d.first=Date.now()}
}catch(e){}

// ---- 浏览器基础属性 ----
d.ua=navigator.userAgent;d.plat=navigator.platform;d.ven=navigator.vendor||'';d.venSub=navigator.vendorSub||'';

// ---- Canvas 指纹 ----
try{var c=document.createElement('canvas');c.width=280;c.height=60;var x=c.getContext('2d');x.textBaseline='top';x.font='14px Arial';x.fillStyle='#f60';x.fillRect(125,1,62,20);x.fillStyle='#069';x.fillText('HoneyPot',2,15);x.fillStyle='rgba(102,204,0,0.7)';x.fillText('HoneyPot',4,17);d.canvas=c.toDataURL().substring(0,128)}catch(e){d.canvas='err'}

// ---- WebGL GPU 指纹（含扩展列表与像素精度） ----
try{var gl=document.createElement('canvas').getContext('webgl')||document.createElement('canvas').getContext('experimental-webgl');if(gl){d.wgl_vendor=gl.getParameter(gl.VENDOR);d.wgl_renderer=gl.getParameter(gl.RENDERER);var ext=gl.getSupportedExtensions();if(ext)d.wgl_ext=ext.slice(0,30).join(',');var dbg=gl.getExtension('WEBGL_debug_renderer_info');if(dbg){d.wgl_umvendor=gl.getParameter(dbg.UNMASKED_VENDOR_WEBGL);d.wgl_umrenderer=gl.getParameter(dbg.UNMASKED_RENDERER_WEBGL)}var m=16,tile=new Uint8Array(m*4),pxl=new Uint32Array(tile.buffer),ps='';for(var i=0;i<m;i++)pxl[i]=Math.floor(Math.random()*0xFFFFFFFF);gl.readPixels(0,0,4,4,gl.RGBA,gl.UNSIGNED_BYTE,tile);for(var i=0;i<32;i++)ps+=tile[i].toString(16);d.wgl_pixel=ps}}catch(e){}

// ---- 屏幕信息 ----
d.scr=screen.width+'x'+screen.height;d.avail=screen.availWidth+'x'+screen.availHeight;d.cd=screen.colorDepth;d.pd=screen.pixelDepth;d.dpr=window.devicePixelRatio||1;

// ---- 时区与国际 ----
d.tz=Intl.DateTimeFormat().resolvedOptions().timeZone;d.lang=navigator.language;try{d.langs=navigator.languages}catch(e){d.langs=[navigator.language]}try{d.cal=new Date().toString().match(/\(([^)]+)\)/)[1]}catch(e){}

// ---- 硬件信息 ----
try{d.hc=navigator.hardwareConcurrency}catch(e){}try{d.dm=navigator.deviceMemory}catch(e){}try{d.maxTouch=navigator.maxTouchPoints||0}catch(e){}try{d.touch=('ontouchstart' in window)}catch(e){}

// ---- 网络类型 ----
try{d.conn=navigator.connection.effectiveType}catch(e){}try{d.rtt=navigator.connection.rtt}catch(e){}try{d.downlink=navigator.connection.downlink}catch(e){}

// ---- 插件枚举 ----
try{var pl=[];for(var i=0;i<navigator.plugins.length;i++)pl.push(navigator.plugins[i].name);d.plugins=pl;d.pLen=navigator.plugins.length}catch(e){}

// ---- 字体指纹（CSS测量法，无Flash依赖） ----
try{var fs=['monospace','sans-serif','serif','Arial','Courier New','Times New Roman','Verdana','Georgia','Comic Sans MS','Trebuchet MS','Impact'],fw=[56,64,72],bf='';for(var i=0;i<fs.length;i++){for(var j=0;j<fw.length;j++){var m=document.createElement('span');m.style.fontFamily=fs[i];m.style.fontSize=fw[j]+'px';m.textContent='mmmmmmmmmml';document.body.appendChild(m);bf+=m.offsetWidth+',';document.body.removeChild(m)}}d.fonts=bf.substring(0,200)}catch(e){}

// ---- Math 计算精度指纹 ----
try{d.math_pi=Math.PI.toString();d.math_e=Math.E.toString()}catch(e){}

// ---- AudioContext 指纹（OfflineAudioContext 绕过自动播放限制） ----
try{var actx=new(window.OfflineAudioContext||window.webkitOfflineAudioContext)(1,44100,44100),osc=actx.createOscillator();osc.type='triangle';osc.frequency.value=10000;var an=actx.createAnalyser(),gn=actx.createGain();gn.gain.value=0;osc.connect(an);an.connect(gn);gn.connect(actx.destination);osc.start(0);actx.startRendering().then(function(b){var s=new Float32Array(b.length),sum=0;b.copyFromChannel(s,0);for(var i=0;i<Math.min(s.length,1000);i++)sum+=Math.abs(s[i]);try{new Image().src='/api/collect?d='+encodeURIComponent(JSON.stringify({ac:Math.round(sum)}))}catch(e){}})}catch(e){}

// ---- 广告拦截器/隐私检测 ----
try{var ba=document.createElement('div');ba.className='adsbox';ba.style.cssText='position:absolute;left:-999px;width:1px;height:1px';document.body.appendChild(ba);setTimeout(function(){d.adblock=ba.offsetHeight===0;document.body.removeChild(ba)},100)}catch(e){}
d.cookie=navigator.cookieEnabled;try{d.dnt=navigator.doNotTrack||navigator.msDoNotTrack||'unspecified'}catch(e){}

// ---- 无头浏览器/自动化检测 ----
try{d.headless=navigator.webdriver?1:0}catch(e){}

// ---- 屏幕捕获/录屏检测 ----
try{d.mde=!!(navigator.mediaDevices&&navigator.mediaDevices.getDisplayMedia)?1:0}catch(e){}
try{d.mr=!!(window.MediaRecorder)}catch(e){}
try{var mst=[];if(navigator.mediaDevices&&navigator.mediaDevices.enumerateDevices){navigator.mediaDevices.enumerateDevices().then(function(dv){for(var i=0;i<dv.length;i++){if(dv[i].kind==='videoinput')mst.push(dv[i].label||dv[i].deviceId);d.vdev=mst;d.vdevCnt=dv.length}}).catch(function(){})}}catch(e){}

// ---- 移动设备检测 ----
try{d.mobile=/Mobi|Android|iPhone|iPad|iPod/i.test(navigator.userAgent)?1:0}catch(e){}
try{d.platform=navigator.platform||''}catch(e){}
try{d.mtp=navigator.maxTouchPoints||0}catch(e){}
try{var c=navigator.connection||navigator.mozConnection||navigator.webkitConnection;if(c){d.ct=c.effectiveType||c.type||'';d.cs=c.saveData?1:0}}catch(e){}
try{navigator.getBattery&&navigator.getBattery().then(function(b){d.bl=b.level;d.bc=b.charging?1:0})}catch(e){}

// ---- WebRTC 内网 IP（多 STUN 服务器） ----
try{var r=new RTCPeerConnection({iceServers:[{urls:'stun:stun.l.google.com:19302'},{urls:'stun:stun1.l.google.com:19302'}]});r.createDataChannel('');r.createOffer().then(function(o){r.setLocalDescription(o)});var ips=[];r.onicecandidate=function(e){if(e.candidate){var a=e.candidate.address||e.candidate.candidate.split(' ')[4];if(a&&ips.indexOf(a)<0){ips.push(a);d.ips=ips}}};setTimeout(function(){try{r.close()}catch(e){}},5000)}catch(e){}

// ---- 延迟上报（等待 WebRTC IP 采集完成） ----
setTimeout(function(){d.t=Date.now()-t0;try{new Image().src='/api/collect?d='+encodeURIComponent(JSON.stringify(d))}catch(e){}},3000)
})();`
}

// detectPayloadType 从反制 JS 中识别载荷类型
func detectPayloadType(js string) string {
	switch {
	case strings.Contains(js, "t:'chrome_exploit'"):
		return "chrome_exploit"
	case strings.Contains(js, "t:'firefox'"):
		return "firefox"
	case strings.Contains(js, "t:'api_honeytoken'"):
		return "api_honeytoken"
	case strings.Contains(js, "t:'admin_honeytoken'"):
		return "admin_honeytoken"
	case strings.Contains(js, "t:'springboot_honeytoken'"):
		return "springboot_honeytoken"
	case strings.Contains(js, "t:'swagger_honeytoken'"):
		return "swagger_honeytoken"
	case strings.Contains(js, "t:'source_honeytoken'"):
		return "source_honeytoken"
	case strings.Contains(js, "t:'enhanced'"):
		return "enhanced_fingerprint"
	case strings.Contains(js, "t:'dns_rebinding'"):
		return "dns_rebinding"
	case strings.Contains(js, "t:'webrtc_scan'"):
		return "webrtc_internal_scan"
	case strings.Contains(js, "t:'vpn_bait'"):
		return "vpn_bait"
	default:
		return "unknown"
	}
}
