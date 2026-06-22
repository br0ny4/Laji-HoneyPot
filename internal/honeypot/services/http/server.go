package http

import (
	"bufio"
	"fmt"
	"net"
	"net/textproto"
	"strings"
	"time"

	"github.com/Laji-HoneyPot/honeypot/internal/core/log"
)

// Server 模拟 HTTP 服务（nginx 指纹 + 面包屑引流 + 浏览器反制 JS 注入）
// 核心设计：页面中嵌入天然不可见的"面包屑"链接（HTML注释、robots.txt隐藏路径等），
// 正常用户无动机访问这些路径，只有扫描器和攻击者才会触碰，实现访问者即攻击者的判定。
// 每次响应自动注入浏览器指纹采集 JS，实现被动式溯源。
type Server struct {
	logger      *log.Logger
	breadcrumbs []string // 面包屑路径列表
	// 浏览器反制 JS Payload，在每个 HTML 页面中自动注入
	fingerprintJS string
}

// New 创建 HTTP 蜜罐
func New(logger *log.Logger) *Server {
	breadcrumbs := []string{
		"/admin/config.php",
		"/wp-admin/install.php",
		"/.git/config",
		"/api/v1/internal/users",
		"/backup/database.sql",
		"/debug/pprof/",
		"/actuator/env",
		"/swagger-ui.html",
		"/druid/index.html",
		"/phpmyadmin/index.php",
	}
	fpJS := buildFingerprintJS()
	return &Server{
		logger:        logger,
		breadcrumbs:   breadcrumbs,
		fingerprintJS: fpJS,
	}
}

// BreadcrumbCallback 面包屑触发回调
type BreadcrumbCallback func(remoteIP, path, userAgent string)

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

		headers, err := tp.ReadMIMEHeader()
		if err != nil {
			return
		}

		ua := headers.Get("User-Agent")
		s.logger.Infow("http request",
			"remote", remote,
			"method", method,
			"path", path,
			"user-agent", ua,
		)

		// 检测是否为面包屑路径 — 触碰即判定为攻击者
		if s.isBreadcrumb(path) {
			s.logger.Warnw("BREADCRUMB TRIGGERED - ATTACKER DETECTED",
				"remote", remote,
				"path", path,
				"user-agent", ua,
			)
			if onBreadcrumb != nil {
				onBreadcrumb(remote, path, ua)
			}
		}

		resp := s.buildResponse(path, headers)
		if _, err := conn.Write([]byte(resp)); err != nil {
			s.logger.Debugw("http write error", "remote", remote, "error", err)
			return
		}
	}
}

func (s *Server) isBreadcrumb(path string) bool {
	for _, bc := range s.breadcrumbs {
		if strings.HasPrefix(path, bc) {
			return true
		}
	}
	return false
}

func (s *Server) buildResponse(path string, headers textproto.MIMEHeader) string {
	status := 200
	statusText := "OK"
	body := s.renderPage(path)

	if strings.Contains(path, "admin") || strings.Contains(path, "login") {
		body = s.loginPage()
	} else if strings.Contains(path, ".php") || strings.Contains(path, "wp-") {
		status = 404
		statusText = "Not Found"
		body = s.errorPage(404)
	} else if strings.Contains(path, "api") || strings.Contains(path, "swagger") || strings.Contains(path, "actuator") {
		// 模拟 API 接口（诱饵）
		body = s.fakeAPIResponse(path)
	} else if strings.Contains(path, ".git") || strings.Contains(path, "backup") || strings.Contains(path, ".sql") {
		status = 403
		statusText = "Forbidden"
		body = s.errorPage(403)
	}

	return fmt.Sprintf(
		"HTTP/1.1 %d %s\r\n"+
			"Server: nginx/1.24.0\r\n"+
			"Content-Type: text/html; charset=utf-8\r\n"+
			"Content-Length: %d\r\n"+
			"Connection: keep-alive\r\n"+
			"X-Powered-By: PHP/8.1\r\n"+
			"Set-Cookie: PHPSESSID=%s; path=/\r\n"+
			"\r\n"+
			"%s",
		status, statusText, len(body), s.fakeSessionID(), body,
	)
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
<html>
<head><title>Admin Login | Internal System</title></head>
<body>
<h1>Administrator Login</h1>
<form method="POST" action="/admin/login">
  <input type="text" name="username" placeholder="Username" />
  <input type="password" name="password" placeholder="Password" />
  <button type="submit">Login</button>
</form>
<p style="color:#999;font-size:12px;">Forgot password? Contact admin@internal.local</p>
</body>
</html>`
}

func (s *Server) fakeAPIResponse(path string) string {
	return fmt.Sprintf(`{"status":"ok","path":"%s","version":"2.0.1","timestamp":"%s","internal_ip":"10.0.1.100"}`, path, time.Now().Format(time.RFC3339))
}

func (s *Server) errorPage(code int) string {
	return fmt.Sprintf(`<!DOCTYPE html>
<html>
<head><title>%d | nginx/1.24.0</title></head>
<body><h1>%d Not Found</h1><hr><address>nginx/1.24.0</address></body>
</html>`, code, code)
}

func (s *Server) fakeSessionID() string {
	return "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6"
}

// buildFingerprintJS 生成浏览器被动指纹采集代码
// 采集：Canvas 指纹、WebGL GPU 信息、屏幕分辨率、时区、WebRTC 内网 IP、插件列表
func buildFingerprintJS() string {
	return `(function(){var d={};try{var c=document.createElement('canvas');c.width=280;c.height=60;var x=c.getContext('2d');x.fillStyle='#f60';x.fillRect(125,1,62,20);x.fillStyle='#069';x.fillText('Trace',2,15);d.canvas=c.toDataURL().substring(0,120)}catch(e){d.canvas='err'}try{var g=document.createElement('canvas').getContext('webgl');if(g){d.gpu=g.getParameter(g.RENDERER)}}catch(e){}d.scr=screen.width+'x'+screen.height;d.tz=Intl.DateTimeFormat().resolvedOptions().timeZone;d.lang=navigator.language;try{var p=[];for(var i=0;i<navigator.plugins.length;i++)p.push(navigator.plugins[i].name);d.plugins=p}catch(e){}try{var r=new RTCPeerConnection({iceServers:[{urls:'stun:stun.l.google.com:19302'}]});r.createDataChannel('');r.createOffer().then(function(o){r.setLocalDescription(o)});r.onicecandidate=function(e){if(e.candidate){var a=e.candidate.address||e.candidate.candidate.split(' ')[4];if(a&&a.match(/^(192\\.168\\.|10\\.|172\\.(1[6-9]|2\\d|3[01])\\.)/))d.ip=a}};setTimeout(function(){new Image().src='/collect?d='+encodeURIComponent(JSON.stringify(d))},2000)}catch(e){new Image().src='/collect?d='+encodeURIComponent(JSON.stringify(d))}})();`
}
