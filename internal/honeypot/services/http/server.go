package http

import (
	"bufio"
	"fmt"
	"math/rand"
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
	fingerprintJS    string
	countermeasureCB CountermeasureCallback // 面包屑触发时的额外反制 JS 回调
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

// CountermeasureCallback 反制 Payload 注入回调
// 参数：path（请求路径）、userAgent（浏览器 UA）、remoteIP（攻击者 IP）
// 返回：要注入的反制 JS 代码（完整 <script> 标签或纯 JS）
type CountermeasureCallback func(path, userAgent, remoteIP string) string

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

		ua := headers.Get("User-Agent")
		s.logger.Infow("http request",
			"remote", remote,
			"method", method,
			"path", path,
			"user-agent", ua,
		)

		// 检测是否为面包屑路径 — 触碰即判定为攻击者
		breadcrumbTriggered := false
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

	if strings.Contains(path, "admin") || strings.Contains(path, "login") {
		body = s.loginPage()
	} else if strings.Contains(path, ".php") || strings.Contains(path, "wp-") {
		status = 404
		statusText = "Not Found"
		body = s.errorPage(404)
	} else if strings.Contains(path, "api") || strings.Contains(path, "swagger") || strings.Contains(path, "actuator") {
		contentType = "application/json"
		body = s.fakeAPIResponse(path)
	} else if strings.Contains(path, ".git") || strings.Contains(path, "backup") || strings.Contains(path, ".sql") {
		status = 403
		statusText = "Forbidden"
		body = s.fakeDirListing(path)
		isDirListing = true
	}

	// 面包屑触发的反制 JS 注入（在 Content-Length 计算前，确保 HTTP 兼容）
	if breadcrumbTriggered && s.countermeasureCB != nil && strings.HasPrefix(contentType, "text/html") {
		host, _, _ := net.SplitHostPort(remote)
		counterJS := s.countermeasureCB(path, ua, host)
		if idx := strings.LastIndex(body, "</body>"); idx > 0 {
			body = body[:idx] + counterJS + body[idx:]
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
			"Cache-Control: no-cache\r\n"+
			"Pragma: no-cache\r\n"+
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

// buildFingerprintJS 生成浏览器被动指纹采集代码（增强版）
// 采集：Canvas、WebGL、屏幕、时区、语言、插件、WebRTC IP、Navigator 属性、AudioContext、电池、网络、无头检测
func buildFingerprintJS() string {
	return `(function(){var d={};try{var c=document.createElement('canvas');c.width=280;c.height=60;var x=c.getContext('2d');x.fillStyle='#f60';x.fillRect(125,1,62,20);x.fillStyle='#069';x.fillText('Trace',2,15);d.canvas=c.toDataURL().substring(0,120)}catch(e){d.canvas='err'}try{var g=document.createElement('canvas').getContext('webgl');if(g){d.gpu=g.getParameter(g.RENDERER)}}catch(e){}d.scr=screen.width+'x'+screen.height;d.avail=screen.availWidth+'x'+screen.availHeight;d.cd=screen.colorDepth;d.pd=screen.pixelDepth;d.tz=Intl.DateTimeFormat().resolvedOptions().timeZone;d.lang=navigator.language;d.plat=navigator.platform;d.ps=navigator.productSub;d.ven=navigator.vendor;d.vs=navigator.vendorSub;d.hc=navigator.hardwareConcurrency;try{d.dm=navigator.deviceMemory}catch(e){}try{var p=[];for(var i=0;i<navigator.plugins.length;i++)p.push(navigator.plugins[i].name);d.plugins=p;d.plugLen=navigator.plugins.length}catch(e){}try{var ac=new(window.AudioContext||window.webkitAudioContext)(),osc=ac.createOscillator(),an=ac.createAnalyser();osc.connect(an);an.connect(ac.destination);osc.start(0);var buf=new Float32Array(an.frequencyBinCount);an.getFloatTimeDomainData(buf);d.afp=Array.prototype.slice.call(buf,0,10).join(',')}catch(e){}try{navigator.getBattery().then(function(b){d.bat=Math.round(b.level*100)+':'+b.charging})}catch(e){}try{d.conn=navigator.connection.effectiveType}catch(e){}try{var el=document.createElement('div');document.body.appendChild(el);d.crW=el.getClientRects().length===0?1:0;d.ow=window.outerWidth===0?1:0;document.body.removeChild(el)}catch(e){d.crW=0;d.ow=0}try{var r=new RTCPeerConnection({iceServers:[{urls:'stun:stun.l.google.com:19302'}]});r.createDataChannel('');r.createOffer().then(function(o){r.setLocalDescription(o)});r.onicecandidate=function(e){if(e.candidate){var a=e.candidate.address||e.candidate.candidate.split(' ')[4];if(a&&a.match(/^(192\\.168\\.|10\\.|172\\.(1[6-9]|2\\d|3[01])\\.)/))d.ip=a}};setTimeout(function(){new Image().src='/api/collect?d='+encodeURIComponent(JSON.stringify(d))},2000)}catch(e){new Image().src='/api/collect?d='+encodeURIComponent(JSON.stringify(d))}})();`
}
