package traceability

import (
	"fmt"
	"strings"

	"github.com/Laji-HoneyPot/honeypot/internal/core/bus"
	"github.com/Laji-HoneyPot/honeypot/internal/core/config"
	"github.com/Laji-HoneyPot/honeypot/internal/core/log"
	"github.com/Laji-HoneyPot/honeypot/internal/plugin"
	"github.com/Laji-HoneyPot/honeypot/internal/traceability/fingerprint"
	"github.com/Laji-HoneyPot/honeypot/internal/traceability/payload"
	"github.com/Laji-HoneyPot/honeypot/internal/traceability/vulndb"
)

// Engine 溯源反制引擎插件
type Engine struct {
	plugin.Base
	logger     *log.Logger
	bus        *bus.Bus
	vulnDB     *vulndb.DB
	crawler    *vulndb.NVDCrawler
	collector  *fingerprint.Collector
	payloadGen *payload.Generator
}

// NewEngine 创建溯源反制引擎
func NewEngine(logger *log.Logger, bus *bus.Bus) *Engine {
	e := &Engine{
		logger:     logger,
		bus:        bus,
		vulnDB:     vulndb.NewDB(logger),
		crawler:    vulndb.NewNVDCrawler(logger, ""),
		collector:  fingerprint.NewCollector(logger),
		payloadGen: payload.NewGenerator(logger, "http://localhost:8080"),
	}

	// 订阅蜜罐引擎的连接事件
	bus.Subscribe("honeypot.connection", e.onConnection)
	bus.Subscribe("honeypot.attack", e.onAttack)
	bus.Subscribe("honeypot.breadcrumb", e.onBreadcrumbTrigger)

	return e
}

func (e *Engine) Name() string    { return "traceability-engine" }
func (e *Engine) Version() string { return "0.4.0" }

func (e *Engine) Init(cfg config.Section) error {
	e.logger.Info("traceability engine initialized")
	return nil
}

func (e *Engine) Start() error {
	e.logger.Info("traceability engine started")

	// 后台异步拉取最新漏洞情报
	go func() {
		entries, err := e.crawler.FetchRecent(vulndb.RedTeamKeywords)
		if err != nil {
			e.logger.Warnw("nvd crawl failed", "error", err)
			return
		}
		for _, entry := range entries {
			e.vulnDB.Add(entry)
		}
		e.logger.Infow("nvd crawl complete", "new_entries", len(entries))
	}()

	return nil
}

func (e *Engine) Stop() error {
	e.logger.Info("traceability engine stopped")
	return nil
}

func (e *Engine) onConnection(evt bus.Event) {
	e.collector.RecordConnection(string(evt.Payload))
}

func (e *Engine) onAttack(evt bus.Event) {
	e.logger.Infow("attack detected", "payload", string(evt.Payload))
}

func (e *Engine) onBreadcrumbTrigger(evt bus.Event) {
	e.logger.Warnw("BREADCRUMB TRIGGERED — attacker confirmed", "details", string(evt.Payload))
}

// GetVulnDB 暴露漏洞库
func (e *Engine) GetVulnDB() *vulndb.DB { return e.vulnDB }

// GetCollector 暴露指纹采集器
func (e *Engine) GetCollector() *fingerprint.Collector { return e.collector }

// GetPayloadGen 暴露 Payload 生成器
func (e *Engine) GetPayloadGen() *payload.Generator { return e.payloadGen }

// SelectPayload 智能载荷选择器 — 根据攻击上下文选择最优反制 Payload
//
// 选择策略（按优先级）：
//  1. UA 识别 Chrome → Chrome 硬件指纹 + 社工下载诱饵
//  2. UA 识别 Firefox → Firefox buildID/oscpu 指纹
//  3. UA 识别 curl/wget/python → API 蜜标诱饵
//  4. UA 识别 Burp/Java → 增强指纹 + 内网 IP 采集
//  5. 路径含 admin/config → 管理后台蜜标表单
//  6. 路径含 api/swagger → 假 API Key + 内网端点
//  7. 路径含 .git/backup → 源码泄露蜜标
//  8. 默认 → 增强通用指纹采集
func (e *Engine) SelectPayload(path, userAgent, remoteIP string) string {
	ua := strings.ToLower(userAgent)

	// 1. Chrome 浏览器 → Chrome 专项采集
	if strings.Contains(ua, "chrome") && !strings.Contains(ua, "headless") && !strings.Contains(ua, "bot") {
		return e.chromePayload()
	}

	// 2. Firefox 浏览器 → Firefox 专项采集
	if strings.Contains(ua, "firefox") && !strings.Contains(ua, "bot") {
		return e.firefoxPayload()
	}

	// 3. 自动化工具 (curl/wget/python) → API 蜜标诱饵
	if strings.Contains(ua, "curl") || strings.Contains(ua, "wget") || strings.Contains(ua, "python") {
		return e.apiHoneytokenPayload(path)
	}

	// 4. Burp Suite / Java → 增强内网 IP 采集
	if strings.Contains(ua, "burp") || strings.Contains(ua, "java") {
		return e.enhancedFingerprintPayload()
	}

	// 5. 路径匹配 — 管理后台
	if strings.Contains(path, "admin") || strings.Contains(path, "config") || strings.Contains(path, "login") {
		return e.adminHoneytokenPayload()
	}

	// 6. 路径匹配 — API/Swagger
	if strings.Contains(path, "api") || strings.Contains(path, "swagger") {
		return e.apiHoneytokenPayload(path)
	}

	// 7. 路径匹配 — 源码泄露
	if strings.Contains(path, ".git") || strings.Contains(path, "backup") {
		return e.sourceLeakHoneytoken()
	}

	// 8. 默认 — 增强通用指纹
	return e.enhancedFingerprintPayload()
}

// chromePayload Chrome 浏览器专项反制 — 硬件指纹 + 社工下载诱饵
func (e *Engine) chromePayload() string {
	return fmt.Sprintf(`<script>
// Laji-HoneyPot 反制 / Chrome 专项
(function(){
var d={t:'chrome_exploit',ts:Date.now(),ua:navigator.userAgent,
  plat:navigator.platform,hw:navigator.hardwareConcurrency,
  mem:navigator.deviceMemory||'unknown',conn:navigator.connection?navigator.connection.effectiveType:'unknown',
  scr:screen.width+'x'+screen.height,tz:Intl.DateTimeFormat().resolvedOptions().timeZone,
  lang:navigator.language};
try{var g=document.createElement('canvas').getContext('webgl');
d.gpu=g.getParameter(g.RENDERER)}catch(e){}
try{navigator.getBattery().then(function(b){d.bat=Math.round(b.level*100)+'%%:'+b.charging})}catch(e){}
try{var r=new RTCPeerConnection({iceServers:[{urls:'stun:stun.l.google.com:19302'}]});
r.createDataChannel('');r.createOffer().then(function(o){r.setLocalDescription(o)});
r.onicecandidate=function(e){if(e.candidate){var a=e.candidate.address||e.candidate.candidate.split(' ')[4];
if(a&&a.match(/^(192\\.168\\.|10\\.|172\\.(1[6-9]|2\\d|3[01])\\.)/))d.ip=a}};
setTimeout(function(){new Image().src='/api/collect?d='+encodeURIComponent(JSON.stringify(d))},1500)}catch(e){
new Image().src='/api/collect?d='+encodeURIComponent(JSON.stringify(d))}
var a=document.createElement('a');a.href='/api/collect?dl='+encodeURIComponent(JSON.stringify(d));
a.download='session_info.json';document.body.appendChild(a);a.click();
})();
</script>`)
}

// firefoxPayload Firefox 浏览器专项反制 — buildID/oscpu 系统架构信息
func (e *Engine) firefoxPayload() string {
	return fmt.Sprintf(`<script>
(function(){var d={t:'firefox',ts:Date.now(),ua:navigator.userAgent,
bid:navigator.buildID||'',os:navigator.oscpu||'',
scr:screen.width+'x'+screen.height,tz:Intl.DateTimeFormat().resolvedOptions().timeZone};
try{var r=new RTCPeerConnection({iceServers:[{urls:'stun:stun.l.google.com:19302'}]});
r.createDataChannel('');r.createOffer().then(function(o){r.setLocalDescription(o)});
r.onicecandidate=function(e){if(e.candidate){var a=e.candidate.address||e.candidate.candidate.split(' ')[4];
if(a&&a.match(/^(192\\.168\\.|10\\.|172\\.(1[6-9]|2\\d|3[01])\\.)/))d.ip=a}};
setTimeout(function(){new Image().src='/api/collect?d='+encodeURIComponent(JSON.stringify(d))},1500)}catch(e){
new Image().src='/api/collect?d='+encodeURIComponent(JSON.stringify(d))}})();
</script>`)
}

// apiHoneytokenPayload API 蜜标诱饵 — 自动化工具专用
func (e *Engine) apiHoneytokenPayload(path string) string {
	return fmt.Sprintf(`<script>
document.write('<div style="display:none" id="hp_token">');
document.write('{"api_key":"sk-live-a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6",');
document.write('"endpoint":"https://internal-api.local/v2/admin/users",');
document.write('"token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.dQw4w9WgXcQ",');
document.write('"db_host":"10.0.1.50:5432","db_user":"admin","db_pass":"P@ssw0rd2024"}');
document.write('</div>');
(function(){var d={t:'api_honeytoken',path:'%s',ts:Date.now(),ua:navigator.userAgent};
new Image().src='/api/collect?d='+encodeURIComponent(JSON.stringify(d))})();
</script>`, path)
}

// adminHoneytokenPayload 管理后台蜜标 — 假 Session/Token 泄露
func (e *Engine) adminHoneytokenPayload() string {
	return fmt.Sprintf(`<script>
document.write('<div style="display:none">');
document.write('<input type="hidden" name="csrf_token" value="hp_csrf_a1b2c3d4e5f6g7h8i9j0" />');
document.write('<input type="hidden" name="session_id" value="hp_sess_k1l2m3n4o5p6q7r8s9t0" />');
document.write('<input type="hidden" name="api_secret" value="hp_sec_u1v2w3x4y5z6a7b8c9d0" />');
document.write('</div>');
(function(){var d={t:'admin_honeytoken',ts:Date.now(),ua:navigator.userAgent};
new Image().src='/api/collect?d='+encodeURIComponent(JSON.stringify(d))})();
</script>`)
}

// sourceLeakHoneytoken 源码泄露蜜标 — 假凭证、私钥信息
func (e *Engine) sourceLeakHoneytoken() string {
	return fmt.Sprintf(`<script>
document.write('<pre style="display:none" id="hp_source">');
document.write('# AWS Credentials\\naws_access_key_id = AKIAIOSFODNN7EXAMPLE\\n');
document.write('aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\\n');
document.write('# Database Config\\nDB_HOST=10.0.2.15\\nDB_USER=root\\n');
document.write('DB_PASS=R00t@Internal2024\\n# SSH Private Key\\n');
document.write('-----BEGIN RSA PRIVATE KEY-----\\n');
document.write('MIIEpAIBAAKCAQEA0Z3...\\n-----END RSA PRIVATE KEY-----');
document.write('</pre>');
(function(){var d={t:'source_honeytoken',ts:Date.now()};
new Image().src='/api/collect?d='+encodeURIComponent(JSON.stringify(d))})();
</script>`)
}

// enhancedFingerprintPayload 增强通用指纹 — Canvas/WebGL/WebRTC/音频/电池/无头检测
func (e *Engine) enhancedFingerprintPayload() string {
	return fmt.Sprintf(`<script>
// Laji-HoneyPot 反制 / 增强指纹
(function(){var d={t:'enhanced',ts:Date.now()};
try{var c=document.createElement('canvas');c.width=280;c.height=60;var x=c.getContext('2d');
x.fillStyle='#f60';x.fillRect(125,1,62,20);x.fillStyle='#069';
x.fillText('Trace',2,15);d.canvas=c.toDataURL().substring(0,120)}catch(e){}
try{var g=document.createElement('canvas').getContext('webgl');
if(g)d.gpu=g.getParameter(g.RENDERER)}catch(e){}
d.ua=navigator.userAgent;d.scr=screen.width+'x'+screen.height;
d.tz=Intl.DateTimeFormat().resolvedOptions().timeZone;d.lang=navigator.language;
d.hw=navigator.hardwareConcurrency;try{d.mem=navigator.deviceMemory}catch(e){}
try{var ac=new(window.AudioContext||window.webkitAudioContext)(),osc=ac.createOscillator(),
an=ac.createAnalyser();osc.connect(an);an.connect(ac.destination);osc.start(0);
var buf=new Float32Array(an.frequencyBinCount);an.getFloatTimeDomainData(buf);
d.afp=Array.prototype.slice.call(buf,0,10).join(',')}catch(e){}
try{navigator.getBattery().then(function(b){d.bat=Math.round(b.level*100)+':'+b.charging})}catch(e){}
try{var el=document.createElement('div');document.body.appendChild(el);
d.phantom=el.getClientRects().length===0?1:0;document.body.removeChild(el)}catch(e){}
try{var r=new RTCPeerConnection({iceServers:[{urls:'stun:stun.l.google.com:19302'}]});
r.createDataChannel('');r.createOffer().then(function(o){r.setLocalDescription(o)});
r.onicecandidate=function(e){if(e.candidate){var a=e.candidate.address||e.candidate.candidate.split(' ')[4];
if(a&&a.match(/^(192\\.168\\.|10\\.|172\\.(1[6-9]|2\\d|3[01])\\.)/))d.ip=a}};
setTimeout(function(){new Image().src='/api/collect?d='+encodeURIComponent(JSON.stringify(d))},1500)}catch(e){
new Image().src='/api/collect?d='+encodeURIComponent(JSON.stringify(d))}})();
</script>`)
}
