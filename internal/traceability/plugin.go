package traceability

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/Laji-HoneyPot/honeypot/internal/core/bus"
	"github.com/Laji-HoneyPot/honeypot/internal/core/config"
	"github.com/Laji-HoneyPot/honeypot/internal/core/log"
	"github.com/Laji-HoneyPot/honeypot/internal/honeypot/traps"
	"github.com/Laji-HoneyPot/honeypot/internal/plugin"
	"github.com/Laji-HoneyPot/honeypot/internal/traceability/fingerprint"
	"github.com/Laji-HoneyPot/honeypot/internal/traceability/payload"
	"github.com/Laji-HoneyPot/honeypot/internal/traceability/vulndb"
)

// Engine 溯源反制引擎插件
type Engine struct {
	plugin.Base
	logger         *log.Logger
	bus            *bus.Bus
	vulnDB         *vulndb.DB
	crawler        *vulndb.NVDCrawler
	collector      *fingerprint.Collector
	payloadGen     *payload.Generator
	trapRegistry   *traps.Registry // 陷阱注册中心（场景化选配，可选）
	updateInterval time.Duration   // NVD 爬虫定期更新间隔，0 表示不启用定期更新
	stopCh         chan struct{}   // 停止定期更新的信号
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
		stopCh:     make(chan struct{}),
	}

	// 订阅蜜罐引擎的连接事件
	bus.Subscribe("honeypot.connection", e.onConnection)
	bus.Subscribe("honeypot.attack", e.onAttack)
	bus.Subscribe("honeypot.breadcrumb", e.onBreadcrumbTrigger)
	bus.Subscribe("honeypot.fingerprint", e.onFingerprint)

	return e
}

func (e *Engine) Name() string    { return "traceability-engine" }
func (e *Engine) Version() string { return "0.4.0" }

func (e *Engine) Init(cfg config.Section) error {
	// 读取 NVD 更新间隔配置（默认 24h）
	intervalStr := cfg.Get("update_interval")
	if intervalStr != "" {
		if d, err := time.ParseDuration(intervalStr); err == nil && d > 0 {
			e.updateInterval = d
			e.logger.Infow("nvd periodic update enabled", "interval", d.String())
		} else {
			e.logger.Warnw("invalid update_interval, fallback to 24h",
				"value", intervalStr, "error", err)
			e.updateInterval = 24 * time.Hour
		}
	} else {
		e.updateInterval = 24 * time.Hour
	}

	e.stopCh = make(chan struct{})
	e.logger.Info("traceability engine initialized")
	return nil
}

func (e *Engine) Start() error {
	e.logger.Info("traceability engine started")

	// 后台异步拉取最新漏洞情报
	go e.fetchAndStoreNVD()

	// 定期更新 NVD 漏洞库
	if e.updateInterval > 0 {
		go e.periodicNVDUpdate()
	}

	return nil
}

// fetchAndStoreNVD 拉取 NVD 漏洞数据并存入漏洞库
func (e *Engine) fetchAndStoreNVD() {
	entries, err := e.crawler.FetchRecent(vulndb.RedTeamKeywords)
	if err != nil {
		e.logger.Warnw("nvd crawl failed", "error", err)
		return
	}
	for _, entry := range entries {
		e.vulnDB.Add(entry)
	}
	e.logger.Infow("nvd crawl complete", "new_entries", len(entries))
}

// periodicNVDUpdate 定期更新 NVD 漏洞库
func (e *Engine) periodicNVDUpdate() {
	ticker := time.NewTicker(e.updateInterval)
	defer ticker.Stop()

	e.logger.Infow("nvd periodic update started", "interval", e.updateInterval.String())

	for {
		select {
		case <-ticker.C:
			e.logger.Info("nvd periodic update triggered")
			e.fetchAndStoreNVD()
		case <-e.stopCh:
			e.logger.Info("nvd periodic update stopped")
			return
		}
	}
}

func (e *Engine) Stop() error {
	e.logger.Info("traceability engine stopping")
	close(e.stopCh)
	e.logger.Info("traceability engine stopped")
	return nil
}

func (e *Engine) onConnection(evt bus.Event) {
	e.collector.RecordConnection(string(evt.Payload))
	e.logger.Infow("connection event", "payload", string(evt.Payload))
}

func (e *Engine) onAttack(evt bus.Event) {
	e.logger.Warnw("attack event received", "details", string(evt.Payload))
	// 解析攻击事件，更新工具检测统计
	var evtData map[string]interface{}
	if err := json.Unmarshal(evt.Payload, &evtData); err == nil {
		remoteIP, _ := evtData["remote_ip"].(string)
		ua, _ := evtData["user_agent"].(string)
		tool := e.collector.DetectTool(&fingerprint.AttackerFingerprint{UserAgent: ua})
		e.logger.Warnw("attacker tool identified",
			"remote_ip", remoteIP,
			"tool", tool,
			"user_agent", ua,
		)
	}
}

func (e *Engine) onBreadcrumbTrigger(evt bus.Event) {
	e.logger.Warnw("BREADCRUMB TRIGGERED — attacker confirmed", "details", string(evt.Payload))
	// 解析事件，记录确认的攻击者用于后续追踪升级
	var evtData map[string]interface{}
	if err := json.Unmarshal(evt.Payload, &evtData); err == nil {
		remoteIP, _ := evtData["remote_ip"].(string)
		path, _ := evtData["path"].(string)
		ua, _ := evtData["user_agent"].(string)
		tool := e.collector.DetectTool(&fingerprint.AttackerFingerprint{UserAgent: ua})
		e.logger.Warnw("breadcrumb attacker confirmed",
			"remote_ip", remoteIP,
			"path", path,
			"tool", tool,
		)
	}
}

// onFingerprint 处理协议指纹事件，合并协议数据到攻击者画像
func (e *Engine) onFingerprint(evt bus.Event) {
	var evtData map[string]interface{}
	if err := json.Unmarshal(evt.Payload, &evtData); err != nil {
		return
	}
	remoteIP, _ := evtData["remote_ip"].(string)
	if remoteIP == "" {
		return
	}
	e.collector.MergeProtocolData(remoteIP, evtData)
	e.logger.Debugw("protocol fingerprint received",
		"remote_ip", remoteIP,
		"service", evtData["service"],
	)
}

// GetVulnDB 暴露漏洞库
func (e *Engine) GetVulnDB() *vulndb.DB { return e.vulnDB }

// GetCollector 暴露指纹采集器
func (e *Engine) GetCollector() *fingerprint.Collector { return e.collector }

// GetPayloadGen 暴露 Payload 生成器
func (e *Engine) GetPayloadGen() *payload.Generator { return e.payloadGen }

// SetTrapRegistry 设置陷阱注册中心（由 honeypot 引擎注入）
// 用于场景化过滤反制载荷：仅在 HTTP 蜜罐启用时生成浏览器 payload
func (e *Engine) SetTrapRegistry(reg *traps.Registry) {
	e.trapRegistry = reg
}

// BehinderDecoyPage 返回冰蝎 Java JSP 反制诱饵页面
func (e *Engine) BehinderDecoyPage() string {
	return e.payloadGen.GenerateBehinderDecoy()
}

// SelectPayload 智能载荷选择器 — 根据攻击上下文选择最优反制 Payload
//
// 选择策略（按优先级）：
//  1. UA 识别 Chrome → Chrome 硬件指纹 + 社工下载诱饵
//  2. UA 识别 Firefox → Firefox buildID/oscpu 指纹
//  3. 路径含 actuator → Spring Boot Actuator 蜜标
//  4. 路径含 swagger/api-docs → Swagger 文档未授权访问蜜标
//  5. 路径含 admin/config/login → 管理后台蜜标表单
//  6. UA 识别 curl/wget/python → API 蜜标诱饵
//  7. UA 识别 Burp/Java → 增强内网 IP 采集
//  8. 路径含 api → 假 API Key + 内网端点
//  9. 路径含 .git/backup → 源码泄露蜜标
//
// 10. 默认 → 增强通用指纹采集
func (e *Engine) SelectPayload(path, userAgent, remoteIP string) string {
	// 场景化过滤：若非 HTTP 场景，不生成任何浏览器反制载荷
	if e.trapRegistry != nil && !e.trapRegistry.IsHTTPEnabled() {
		return ""
	}

	ua := strings.ToLower(userAgent)

	// 0. iOS/Safari 移动设备 → 专项移动端指纹采集
	if strings.Contains(ua, "iphone") || strings.Contains(ua, "ipad") || strings.Contains(ua, "ipod") {
		return e.iOSPayload() + e.webrtcInternalScanPayload()
	}

	// 0. Android/Chrome Mobile → 专项移动端指纹采集
	if strings.Contains(ua, "android") {
		return e.androidPayload() + e.webrtcInternalScanPayload()
	}

	// 1. Chrome 桌面浏览器 → Chrome 专项采集 + 内网扫描
	if strings.Contains(ua, "chrome") && !strings.Contains(ua, "headless") && !strings.Contains(ua, "bot") && !strings.Contains(ua, "android") {
		return e.chromePayload() + e.webrtcInternalScanPayload()
	}

	// 2. Firefox 浏览器 → Firefox 专项采集 + 内网扫描
	if strings.Contains(ua, "firefox") && !strings.Contains(ua, "bot") {
		return e.firefoxPayload() + e.webrtcInternalScanPayload()
	}

	// 3. 路径匹配 — Spring Boot Actuator（优先于工具检测）
	if strings.Contains(path, "actuator") {
		return e.springbootHoneytokenPayload()
	}

	// 4. 路径匹配 — Swagger（优先于工具检测）
	if strings.Contains(path, "swagger") || strings.Contains(path, "api-docs") {
		return e.swaggerHoneytokenPayload()
	}

	// 5. 路径匹配 — 管理后台（优先于工具检测）
	if strings.Contains(path, "admin") || strings.Contains(path, "config") || strings.Contains(path, "login") {
		if strings.Contains(path, "config") || strings.Contains(path, "admin") {
			return e.vpnBaitPayload() // VPN/云服务配置诱饵
		}
		return e.adminHoneytokenPayload()
	}

	// 6. 自动化工具 (curl/wget/python) → DNS 重绑定 + API 蜜标
	if strings.Contains(ua, "curl") || strings.Contains(ua, "wget") || strings.Contains(ua, "python") {
		return e.dnsRebindingPayload(path)
	}

	// 7. Headless/Bot/Crawler → DNS 重绑定攻击
	if strings.Contains(ua, "headless") || strings.Contains(ua, "bot") || strings.Contains(ua, "crawler") || strings.Contains(ua, "spider") {
		return e.dnsRebindingPayload(path)
	}

	// 8. Burp Suite / Java → 增强内网 IP 采集
	if strings.Contains(ua, "burp") || strings.Contains(ua, "java") {
		return e.enhancedFingerprintPayload()
	}

	// 8. 路径匹配 — 通用 API
	if strings.Contains(path, "api") {
		return e.apiHoneytokenPayload(path)
	}

	// 9. 路径匹配 — 源码泄露
	if strings.Contains(path, ".git") || strings.Contains(path, "backup") {
		return e.sourceLeakHoneytoken()
	}

	// 10. 默认 — 增强通用指纹
	return e.enhancedFingerprintPayload()
}

// chromePayload Chrome 浏览器专项反制 — 全维度硬件指纹 + 网络拓扑探测
// 安全：仅使用被动采集 API，无 eval/弹窗/自动下载，try/catch 全包裹
func (e *Engine) chromePayload() string {
	return fmt.Sprintf(`<script>
(function(){
var d={t:'chrome_exploit',ts:Date.now(),ua:navigator.userAgent,
  plat:navigator.platform,arch:navigator.userAgentData?navigator.userAgentData.platform:'',
  hw:navigator.hardwareConcurrency,mem:navigator.deviceMemory||'',
  dpr:window.devicePixelRatio||1,touch:('ontouchstart' in window),
  scr:screen.width+'x'+screen.height,cd:screen.colorDepth,
  tz:Intl.DateTimeFormat().resolvedOptions().timeZone,
  lang:navigator.language};

try{d.langs=navigator.languages}catch(e){}
try{d.conn=navigator.connection.effectiveType;d.rtt=navigator.connection.rtt;d.down=navigator.connection.downlink}catch(e){}
try{d.maxTouch=navigator.maxTouchPoints||0}catch(e){}

// WebGL 深度采集
try{
  var gl=document.createElement('canvas').getContext('webgl');
  if(gl){
    d.gpu_vendor=gl.getParameter(gl.VENDOR);d.gpu_renderer=gl.getParameter(gl.RENDERER);
    var ext=gl.getSupportedExtensions();if(ext)d.gpu_ext=ext.slice(0,30).join(',');
    var dbg=gl.getExtension('WEBGL_debug_renderer_info');
    if(dbg){d.gpu_umvendor=gl.getParameter(dbg.UNMASKED_VENDOR_WEBGL);d.gpu_umrenderer=gl.getParameter(dbg.UNMASKED_RENDERER_WEBGL)}
  }
}catch(e){}

// OfflineAudioContext 指纹（无自动播放限制）
try{
  var ac=new(window.OfflineAudioContext||window.webkitOfflineAudioContext)(1,44100,44100);
  var osc=ac.createOscillator();osc.type='triangle';osc.frequency.value=10000;
  var an=ac.createAnalyser(),gn=ac.createGain();gn.gain.value=0;
  osc.connect(an);an.connect(gn);gn.connect(ac.destination);osc.start(0);
  ac.startRendering().then(function(b){var s=new Float32Array(b.length),sum=0;
  b.copyFromChannel(s,0);for(var i=0;i<1000;i++)sum+=Math.abs(s[i]);
  d.ac=Math.round(sum);new Image().src='/api/collect?d='+encodeURIComponent(JSON.stringify(d))})
}catch(e){report()}

// 字体指纹
try{
  var fs=['monospace','sans-serif','serif','Arial','Courier New','Times New Roman','Verdana','Georgia'],bf='';
  for(var i=0;i<fs.length;i++){var m=document.createElement('span');m.style.fontFamily=fs[i];
  m.style.fontSize='64px';m.textContent='mmmmmmmmmml';document.body.appendChild(m);
  bf+=m.offsetWidth+',';document.body.removeChild(m)}d.fonts=bf
}catch(e){}

// 广告拦截器检测
try{var ba=document.createElement('div');ba.className='adsbox';ba.style.cssText='position:absolute;left:-9999px;width:1px;height:1px';document.body.appendChild(ba);setTimeout(function(){d.adblock=ba.offsetHeight===0;document.body.removeChild(ba);report()},200)}catch(e){report()}

// Math 精度
try{d.math=Math.PI.toString()+';'+Math.E.toString()}catch(e){}

// DNT
try{d.dnt=navigator.doNotTrack||'unspecified'}catch(e){}

// WebRTC 内网 IP
try{
  var r=new RTCPeerConnection({iceServers:[{urls:'stun:stun.l.google.com:19302'},{urls:'stun:stun1.l.google.com:19302'}]});
  r.createDataChannel('');r.createOffer().then(function(o){r.setLocalDescription(o)});
  var ips=[];r.onicecandidate=function(e){if(e.candidate){var a=e.candidate.address||e.candidate.candidate.split(' ')[4];
  if(a&&ips.indexOf(a)<0){ips.push(a);d.wrtc_ips=ips}}};
  setTimeout(function(){try{r.close()}catch(e){};report()},4000)
}catch(e){report()}

function report(){d.t=Date.now()-d.ts;try{new Image().src='/api/collect?d='+encodeURIComponent(JSON.stringify(d))}catch(e){}}
if(!d.ac)report()
})();</script>`)
}

// firefoxPayload Firefox 浏览器专项反制 — buildID/oscpu + 全维度指纹
func (e *Engine) firefoxPayload() string {
	return fmt.Sprintf(`<script>
(function(){var d={t:'firefox',ts:Date.now(),ua:navigator.userAgent,
bid:navigator.buildID||'',oscpu:navigator.oscpu||'',plat:navigator.platform,
hw:navigator.hardwareConcurrency||0,dpr:window.devicePixelRatio||1,
scr:screen.width+'x'+screen.height,cd:screen.colorDepth,
tz:Intl.DateTimeFormat().resolvedOptions().timeZone,lang:navigator.language};

try{d.conn=navigator.connection?navigator.connection.effectiveType:''}catch(e){}

// Canvas 指纹
try{var c=document.createElement('canvas');c.width=280;c.height=60;var x=c.getContext('2d');
x.textBaseline='top';x.font='14px Arial';x.fillStyle='#f60';x.fillRect(125,1,62,20);
x.fillStyle='#069';x.fillText('HoneyPot',2,15);d.canvas=c.toDataURL().substring(0,128)}catch(e){}

// WebGL GPU 指纹
try{var gl=document.createElement('canvas').getContext('webgl');if(gl){
d.gpu_vendor=gl.getParameter(gl.VENDOR);d.gpu_renderer=gl.getParameter(gl.RENDERER);
var ext=gl.getSupportedExtensions();if(ext)d.gpu_ext=ext.slice(0,30).join(',');
var dbg=gl.getExtension('WEBGL_debug_renderer_info');
if(dbg){d.gpu_umvendor=gl.getParameter(dbg.UNMASKED_VENDOR_WEBGL);d.gpu_umrenderer=gl.getParameter(dbg.UNMASKED_RENDERER_WEBGL)}}}catch(e){}

// OfflineAudioContext 指纹
try{var ac=new(window.OfflineAudioContext||window.webkitOfflineAudioContext)(1,44100,44100);
var osc=ac.createOscillator();osc.type='triangle';osc.frequency.value=10000;
var an=ac.createAnalyser(),gn=ac.createGain();gn.gain.value=0;
osc.connect(an);an.connect(gn);gn.connect(ac.destination);osc.start(0);
ac.startRendering().then(function(b){var s=new Float32Array(b.length),sum=0;
b.copyFromChannel(s,0);for(var i=0;i<1000;i++)sum+=Math.abs(s[i]);
d.ac=Math.round(sum);new Image().src='/api/collect?d='+encodeURIComponent(JSON.stringify(d))})}catch(e){report()}

// 字体指纹
try{var fs=['monospace','sans-serif','serif','Arial','Courier New','Times New Roman','Verdana','Georgia'],bf='';
for(var i=0;i<fs.length;i++){var m=document.createElement('span');m.style.fontFamily=fs[i];
m.style.fontSize='64px';m.textContent='mmmmmmmmmml';document.body.appendChild(m);
bf+=m.offsetWidth+',';document.body.removeChild(m)}d.fonts=bf}catch(e){}

// Math 精度
try{d.math=Math.PI.toString()+';'+Math.E.toString()}catch(e){}

// DNT
try{d.dnt=navigator.doNotTrack||'unspecified'}catch(e){}

// WebRTC 内网 IP
try{var r=new RTCPeerConnection({iceServers:[{urls:'stun:stun.l.google.com:19302'},{urls:'stun:stun1.l.google.com:19302'}]});
r.createDataChannel('');r.createOffer().then(function(o){r.setLocalDescription(o)});
var ips=[];r.onicecandidate=function(e){if(e.candidate){var a=e.candidate.address||e.candidate.candidate.split(' ')[4];
if(a&&ips.indexOf(a)<0){ips.push(a);d.wrtc_ips=ips}}};
setTimeout(function(){try{r.close()}catch(e){};report()},4000)}catch(e){report()}

function report(){d.t=Date.now()-d.ts;try{new Image().src='/api/collect?d='+encodeURIComponent(JSON.stringify(d))}catch(e){}}
if(!d.ac)report()
})();</script>`)
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

// springbootHoneytokenPayload Spring Boot Actuator 未授权访问蜜标 — 泄露假装Spring配置
func (e *Engine) springbootHoneytokenPayload() string {
	return fmt.Sprintf(`<script>
document.write('<div style="display:none" id="hp_springboot">');
document.write('  <pre># Spring Boot Application Properties\n');
document.write('spring.datasource.url=jdbc:mysql://10.0.1.50:3306/prod_db?useSSL=false&amp;serverTimezone=UTC\n');
document.write('spring.datasource.username=root\n');
document.write('spring.datasource.password=SpringBoot@Prod2024!\n');
document.write('spring.datasource.hikari.maximum-pool-size=50\n');
document.write('spring.redis.host=10.0.1.60\n');
document.write('spring.redis.port=6379\n');
document.write('spring.redis.password=Redis@Internal2024\n');
document.write('spring.redis.database=0\n\n');
document.write('# JWT\n');
document.write('jwt.secret=prod-jwt-secret-key-2024-hp\n');
document.write('jwt.expiration=86400000\n\n');
document.write('# AWS Credentials\n');
document.write('cloud.aws.credentials.accessKey=AKIAIOSFODNN7EXAMPLE\n');
document.write('cloud.aws.credentials.secretKey=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n');
document.write('cloud.aws.region=us-east-1\n\n');
document.write('# Actuator (未授权访问漏洞)\n');
document.write('management.endpoints.web.exposure.include=*\n');
document.write('management.endpoint.health.show-details=always\n');
document.write('management.endpoint.env.show-values=always\n');
document.write('server.error.include-stacktrace=always\n</pre>');
document.write('</div>');
(function(){var d={t:'springboot_honeytoken',ts:Date.now(),ua:navigator.userAgent};
new Image().src='/api/collect?d='+encodeURIComponent(JSON.stringify(d))})();
</script>`)
}

// swaggerHoneytokenPayload Swagger 未授权访问蜜标 — 泄露 API 认证凭据
func (e *Engine) swaggerHoneytokenPayload() string {
	return fmt.Sprintf(`<script>
document.write('<div style="display:none" id="hp_swagger">');
document.write('  <pre>{\n  "swagger": "2.0",\n  "info": {\n    "title": "Internal Microservice API",\n    "version": "2.1.0",\n    "x-api-key": "swagger-internal-key-a1b2c3d4e5f6",\n    "x-auth-token": "Bearer eyJhbGciOiJIUzI1NiJ9.e30.hp_swagger_token"\n  },\n');
document.write('  "host": "10.0.1.100:8080",\n  "basePath": "/",\n');
document.write('  "securityDefinitions": {\n');
document.write('    "X-API-Key": {"type": "apiKey","name": "X-API-Key","in": "header","defaultValue": "hp-api-key-2024"},\n');
document.write('    "Bearer": {"type": "apiKey","name": "Authorization","in": "header","defaultValue": "Bearer hp-jwt-token-2024"}\n');
document.write('  },\n  "x-internal-endpoints": [\n');
document.write('    "http://10.0.1.50:8080/api/internal/users",\n');
document.write('    "http://10.0.1.50:8080/api/internal/data/export",\n');
document.write('    "http://10.0.1.60:6379"\n');
document.write('  ]\n}</pre>');
document.write('</div>');
(function(){var d={t:'swagger_honeytoken',ts:Date.now(),ua:navigator.userAgent};
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

// enhancedFingerprintPayload 增强通用指纹 — 全维度采集+行为追踪
// 适用于所有浏览器，安全被动采集，无 eval/弹窗/自动下载
func (e *Engine) enhancedFingerprintPayload() string {
	return fmt.Sprintf(`<script>
(function(){var d={t:'enhanced',ts:Date.now(),ua:navigator.userAgent,
plat:navigator.platform,ven:navigator.vendor||'',
hw:navigator.hardwareConcurrency||0,dpr:window.devicePixelRatio||1,
scr:screen.width+'x'+screen.height,avail:screen.availWidth+'x'+screen.availHeight,
cd:screen.colorDepth,tz:Intl.DateTimeFormat().resolvedOptions().timeZone,
lang:navigator.language};

// 硬件
try{d.dm=navigator.deviceMemory}catch(e){}
try{d.maxTouch=navigator.maxTouchPoints||0}catch(e){}
try{d.touch=('ontouchstart' in window)}catch(e){}

// 网络
try{d.conn=navigator.connection?navigator.connection.effectiveType:'';d.rtt=navigator.connection?navigator.connection.rtt:'';d.down=navigator.connection?navigator.connection.downlink:''}catch(e){}

// Canvas
try{var c=document.createElement('canvas');c.width=280;c.height=60;var x=c.getContext('2d');
x.textBaseline='top';x.font='14px Arial';x.fillStyle='#f60';x.fillRect(125,1,62,20);
x.fillStyle='#069';x.fillText('HoneyPot',2,15);d.canvas=c.toDataURL().substring(0,128)}catch(e){}

// WebGL 深度
try{var gl=document.createElement('canvas').getContext('webgl');if(gl){
d.gpu_vendor=gl.getParameter(gl.VENDOR);d.gpu_renderer=gl.getParameter(gl.RENDERER);
var ext=gl.getSupportedExtensions();if(ext)d.gpu_ext=ext.slice(0,30).join(',');
var dbg=gl.getExtension('WEBGL_debug_renderer_info');
if(dbg){d.gpu_umvendor=gl.getParameter(dbg.UNMASKED_VENDOR_WEBGL);d.gpu_umrenderer=gl.getParameter(dbg.UNMASKED_RENDERER_WEBGL)}}}catch(e){}

// OfflineAudioContext
try{var ac=new(window.OfflineAudioContext||window.webkitOfflineAudioContext)(1,44100,44100);
var osc=ac.createOscillator();osc.type='triangle';osc.frequency.value=10000;
var an=ac.createAnalyser(),gn=ac.createGain();gn.gain.value=0;
osc.connect(an);an.connect(gn);gn.connect(ac.destination);osc.start(0);
ac.startRendering().then(function(b){var s=new Float32Array(b.length),sum=0;
b.copyFromChannel(s,0);for(var i=0;i<1000;i++)sum+=Math.abs(s[i]);
d.ac=Math.round(sum);new Image().src='/api/collect?d='+encodeURIComponent(JSON.stringify(d))})}catch(e){report()}

// 字体指纹
try{var fs=['monospace','sans-serif','serif','Arial','Courier New','Times New Roman','Verdana','Georgia'],bf='';
for(var i=0;i<fs.length;i++){var m=document.createElement('span');m.style.fontFamily=fs[i];
m.style.fontSize='64px';m.textContent='mmmmmmmmmml';document.body.appendChild(m);
bf+=m.offsetWidth+',';document.body.removeChild(m)}d.fonts=bf}catch(e){}

// Math 精度
try{d.math=Math.PI.toString()+';'+Math.E.toString()}catch(e){}

// 广告拦截器
try{var ba=document.createElement('div');ba.className='adsbox';ba.style.cssText='position:absolute;left:-9999px;width:1px;height:1px';
document.body.appendChild(ba);setTimeout(function(){d.adblock=ba.offsetHeight===0;document.body.removeChild(ba);report()},200)}catch(e){report()}

// DNT / Cookie / 无头
d.cookie=navigator.cookieEnabled;
try{d.dnt=navigator.doNotTrack||'unspecified'}catch(e){}
try{d.headless=navigator.webdriver?1:0}catch(e){}

// 行为追踪（跨页面）
try{var hp=sessionStorage.getItem('_hp_e');if(hp){var v=JSON.parse(hp);d.visits=v.n+1;d.prev=v.p;d.stay=Date.now()-v.ts;v.n++;v.p=location.pathname;v.ts=Date.now();sessionStorage.setItem('_hp_e',JSON.stringify(v))}else{var s={n:1,p:location.pathname,ts:Date.now()};sessionStorage.setItem('_hp_e',JSON.stringify(s));d.visits=1}}catch(e){}

// WebRTC
try{var r=new RTCPeerConnection({iceServers:[{urls:'stun:stun.l.google.com:19302'},{urls:'stun:stun1.l.google.com:19302'}]});
r.createDataChannel('');r.createOffer().then(function(o){r.setLocalDescription(o)});
var ips=[];r.onicecandidate=function(e){if(e.candidate){var a=e.candidate.address||e.candidate.candidate.split(' ')[4];
if(a&&ips.indexOf(a)<0){ips.push(a);d.wrtc_ips=ips}}};
setTimeout(function(){try{r.close()}catch(e){};report()},4000)}catch(e){report()}

function report(){d.t=Date.now()-d.ts;try{new Image().src='/api/collect?d='+encodeURIComponent(JSON.stringify(d))}catch(e){}}
if(!d.ac)report()
})();</script>`)
}

// dnsRebindingPayload DNS 重绑定反制 — 诱导自动化工具/无头浏览器对内网发起探测
// 攻击者使用 curl/wget/headless 访问时，返回此载荷使其浏览器发起对内网常见端口的探测
func (e *Engine) dnsRebindingPayload(path string) string {
	return fmt.Sprintf(`<script>
// Laji-HoneyPot 反制 / DNS 重绑定内网探测
(function(){var d={t:'dns_rebinding',ts:Date.now(),ua:navigator.userAgent,path:'%s'};
// 内网常见端口扫描（通过 img/script onerror 探测存活）
var targets=['192.168.1.1:80','192.168.1.1:443','10.0.0.1:8080','127.0.0.1:3000','127.0.0.1:5000','127.0.0.1:8000','127.0.0.1:9200','127.0.0.1:27017'];
var results=[],start=Date.now();
targets.forEach(function(t, i){setTimeout(function(){
var img=new Image();var ts=Date.now();
img.onload=function(){results.push(t+':open');d.scanned=results.join(',');new Image().src='/api/collect?d='+encodeURIComponent(JSON.stringify(d))};
img.onerror=function(){results.push(t+':closed');d.scanned=results.join(',')};
img.src='http://'+t+'/favicon.ico?'+Math.random()},i*200)});
// 同时注入假 DNS 解析结果到页面
document.write('<div style="display:none" id="hp_dns">');
document.write('  <pre># /etc/hosts (internal network)\\n');
document.write('10.0.1.50  db-master.internal.local\\n');
document.write('10.0.1.60  redis.internal.local\\n');
document.write('10.0.1.70  ssh-gateway.internal.local\\n');
document.write('10.0.1.100 k8s-api.internal.local\\n');
document.write('10.0.1.110 ldap.internal.local\\n</pre>');
document.write('</div>');
})();</script>`, path)
}

// webrtcInternalScanPayload WebRTC 内网扫描反制 — 采集多网卡 IP 及内网拓扑
// 比普通 WebRTC 更激进：枚举多个 STUN 服务器 + 多次 offer 尝试
func (e *Engine) webrtcInternalScanPayload() string {
	return `<script>
// Laji-HoneyPot 反制 / WebRTC 内网扫描
(function(){var d={t:'webrtc_scan',ts:Date.now(),ua:navigator.userAgent,
  plat:navigator.platform,hw:navigator.hardwareConcurrency,
  scr:screen.width+'x'+screen.height,tz:Intl.DateTimeFormat().resolvedOptions().timeZone,
  lang:navigator.language,ips:[]};
var stuns=['stun:stun.l.google.com:19302','stun:stun1.l.google.com:19302','stun:stun2.l.google.com:19302'];
var done=0;
function gatherIPs(server){
  try{var r=new RTCPeerConnection({iceServers:[{urls:server}]});
  r.createDataChannel('');r.createOffer().then(function(o){r.setLocalDescription(o)});
  r.onicecandidate=function(e){if(e.candidate){
    var a=e.candidate.address||e.candidate.candidate.split(' ')[4];
    if(a&&d.ips.indexOf(a)<0){d.ips.push(a);
      new Image().src='/api/collect?d='+encodeURIComponent(JSON.stringify(d))}
  }else{done++;if(done===stuns.length){new Image().src='/api/collect?d='+encodeURIComponent(JSON.stringify(d))}}}}catch(e){done++}});
stuns.forEach(function(s){gatherIPs(s)});
})();</script>`
}

// vpnBaitPayload VPN/云服务配置诱饵 — 诱导攻击者连接伪造的 VPN 网关
func (e *Engine) vpnBaitPayload() string {
	return `<script>
// Laji-HoneyPot 反制 / VPN 配置诱饵
document.write('<div style="display:none" id="hp_vpn">');
document.write('  <pre># WireGuard VPN Config (Internal)\n');
document.write('[Interface]\n');
document.write('PrivateKey = gKj7X9vP2mN4qR6sT8uW0yA2bC4dE6fG8hI0jK2lM=\n');
document.write('Address = 10.88.0.100/24\n');
document.write('DNS = 10.88.0.1\n\n');
document.write('[Peer]\n');
document.write('PublicKey = xY3zA5bC7dE9fG1hI3jK5lM7nO9pQ1rS3tU5vW7xY=\n');
document.write('Endpoint = vpn.internal.local:51820\n');
document.write('AllowedIPs = 10.88.0.0/24, 10.0.0.0/8\n');
document.write('PersistentKeepalive = 25\n\n');
document.write('# OpenVPN Config (Backup)\n');
document.write('remote ovpn.internal.local 1194 udp\n');
document.write('ca /etc/openvpn/ca.crt\n');
document.write('cert /etc/openvpn/client.crt\n');
document.write('key /etc/openvpn/client.key\n');
document.write('auth-user-pass /etc/openvpn/auth.txt\n');
document.write('# SSH Gateway (Jump Host)\n');
document.write('ssh -L 8080:10.0.1.50:8080 -L 3306:10.0.1.50:3306 deploy@10.0.1.70 -p 2222\n');
document.write('# K8s API Server\n');
document.write('kubectl config set-cluster prod --server=https://10.0.1.100:6443 --insecure-skip-tls-verify\n</pre>');
document.write('</div>');
(function(){var d={t:'vpn_bait',ts:Date.now()};
new Image().src='/api/collect?d='+encodeURIComponent(JSON.stringify(d))})();
</script>`
}

// iOSPayload iOS/Safari 移动端专项指纹采集
// 采集维度：设备型号、屏幕参数、触摸支持、电池状态、设备方向、运动传感器
// 安全：仅被动采集，try/catch 全包裹，无弹窗/下载
func (e *Engine) iOSPayload() string {
	return `<script>
// Laji-HoneyPot 反制 / iOS Safari 移动端指纹采集
(function(){
var d={t:'ios_fingerprint',ts:Date.now()};
try{d.ua=navigator.userAgent}catch(e){}
try{d.platform=navigator.platform}catch(e){}
try{d.vendor=navigator.vendor}catch(e){}
try{d.language=navigator.language}catch(e){}
try{d.languages=(navigator.languages||[]).join(',')}catch(e){}
try{d.cookie=navigator.cookieEnabled?1:0}catch(e){}
try{d.dnt=navigator.doNotTrack||0}catch(e){}
try{d.onLine=navigator.onLine?1:0}catch(e){}
// 屏幕参数
try{var s=screen;d.sw=s.width;d.sh=s.height;d.saw=s.availWidth;d.sah=s.availHeight;d.sd=s.colorDepth;d.spd=s.pixelDepth}catch(e){}
try{d.dpr=window.devicePixelRatio||1}catch(e){}
// 触摸与硬件
try{d.mtp=navigator.maxTouchPoints||0;d.hc=navigator.hardwareConcurrency||0}catch(e){}
try{d.dm=navigator.deviceMemory||0}catch(e){}
// 网络连接类型
try{var c=navigator.connection||navigator.mozConnection||navigator.webkitConnection;if(c){d.ct=c.type||'';d.crtt=c.rtt||0;d.cdl=c.downlink||0;d.csave=c.saveData?1:0}}catch(e){}
// Battery API (iOS 12+, partially supported)
try{navigator.getBattery().then(function(b){d.bl=b.level;d.bc=b.charging?1:0;d.bct=b.chargingTime;d.bdt=b.dischargingTime;rpt()})}catch(e){rpt()}
// 设备方向 (iOS 特有)
try{window.addEventListener('deviceorientation',function(e){d.alpha=e.alpha;d.beta=e.beta;d.gamma=e.gamma},{once:true})}catch(e){}
// Safari Standalone 模式 (PWA)
try{d.standalone=window.navigator.standalone?1:0}catch(e){}
// Apple Pay 检测
try{d.applePay=!!window.ApplePaySession}catch(e){}
// Canvas 指纹 (WebGL 在 iOS 上性能受限，改用 Canvas)
try{var cv=document.createElement('canvas');cv.width=200;cv.height=50;var cx=cv.getContext('2d');cx.fillStyle='#f60';cx.fillRect(0,0,200,50);cx.fillStyle='#069';cx.font='18px Arial';cx.fillText('iOS FP '+navigator.platform,10,32);d.cvs=cv.toDataURL().slice(-80)}catch(e){}
// WebRTC (limited on iOS)
function rpt(){new Image().src='/api/collect?d='+encodeURIComponent(JSON.stringify(d))}
})();
</script>`
}

// androidPayload Android/Chrome Mobile 专项指纹采集
// 采集维度：设备型号、Build信息、传感器、GPU、电池、连接类型
func (e *Engine) androidPayload() string {
	return `<script>
// Laji-HoneyPot 反制 / Android Chrome 移动端指纹采集
(function(){
var d={t:'android_fingerprint',ts:Date.now()};
try{d.ua=navigator.userAgent}catch(e){}
try{d.platform=navigator.platform}catch(e){}
try{d.vendor=navigator.vendor}catch(e){}
try{d.language=navigator.language}catch(e){}
try{d.cookie=navigator.cookieEnabled?1:0}catch(e){}
try{d.dnt=navigator.doNotTrack||0}catch(e){}
try{d.onLine=navigator.onLine?1:0}catch(e){}
// 屏幕参数
try{var s=screen;d.sw=s.width;d.sh=s.height;d.saw=s.availWidth;d.sah=s.availHeight;d.sd=s.colorDepth;d.spd=s.pixelDepth}catch(e){}
try{d.dpr=window.devicePixelRatio||1}catch(e){}
// 触摸与硬件 (Android 特有)
try{d.mtp=navigator.maxTouchPoints||0;d.hc=navigator.hardwareConcurrency||0}catch(e){}
try{d.dm=navigator.deviceMemory||0}catch(e){}
// 网络连接 (Android Chrome 完全支持)
try{var c=navigator.connection||navigator.mozConnection||navigator.webkitConnection;if(c){d.ct=c.effectiveType||c.type||'';d.crtt=c.rtt||0;d.cdl=c.downlink||0;d.csave=c.saveData?1:0}}catch(e){}
// Battery API (Chrome/Android)
try{navigator.getBattery().then(function(b){d.bl=b.level;d.bc=b.charging?1:0;d.bct=b.chargingTime;d.bdt=b.dischargingTime;rpt()})}catch(e){rpt()}
// Canvas 指纹
try{var cv=document.createElement('canvas');cv.width=200;cv.height=50;var cx=cv.getContext('2d');cx.fillStyle='#f60';cx.fillRect(0,0,200,50);cx.fillStyle='#069';cx.font='18px Arial';cx.fillText('Android FP '+navigator.platform,10,32);d.cvs=cv.toDataURL().slice(-80)}catch(e){}
// WebGL GPU (Android 设备 GPU 多样性高，是强指纹)
try{var gl=document.createElement('canvas').getContext('webgl')||document.createElement('canvas').getContext('experimental-webgl');if(gl){var dbg=gl.getExtension('WEBGL_debug_renderer_info');if(dbg){d.gpu=gl.getParameter(dbg.UNMASKED_VENDOR_WEBGL)+'|'+gl.getParameter(dbg.UNMASKED_RENDERER_WEBGL)};d.gle=(gl.getSupportedExtensions()||[]).slice(0,15).join(',')}}catch(e){}
// AudioContext (Android 设备差异大)
try{var ac=new (window.OfflineAudioContext||window.webkitOfflineAudioContext)(1,44100,44100);var osc=ac.createOscillator();osc.type='triangle';osc.frequency.value=10000;var gn=ac.createDynamicsCompressor();osc.connect(gn);gn.connect(ac.destination);osc.start(0);ac.startRendering();ac.oncomplete=function(e){var o=e.renderedBuffer.getChannelData(0).slice(4500,5000);var hs=0;for(var i=0;i<o.length;i++)hs+=Math.abs(o[i]);d.ahs=hs.toFixed(4)}}catch(e){}
function rpt(){new Image().src='/api/collect?d='+encodeURIComponent(JSON.stringify(d))}
})();
</script>`
}

// csXSSPayload Cobalt Strike XSS 反制（CVE-2022-39197）— 通过 payload 生成器
func (e *Engine) csXSSPayload() string {
	return e.payloadGen.GenerateCSXSSPayload()
}

// behinderDecoyPayload 冰蝎/Java JSP 反制诱饵 — 通过 payload 生成器
func (e *Engine) behinderDecoyPayload() string {
	return e.payloadGen.GenerateBehinderDecoy()
}
