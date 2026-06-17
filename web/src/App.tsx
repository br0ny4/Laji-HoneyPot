import { useState, useEffect } from 'react'
import './App.css'

type Tab = 'dashboard' | 'honeypot' | 'traceability' | 'ops'

const API_BASE = '/api'

interface Stats {
  active_services: number
  today_conns: number
  attackers: number
  counter_hits: number
}

interface Connection {
  id: number
  timestamp: string
  remote_ip: string
  port: number
  service: string
  user_agent: string
}

interface AttackEvent {
  id: number
  timestamp: string
  remote_ip: string
  path: string
  tool_name: string
  payload: string
}

interface VulnEntry {
  id: string
  tool: string
  title: string
  description: string
  severity: string
  cve: string
  exploit: string
}

function App() {
  const [activeTab, setActiveTab] = useState<Tab>('dashboard')

  return (
    <div className="app">
      <header className="app-header">
        <h1>Laji-HoneyPot</h1>
        <span className="version">v0.2.0</span>
      </header>

      <nav className="tab-nav">
        {[
          { key: 'dashboard', label: '仪表盘' },
          { key: 'honeypot', label: '蜜罐引擎' },
          { key: 'traceability', label: '溯源反制' },
          { key: 'ops', label: '运维管理' },
        ].map(tab => (
          <button
            key={tab.key}
            className={`tab-btn ${activeTab === tab.key ? 'active' : ''}`}
            onClick={() => setActiveTab(tab.key as Tab)}
          >
            {tab.label}
          </button>
        ))}
      </nav>

      <main className="content">
        {activeTab === 'dashboard' && <Dashboard />}
        {activeTab === 'honeypot' && <HoneypotPanel />}
        {activeTab === 'traceability' && <TraceabilityPanel />}
        {activeTab === 'ops' && <OpsPanel />}
      </main>
    </div>
  )
}

function Dashboard() {
  const [stats, setStats] = useState<Stats>({ active_services: 4, today_conns: 0, attackers: 0, counter_hits: 0 })
  const [connections, setConnections] = useState<Connection[]>([])

  useEffect(() => {
    fetch(`${API_BASE}/stats`)
      .then(r => r.json())
      .then(setStats)
      .catch(() => {})

    fetch(`${API_BASE}/connections?limit=10`)
      .then(r => r.json())
      .then(d => setConnections(d.connections || []))
      .catch(() => {})
  }, [])

  return (
    <div className="panel">
      <h2>仪表盘</h2>
      <div className="stats-grid">
        <div className="stat-card">
          <h3>活跃蜜罐</h3>
          <p className="stat-value">{stats.active_services}</p>
        </div>
        <div className="stat-card">
          <h3>今日连接</h3>
          <p className="stat-value">{stats.today_conns}</p>
        </div>
        <div className="stat-card">
          <h3>已识别攻击者</h3>
          <p className="stat-value">{stats.attackers}</p>
        </div>
        <div className="stat-card">
          <h3>反制事件</h3>
          <p className="stat-value">{stats.counter_hits}</p>
        </div>
      </div>

      {connections.length > 0 && (
        <div className="section">
          <h3>最近连接</h3>
          <table>
            <thead>
              <tr><th>时间</th><th>来源 IP</th><th>端口</th><th>服务</th><th>User-Agent</th></tr>
            </thead>
            <tbody>
              {connections.map(c => (
                <tr key={c.id}>
                  <td>{new Date(c.timestamp).toLocaleTimeString()}</td>
                  <td>{c.remote_ip}</td>
                  <td>{c.port}</td>
                  <td>{c.service}</td>
                  <td title={c.user_agent}>{(c.user_agent || '').substring(0, 40)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}

function HoneypotPanel() {
  return (
    <div className="panel">
      <h2>蜜罐引擎</h2>
      <table>
        <thead>
          <tr><th>服务</th><th>端口</th><th>状态</th><th>指纹</th><th>面包屑</th></tr>
        </thead>
        <tbody>
          <tr><td>HTTP</td><td>8081</td><td className="status-online">运行中</td><td>nginx/1.24.0</td><td>10 路径</td></tr>
          <tr><td>MySQL</td><td>3306</td><td className="status-online">运行中</td><td>MySQL 8.0.35</td><td>-</td></tr>
          <tr><td>Redis</td><td>6379</td><td className="status-online">运行中</td><td>Redis 6.2.13</td><td>-</td></tr>
          <tr><td>SSH</td><td>2222</td><td className="status-online">运行中</td><td>OpenSSH 9.3</td><td>-</td></tr>
        </tbody>
      </table>
    </div>
  )
}

function TraceabilityPanel() {
  const [vulns, setVulns] = useState<VulnEntry[]>([])
  const [attacks, setAttacks] = useState<AttackEvent[]>([])

  useEffect(() => {
    fetch(`${API_BASE}/vulns`)
      .then(r => r.json())
      .then(d => setVulns(d.vulns || []))
      .catch(() => {})

    fetch(`${API_BASE}/attacks?limit=20`)
      .then(r => r.json())
      .then(d => setAttacks(d.attacks || []))
      .catch(() => {})
  }, [])

  const sevClass = (s: string) => {
    switch (s) {
      case 'critical': return 'severity-critical'
      case 'high': return 'severity-high'
      case 'medium': return 'severity-medium'
      default: return 'severity-low'
    }
  }

  const toolTag = (tool: string) => {
    const browsers = ['chrome', 'firefox', 'safari', 'edge']
    return browsers.includes(tool) ? '浏览器' : '红队工具'
  }

  return (
    <div className="panel">
      <h2>溯源反制</h2>

      {attacks.length > 0 && (
        <div className="section">
          <h3>面包屑触发事件（{attacks.length}）</h3>
          <table>
            <thead>
              <tr><th>时间</th><th>来源 IP</th><th>触发路径</th><th>工具</th></tr>
            </thead>
            <tbody>
              {attacks.map(a => (
                <tr key={a.id}>
                  <td>{new Date(a.timestamp).toLocaleTimeString()}</td>
                  <td>{a.remote_ip}</td>
                  <td className="severity-critical">{a.path}</td>
                  <td>{a.tool_name}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      <div className="section">
        <h3>漏洞数据库（{vulns.length} 条）</h3>
        <table>
          <thead>
            <tr><th>ID</th><th>目标工具</th><th>严重程度</th><th>类型</th></tr>
          </thead>
          <tbody>
            {vulns.map(v => (
              <tr key={v.id}>
                <td>{v.id}</td>
                <td>{v.tool}</td>
                <td className={sevClass(v.severity)}>{v.severity}</td>
                <td>{toolTag(v.tool)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <div className="section">
        <h3>反制能力</h3>
        <table>
          <thead>
            <tr><th>触发条件</th><th>反制手段</th><th>采集信息</th></tr>
          </thead>
          <tbody>
            <tr><td>面包屑路径访问</td><td>JS 浏览器指纹采集</td><td>Canvas、WebGL、WebRTC 内网 IP</td></tr>
            <tr><td>Cobalt Strike Beacon</td><td>CVE-2022-39197 XSS 回击</td><td>CS 团队服务器信息</td></tr>
            <tr><td>冰蝎 WebShell 连接</td><td>Java JSP 反制 Payload</td><td>主机名、OS、用户名、Java 版本</td></tr>
            <tr><td>Burp Collaborator 请求</td><td>DNSLOG + WebRTC 泄露</td><td>内网 IP、浏览器指纹</td></tr>
          </tbody>
        </table>
      </div>
    </div>
  )
}

function OpsPanel() {
  return (
    <div className="panel">
      <h2>运维管理</h2>
      <div className="section">
        <h3>CI/CD</h3>
        <table>
          <thead>
            <tr><th>Pipeline</th><th>触发条件</th><th>操作</th></tr>
          </thead>
          <tbody>
            <tr><td>CI</td><td>push: main, develop</td><td>lint → test → build (linux/darwin × amd64/arm64)</td></tr>
            <tr><td>Release</td><td>tag: v*</td><td>build → GitHub Release + artifacts</td></tr>
          </tbody>
        </table>
      </div>
      <div className="section">
        <h3>数据持久化</h3>
        <p>SQLite 存储连接日志、攻击事件、指纹数据，数据目录 ./data</p>
      </div>
    </div>
  )
}

export default App
