import { useState } from 'react'
import './App.css'

type Tab = 'dashboard' | 'honeypot' | 'traceability' | 'ops'

function App() {
  const [activeTab, setActiveTab] = useState<Tab>('dashboard')

  return (
    <div className="app">
      <header className="app-header">
        <h1>Laji-HoneyPot</h1>
        <span className="version">v0.1.0</span>
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
  return (
    <div className="panel">
      <h2>仪表盘</h2>
      <div className="stats-grid">
        <div className="stat-card">
          <h3>活跃蜜罐</h3>
          <p className="stat-value">4</p>
        </div>
        <div className="stat-card">
          <h3>今日连接</h3>
          <p className="stat-value">--</p>
        </div>
        <div className="stat-card">
          <h3>已识别攻击者</h3>
          <p className="stat-value">--</p>
        </div>
        <div className="stat-card">
          <h3>反制成功</h3>
          <p className="stat-value">--</p>
        </div>
      </div>
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
  return (
    <div className="panel">
      <h2>溯源反制</h2>
      <div className="section">
        <h3>漏洞数据库（预置 7 条）</h3>
        <table>
          <thead>
            <tr><th>ID</th><th>目标工具</th><th>严重程度</th><th>类型</th></tr>
          </thead>
          <tbody>
            <tr><td>CVE-2022-39197</td><td>Cobalt Strike</td><td className="severity-critical">严重</td><td>红队工具</td></tr>
            <tr><td>BD-2023-001</td><td>冰蝎</td><td className="severity-high">高危</td><td>红队工具</td></tr>
            <tr><td>BS-2024-001</td><td>Burp Suite</td><td className="severity-medium">中危</td><td>红队工具</td></tr>
            <tr><td>CVE-2024-0519</td><td>Chrome</td><td className="severity-critical">严重</td><td>浏览器</td></tr>
            <tr><td>CH-2024-001</td><td>Chrome/Firefox</td><td className="severity-medium">中危</td><td>浏览器</td></tr>
            <tr><td>FF-2024-001</td><td>Firefox</td><td className="severity-low">低危</td><td>浏览器</td></tr>
            <tr><td>CVE-2023-32784</td><td>SQLMap</td><td className="severity-low">低危</td><td>红队工具</td></tr>
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
        <h3>竞品调研</h3>
        <p>自动检索 GitHub topic:honeypot，按 Stars 排序，标注溯源能力、协议支持、容器化。</p>
      </div>
    </div>
  )
}

export default App
