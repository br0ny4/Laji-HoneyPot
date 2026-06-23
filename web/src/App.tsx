import { useState } from 'react';
import DashboardPanel from './components/DashboardPanel';
import TopologyGraph from './components/TopologyGraph';
import AttackPanel from './components/AttackPanel';
import FingerprintPanel from './components/FingerprintPanel';
import './App.css';

type Tab = 'dashboard' | 'topology' | 'attacks' | 'fingerprints' | 'ops';

interface TabDef {
  key: Tab;
  label: string;
  icon: string;
}

const tabs: TabDef[] = [
  { key: 'dashboard', label: '仪表盘', icon: '' },
  { key: 'topology', label: '攻击拓扑', icon: '' },
  { key: 'attacks', label: '攻击事件', icon: '' },
  { key: 'fingerprints', label: '溯源反制', icon: '' },
  { key: 'ops', label: '运维管理', icon: '' },
];

export default function App() {
  const [activeTab, setActiveTab] = useState<Tab>('dashboard');

  return (
    <div className="app">
      <header className="app-header">
        <div className="header-left">
          <h1 className="app-title">Laji-HoneyPot</h1>
          <span className="app-version">v0.5.0</span>
        </div>
        <div className="header-right">
          <span className="status-indicator status-online" />
          <span className="status-text">运行中</span>
        </div>
      </header>

      <nav className="tab-nav">
        {tabs.map((tab) => (
          <button
            key={tab.key}
            className={`tab-btn ${activeTab === tab.key ? 'active' : ''}`}
            onClick={() => setActiveTab(tab.key)}
          >
            {tab.icon && <span className="tab-icon">{tab.icon}</span>}
            {tab.label}
          </button>
        ))}
      </nav>

      <main className="content">
        {activeTab === 'dashboard' && <DashboardPanel />}
        {activeTab === 'topology' && <TopologyGraph />}
        {activeTab === 'attacks' && <AttackPanel />}
        {activeTab === 'fingerprints' && <FingerprintPanel />}
        {activeTab === 'ops' && <OpsPanel />}
      </main>
    </div>
  );
}

function OpsPanel() {
  return (
    <div className="ops-panel">
      <h2 className="section-title">运维管理</h2>

      <div className="panel-row">
        <div className="panel-half">
          <h3 className="section-title">系统信息</h3>
          <table className="data-table">
            <tbody>
              <tr><td>版本</td><td>v0.5.0</td></tr>
              <tr><td>后端框架</td><td>Go 1.22+</td></tr>
              <tr><td>数据库</td><td>SQLite (WAL模式)</td></tr>
              <tr><td>蜜罐服务</td><td>HTTP/MySQL/Redis/SSH/FTP/LDAP/DNS/SMB/RDP</td></tr>
              <tr><td>SSE 实时推送</td><td><span className="status-badge status-protected">已启用</span></td></tr>
              <tr><td>NVD 漏洞库</td><td><span className="status-badge status-protected">30条+</span></td></tr>
              <tr><td>面包屑路径</td><td>19条(含SpringBoot/Swagger/JSP诱饵)</td></tr>
            </tbody>
          </table>
        </div>

        <div className="panel-half">
          <h3 className="section-title">部署指南</h3>
          <div className="ops-instructions">
            <div className="ops-step">
              <span className="ops-step-num">1</span>
              <div>
                <strong>启动后端</strong>
                <code className="ops-code">go run ./cmd/honeypot</code>
              </div>
            </div>
            <div className="ops-step">
              <span className="ops-step-num">2</span>
              <div>
                <strong>启动前端</strong>
                <code className="ops-code">cd web && npm run dev</code>
              </div>
            </div>
            <div className="ops-step">
              <span className="ops-step-num">3</span>
              <div>
                <strong>访问管理端</strong>
                <code className="ops-code">http://localhost:3000</code>
              </div>
            </div>
            <div className="ops-step">
              <span className="ops-step-num">4</span>
              <div>
                <strong>构建生产版本</strong>
                <code className="ops-code">cd web && npm run build</code>
              </div>
            </div>
          </div>
        </div>
      </div>

      <div className="panel-row">
        <div className="panel-half">
          <h3 className="section-title">性能指标</h3>
          <table className="data-table">
            <tbody>
              <tr><td>API 响应时间</td><td>&lt; 50ms</td></tr>
              <tr><td>拓扑图渲染</td><td>&lt; 500ms (含G6布局)</td></tr>
              <tr><td>SSE 推送延迟</td><td>&lt; 100ms</td></tr>
              <tr><td>速率限制</td><td>100 req/s (Token Bucket)</td></tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
