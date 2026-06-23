import { useState } from 'react';
import DashboardPanel from './components/DashboardPanel';
import TopologyGraph from './components/TopologyGraph';
import AttackPanel from './components/AttackPanel';
import FingerprintPanel from './components/FingerprintPanel';
import CountermeasurePanel from './components/CountermeasurePanel';
import AssetLedger from './components/AssetLedger';
import OpsPanel from './components/OpsPanel';
import './App.css';

type Tab = 'dashboard' | 'topology' | 'attacks' | 'fingerprints' | 'countermeasures' | 'assets' | 'ops';

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
  { key: 'countermeasures', label: '反制日志', icon: '' },
  { key: 'assets', label: '资产台账', icon: '' },
  { key: 'ops', label: '运维管理', icon: '' },
];

export default function App() {
  const [activeTab, setActiveTab] = useState<Tab>('dashboard');

  return (
    <div className="app">
      <header className="app-header">
        <div className="header-left">
          <h1 className="app-title">Laji-HoneyPot</h1>
          <span className="app-version">v0.7.0</span>
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
        {activeTab === 'countermeasures' && <CountermeasurePanel />}
        {activeTab === 'assets' && <AssetLedger />}
        {activeTab === 'ops' && <OpsPanel />}
      </main>
    </div>
  );
}
