import { useState, useEffect } from 'react';
import DashboardPanel from './components/DashboardPanel';
import TopologyGraph from './components/TopologyGraph';
import AttackPanel from './components/AttackPanel';
import FingerprintPanel from './components/FingerprintPanel';
import CountermeasurePanel from './components/CountermeasurePanel';
import AssetLedger from './components/AssetLedger';
import OpsPanel from './components/OpsPanel';
import AttackerProfilePanel from './components/AttackerProfilePanel';
import ClusterPanel from './components/ClusterPanel';
import AgentDeployPanel from './components/AgentDeployPanel';
import BaitLinkagePanel from './components/BaitLinkagePanel';
import UpgradePanel from './components/UpgradePanel';
import StatusBar from './components/StatusBar';
import LoginPage from './components/LoginPage';
import ChangePasswordPage from './components/ChangePasswordPage';
import { isLoggedIn, logout } from './api';
import './App.css';

type Tab = 'dashboard' | 'topology' | 'attacks' | 'fingerprints' | 'countermeasures' | 'assets' | 'cluster' | 'agent' | 'ops' | 'profiles' | 'linkages' | 'upgrade';

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
  { key: 'cluster', label: '集群管理', icon: '' },
  { key: 'agent', label: 'Agent部署', icon: '' },
  { key: 'ops', label: '运维管理', icon: '' },
  { key: 'profiles', label: '攻击者画像', icon: '' },
  { key: 'linkages', label: '蜜饵联动', icon: '' },
  { key: 'upgrade', label: 'Agent升级', icon: '' },
];

export default function App() {
  const [activeTab, setActiveTab] = useState<Tab>('dashboard');
  const [authenticated, setAuthenticated] = useState(isLoggedIn());
  const [mustChangePassword, setMustChangePassword] = useState(false);
  const [clusterNodes, setClusterNodes] = useState<Array<{ node_id: string; online: boolean }>>([]);
  const [preselectedNode, setPreselectedNode] = useState<string | undefined>();

  // 定期检查令牌状态
  useEffect(() => {
    const interval = setInterval(() => {
      setAuthenticated(isLoggedIn());
    }, 10000);
    return () => clearInterval(interval);
  }, []);

  const handleLoginSuccess = (mustChange?: boolean) => {
    setAuthenticated(true);
    if (mustChange) {
      setMustChangePassword(true);
    }
  };

  const handlePasswordChanged = () => {
    setMustChangePassword(false);
  };

  const handleLogout = async () => {
    await logout();
    setAuthenticated(false);
    setMustChangePassword(false);
    setActiveTab('dashboard');
  };

  const handleNavigateTab = (tab: string, nodeId?: string) => {
    setPreselectedNode(nodeId);
    setActiveTab(tab as Tab);
  };

  if (!authenticated) {
    return <LoginPage onLoginSuccess={handleLoginSuccess} />;
  }

  // 首次登录强制修改密码
  if (mustChangePassword) {
    return <ChangePasswordPage onPasswordChanged={handlePasswordChanged} onLogout={handleLogout} />;
  }

  return (
    <div className="app">
      <header className="app-header">
        <div className="header-left">
          <h1 className="app-title">Laji-HoneyPot</h1>
          <span className="app-version">v0.19.0</span>
        </div>
        <div className="header-right">
          <span className="status-indicator status-online" />
          <span className="status-text">运行中</span>
          <button className="btn-logout" onClick={handleLogout} title="退出登录">
            退出
          </button>
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
        {activeTab === 'cluster' && (
          <ClusterPanel
            onNodesLoaded={setClusterNodes}
            onNavigateTab={handleNavigateTab}
          />
        )}
        {activeTab === 'agent' && <AgentDeployPanel />}
        {activeTab === 'ops' && <OpsPanel />}
        {activeTab === 'profiles' && <AttackerProfilePanel />}
        {activeTab === 'linkages' && <BaitLinkagePanel />}
        {activeTab === 'upgrade' && (
          <UpgradePanel nodes={clusterNodes} preselectedNode={preselectedNode} />
        )}
      </main>

      <StatusBar />
    </div>
  );
}
