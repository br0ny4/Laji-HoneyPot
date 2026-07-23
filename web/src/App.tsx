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
import EvidencePanel from './components/EvidencePanel';
import StatusBar from './components/StatusBar';
import LoginPage from './components/LoginPage';
import ChangePasswordPage from './components/ChangePasswordPage';
import { isLoggedIn, logout, changeOwnPassword } from './api';
import './App.css';

type Tab = 'dashboard' | 'topology' | 'attacks' | 'fingerprints' | 'countermeasures' | 'assets' | 'cluster' | 'agent' | 'ops' | 'profiles' | 'linkages' | 'upgrade' | 'evidence';

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
  { key: 'evidence', label: '证据收集', icon: '' },
];

export default function App() {
  const [activeTab, setActiveTab] = useState<Tab>('dashboard');
  const [authenticated, setAuthenticated] = useState(isLoggedIn());
  const [mustChangePassword, setMustChangePassword] = useState(false);
  const [clusterNodes, setClusterNodes] = useState<Array<{ node_id: string; online: boolean }>>([]);
  const [preselectedNode, setPreselectedNode] = useState<string | undefined>();

  // 修改密码弹窗
  const [showChangePwd, setShowChangePwd] = useState(false);
  const [oldPwd, setOldPwd] = useState('');
  const [newPwd, setNewPwd] = useState('');
  const [confirmPwd, setConfirmPwd] = useState('');
  const [changePwdErr, setChangePwdErr] = useState('');
  const [changePwdLoading, setChangePwdLoading] = useState(false);
  const [changePwdOk, setChangePwdOk] = useState(false);

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

  const handleChangePassword = async () => {
    setChangePwdErr('');
    if (!oldPwd) { setChangePwdErr('请输入当前密码'); return; }
    if (newPwd.length < 8) { setChangePwdErr('新密码至少8个字符'); return; }
    if (newPwd !== confirmPwd) { setChangePwdErr('两次输入的新密码不一致'); return; }

    setChangePwdLoading(true);
    const result = await changeOwnPassword(oldPwd, newPwd);
    setChangePwdLoading(false);

    if (!result.success) {
      setChangePwdErr(result.error || '密码修改失败');
      return;
    }
    setChangePwdOk(true);
    setTimeout(() => {
      setShowChangePwd(false);
      setChangePwdOk(false);
      setOldPwd('');
      setNewPwd('');
      setConfirmPwd('');
      setChangePwdErr('');
    }, 1500);
  };

  const openChangePwdModal = () => {
    setOldPwd('');
    setNewPwd('');
    setConfirmPwd('');
    setChangePwdErr('');
    setChangePwdOk(false);
    setShowChangePwd(true);
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
          <button className="btn-changepwd" onClick={openChangePwdModal} title="修改密码">
            修改密码
          </button>
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
        {activeTab === 'evidence' && (
          <EvidencePanel />
        )}
      </main>

      {/* 修改密码弹窗 */}
      {showChangePwd && (
        <div className="modal-overlay" onClick={() => setShowChangePwd(false)}>
          <div className="modal-content change-pwd-modal" onClick={e => e.stopPropagation()}>
            <div className="modal-header">
              <h3>修改密码</h3>
              <button className="btn-close" onClick={() => setShowChangePwd(false)}>&times;</button>
            </div>
            <div className="modal-body">
              {changePwdOk ? (
                <div className="change-pwd-success">
                  <span style={{ fontSize: 24, marginBottom: 8 }}>✓</span>
                  <p>密码修改成功</p>
                </div>
              ) : (
                <div className="change-pwd-form">
                  <div className="form-group">
                    <label>当前密码</label>
                    <input
                      type="password"
                      value={oldPwd}
                      onChange={e => setOldPwd(e.target.value)}
                      placeholder="输入当前密码"
                      autoFocus
                    />
                  </div>
                  <div className="form-group">
                    <label>新密码</label>
                    <input
                      type="password"
                      value={newPwd}
                      onChange={e => setNewPwd(e.target.value)}
                      placeholder="至少8位，含大小写字母+数字+特殊字符"
                    />
                  </div>
                  <div className="form-group">
                    <label>确认新密码</label>
                    <input
                      type="password"
                      value={confirmPwd}
                      onChange={e => setConfirmPwd(e.target.value)}
                      placeholder="再次输入新密码"
                      onKeyDown={e => e.key === 'Enter' && handleChangePassword()}
                    />
                  </div>
                  {changePwdErr && (
                    <div className="change-pwd-error">{changePwdErr}</div>
                  )}
                  <button
                    className="btn-generate"
                    onClick={handleChangePassword}
                    disabled={changePwdLoading}
                    style={{ marginTop: 8 }}
                  >
                    {changePwdLoading ? '修改中...' : '确认修改'}
                  </button>
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      <StatusBar />
    </div>
  );
}
