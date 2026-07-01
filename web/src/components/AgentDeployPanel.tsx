import { useState, useEffect } from 'react';

interface ScenarioInfo {
  key: string;
  description: string;
  services: string[];
}

interface AgentDeployRequest {
  manager_addr: string;
  scenario: string;
  custom_services: string[];
  tls_insecure: boolean;
  binary_source: string;
  custom_url: string;
  node_name: string;
}

interface AgentDeployArtifact {
  manager_addr: string;
  scenario: string;
  enabled_svcs: string[];
  config_yaml: string;
  cli_command: string;
  deploy_script: string;
  docker_command: string;
  verify_hint: string;
}

const SCENARIO_LABELS: Record<string, string> = {
  web: 'Web 业务',
  database: '数据库',
  remote_access: '远程访问',
  infrastructure: '基础设施',
  full: '全量部署',
  custom: '自定义',
};

const SOURCE_LABELS: Record<string, string> = {
  release: 'Release 预编译 (推荐)',
  build: '源码编译 (go build)',
  url: '自定义下载 URL',
};

const SERVICE_LABELS: Record<string, string> = {
  http: 'HTTP', mysql: 'MySQL', redis: 'Redis', ssh: 'SSH',
  ftp: 'FTP', ldap: 'LDAP', dns: 'DNS', smb: 'SMB', rdp: 'RDP',
};

const SERVICE_DESC: Record<string, string> = {
  http: 'Web 蜜罐 — 面包屑引流、浏览器指纹采集、反制载荷注入',
  mysql: 'MySQL 蜜罐 — 模拟数据库服务、捕获 SQL 注入/暴力破解',
  redis: 'Redis 蜜罐 — 模拟缓存服务、捕获未授权访问',
  ssh: 'SSH 蜜罐 — 模拟远程登录服务、捕获暴力破解/密钥窃取',
  ftp: 'FTP 蜜罐 — 模拟文件传输服务、捕获匿名登录/文件窃取',
  ldap: 'LDAP 蜜罐 — 模拟目录服务、捕获信息泄露探测',
  dns: 'DNS 蜜罐 — 模拟域名服务、捕获 DNS 隧道/劫持',
  smb: 'SMB 蜜罐 — 模拟文件共享服务、捕获横向移动',
  rdp: 'RDP 蜜罐 — 模拟远程桌面服务、捕获远程登录攻击',
};

export default function AgentDeployPanel() {
  // 表单状态
  const [managerAddr, setManagerAddr] = useState('10.0.0.1:8443');
  const [scenario, setScenario] = useState('web');
  const [customServices, setCustomServices] = useState<string[]>([]);
  const [tlsInsecure, setTlsInsecure] = useState(false);
  const [binarySource, setBinarySource] = useState('release');
  const [customURL, setCustomURL] = useState('');
  const [nodeName, setNodeName] = useState('');

  // 结果状态
  const [artifact, setArtifact] = useState<AgentDeployArtifact | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');

  // 场景元数据
  const [scenarios, setScenarios] = useState<ScenarioInfo[]>([]);
  const [activeTab, setActiveTab] = useState<'config' | 'cli' | 'script'>('cli');

  // 可用的所有服务
  const allServices = ['http', 'mysql', 'redis', 'ssh', 'ftp', 'ldap', 'dns', 'smb', 'rdp'];
  const SERVICE_LABELS_MAP: Record<string, string> = {
    http: 'HTTP', mysql: 'MySQL', redis: 'Redis', ssh: 'SSH',
    ftp: 'FTP', ldap: 'LDAP', dns: 'DNS', smb: 'SMB', rdp: 'RDP',
  };

  // 自动检测管理端地址 (从 URL 推断)
  useEffect(() => {
    const host = window.location.hostname;
    if (host && host !== 'localhost' && host !== '127.0.0.1') {
      setManagerAddr(`${host}:8443`);
    }
    // 加载场景元数据
    fetch('/api/traps/config', {
      headers: { 'X-API-Key': localStorage.getItem('api_key') || 'hp-admin-2024' },
    })
      .then(r => r.json())
      .then(d => {
        if (d.scenarios) setScenarios(d.scenarios);
      })
      .catch(() => {});
  }, []);

  // 根据场景获取预览服务列表
  const getPreviewServices = (): string[] => {
    const found = scenarios.find(s => s.key === scenario);
    return found?.services || [];
  };

  const toggleCustomService = (svc: string) => {
    setCustomServices(prev =>
      prev.includes(svc) ? prev.filter(s => s !== svc) : [...prev, svc]
    );
  };

  const handleGenerate = async () => {
    if (!managerAddr.trim()) {
      setError('请输入管理端地址');
      return;
    }

    setLoading(true);
    setError('');
    setArtifact(null);
    setSuccess('');

    const req: AgentDeployRequest = {
      manager_addr: managerAddr.trim(),
      scenario,
      custom_services: scenario === 'custom' ? customServices : [],
      tls_insecure: tlsInsecure,
      binary_source: binarySource,
      custom_url: customURL.trim(),
      node_name: nodeName.trim(),
    };

    try {
      const resp = await fetch('/api/cluster/agent/generate', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-API-Key': localStorage.getItem('api_key') || 'hp-admin-2024',
        },
        body: JSON.stringify(req),
      });

      if (!resp.ok) {
        const err = await resp.json();
        throw new Error(err.error || `HTTP ${resp.status}`);
      }

      const data: AgentDeployArtifact = await resp.json();
      setArtifact(data);
      setSuccess(`Agent 配置已生成 — 启用 ${data.enabled_svcs.length} 个服务: ${data.enabled_svcs.map(s => SERVICE_LABELS_MAP[s] || s).join(', ')}`);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setLoading(false);
    }
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text).then(() => {
      setSuccess('已复制到剪贴板');
      setTimeout(() => setSuccess(''), 2000);
    });
  };

  return (
    <div className="panel">
      <div className="panel-header">
        <h2>Agent 部署</h2>
        <span className="panel-subtitle">在 Management Node 平台生成 Agent 配置与部署命令，一键部署至目标主机</span>
      </div>

      <div className="panel-body">
        {/* 配置表单 */}
        <div className="deploy-form">
          <div className="form-row">
            <div className="form-group">
              <label>管理端地址</label>
              <input
                type="text"
                value={managerAddr}
                onChange={e => setManagerAddr(e.target.value)}
                placeholder="10.0.0.1:8443"
              />
              <span className="form-hint">Agent 连接的管理节点 TLS 地址（自动填写当前节点 IP）</span>
            </div>
            <div className="form-group">
              <label>节点名称（可选）</label>
              <input
                type="text"
                value={nodeName}
                onChange={e => setNodeName(e.target.value)}
                placeholder="web-node-01"
              />
            </div>
          </div>

          <div className="form-group">
            <label>陷阱场景选配</label>
            <div className="scenario-selector">
              {['web', 'database', 'remote_access', 'infrastructure', 'full', 'custom'].map(s => (
                <button
                  key={s}
                  className={`scenario-btn ${scenario === s ? 'active' : ''}`}
                  onClick={() => setScenario(s)}
                >
                  {SCENARIO_LABELS[s] || s}
                </button>
              ))}
            </div>
            <span className="form-hint">
              {scenario !== 'custom'
                ? `将启用以下服务: ${getPreviewServices().map(s => SERVICE_LABELS_MAP[s] || s).join(', ') || '（无）'}`
                : '请在下方勾选需要启用的服务'}
            </span>
          </div>

          {/* 自定义服务选择 (仅 custom 场景) */}
          {scenario === 'custom' && (
            <div className="form-group">
              <label>自定义服务</label>
              <div className="service-checkboxes">
                {allServices.map(svc => (
                  <label key={svc} className="checkbox-label">
                    <input
                      type="checkbox"
                      checked={customServices.includes(svc)}
                      onChange={() => toggleCustomService(svc)}
                    />
                    {SERVICE_LABELS_MAP[svc] || svc}
                  </label>
                ))}
              </div>
            </div>
          )}

          {/* 配置预览 */}
          {scenarios.length > 0 && (
            <div className="config-preview">
              <h4 className="preview-title">
                配置预览 — {SCENARIO_LABELS[scenario] || scenario}
                <span className="count-badge">{getPreviewServices().length}/{allServices.length}</span>
              </h4>
              <p className="preview-desc">
                {scenarios.find(s => s.key === scenario)?.description || '自定义选配'}
              </p>
              <div className="services-grid">
                {allServices.map(svc => {
                  const enabled = getPreviewServices().includes(svc);
                  return (
                    <div key={svc} className={`service-card ${enabled ? 'enabled' : 'disabled'}`}>
                      <div className="service-header">
                        <span className={`status-dot ${enabled ? 'online' : 'offline'}`} />
                        <span className="service-name">{SERVICE_LABELS[svc] || svc}</span>
                      </div>
                      <p className="service-desc">{SERVICE_DESC[svc] || ''}</p>
                      <span className="service-state">{enabled ? '已启用' : '未启用'}</span>
                    </div>
                  );
                })}
              </div>
              <div className="preview-note">
                以上为陷阱部署预览。未启用服务不会监听端口，不产生资源占用。点击"生成 Agent 部署命令"后，选配将被写入 Agent 的 config.yaml。
              </div>
            </div>
          )}

          <div className="form-row">
            <div className="form-group">
              <label>二进制获取方式</label>
              <select value={binarySource} onChange={e => setBinarySource(e.target.value)}>
                {Object.entries(SOURCE_LABELS).map(([k, v]) => (
                  <option key={k} value={k}>{v}</option>
                ))}
              </select>
            </div>
            {binarySource === 'url' && (
              <div className="form-group">
                <label>自定义下载 URL</label>
                <input
                  type="text"
                  value={customURL}
                  onChange={e => setCustomURL(e.target.value)}
                  placeholder="https://cdn.example.com/honeypot"
                />
              </div>
            )}
          </div>

          <div className="form-group">
            <label className="checkbox-label">
              <input
                type="checkbox"
                checked={tlsInsecure}
                onChange={e => setTlsInsecure(e.target.checked)}
              />
              跳过 TLS 证书验证（仅测试环境使用）
            </label>
          </div>

          <button
            className="btn btn-primary btn-generate"
            onClick={handleGenerate}
            disabled={loading}
          >
            {loading ? '生成中...' : '生成 Agent 部署命令'}
          </button>
        </div>

        {/* 错误提示 */}
        {error && (
          <div className="alert alert-error">{error}</div>
        )}

        {/* 成功提示 */}
        {success && (
          <div className="alert alert-success">{success}</div>
        )}

        {/* 生成结果 */}
        {artifact && (
          <div className="deploy-result">
            <h3>部署产出物</h3>

            {/* Tab 切换 */}
            <div className="result-tabs">
              <button
                className={`tab-btn ${activeTab === 'cli' ? 'active' : ''}`}
                onClick={() => setActiveTab('cli')}
              >
                CLI 一键命令
              </button>
              <button
                className={`tab-btn ${activeTab === 'script' ? 'active' : ''}`}
                onClick={() => setActiveTab('script')}
              >
                部署脚本 (bash)
              </button>
              <button
                className={`tab-btn ${activeTab === 'config' ? 'active' : ''}`}
                onClick={() => setActiveTab('config')}
              >
                config.yaml
              </button>
            </div>

            {/* CLI 命令 */}
            {activeTab === 'cli' && (
              <div className="result-section">
                <div className="result-header">
                  <span className="result-label">在目标主机上执行以下命令即可完成部署：</span>
                  <button className="btn btn-sm" onClick={() => copyToClipboard(artifact.cli_command)}>
                    复制命令
                  </button>
                </div>
                <pre className="code-block cmd-block">{artifact.cli_command}</pre>
              </div>
            )}

            {/* 部署脚本 */}
            {activeTab === 'script' && (
              <div className="result-section">
                <div className="result-header">
                  <span className="result-label">完整 bash 部署脚本（含 systemd 服务注册）：</span>
                  <button className="btn btn-sm" onClick={() => copyToClipboard(artifact.deploy_script)}>
                    复制脚本
                  </button>
                </div>
                <pre className="code-block">{artifact.deploy_script}</pre>
              </div>
            )}

            {/* config.yaml */}
            {activeTab === 'config' && (
              <div className="result-section">
                <div className="result-header">
                  <span className="result-label">Agent 配置文件（如需手动部署）：</span>
                  <button className="btn btn-sm" onClick={() => copyToClipboard(artifact.config_yaml)}>
                    复制配置
                  </button>
                </div>
                <pre className="code-block">{artifact.config_yaml}</pre>
              </div>
            )}

            {/* 验证提示 */}
            <div className="verify-section">
              <h4>注册校验</h4>
              <pre className="code-block">{artifact.verify_hint}</pre>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
