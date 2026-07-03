import { useState, useEffect } from 'react';
import { apiFetch } from '../api';

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
  os_target: string;  // "linux" or "windows"
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
  os_target: string;
  install_script_ps: string;
  service_config: string;
  binary_name: string;
  // v0.17.1: 双模式部署
  pull_command: string;
  manual_guide: string;
  package_url: string;
  file_list: { name: string; description: string }[];
  build_command: string;
}

type DeployMode = 'manual' | 'pull';

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
  const [osTarget, setOsTarget] = useState<'linux' | 'windows'>('linux');
  const [deployMode, setDeployMode] = useState<DeployMode>('pull');  // v0.17.1: 部署模式

  // 结果状态
  const [artifact, setArtifact] = useState<AgentDeployArtifact | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');

  // 场景元数据
  const [scenarios, setScenarios] = useState<ScenarioInfo[]>([]);
  const [activeTab, setActiveTab] = useState<'config' | 'cli' | 'script' | 'ps' | 'service' | 'pull' | 'manual' | 'build'>('cli');

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
    apiFetch('/api/traps/config')
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
      os_target: osTarget,
    };

    try {
      const resp = await apiFetch('/api/cluster/agent/generate', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
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
            <label>部署模式</label>
            <div className="scenario-selector">
              <button
                className={`scenario-btn ${deployMode === 'pull' ? 'active' : ''}`}
                onClick={() => setDeployMode('pull')}
              >
                一键拉取
              </button>
              <button
                className={`scenario-btn ${deployMode === 'manual' ? 'active' : ''}`}
                onClick={() => setDeployMode('manual')}
              >
                手动部署
              </button>
            </div>
            <span className="form-hint">
              {deployMode === 'pull'
                ? '目标主机执行命令从管理端拉取所有文件并自动启动'
                : '本地编译二进制后手动发送到目标主机，通过脚本启动'}
            </span>
          </div>

          <div className="form-group">
            <label>目标操作系统</label>
            <div className="scenario-selector">
              <button
                className={`scenario-btn ${osTarget === 'linux' ? 'active' : ''}`}
                onClick={() => setOsTarget('linux')}
              >
                Linux
              </button>
              <button
                className={`scenario-btn ${osTarget === 'windows' ? 'active' : ''}`}
                onClick={() => setOsTarget('windows')}
              >
                Windows
              </button>
            </div>
            <span className="form-hint">
              {osTarget === 'linux' ? '生成 bash/systemd 部署脚本' : '生成 PowerShell/Windows Service 部署脚本'}
            </span>
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

            {/* 部署模式切换 */}
            <div className="form-group" style={{marginBottom: '1rem'}}>
              <label>部署模式</label>
              <div className="scenario-selector">
                <button
                  className={`scenario-btn ${deployMode === 'pull' ? 'active' : ''}`}
                  onClick={() => { setDeployMode('pull'); setActiveTab('pull'); }}
                >
                  一键拉取
                </button>
                <button
                  className={`scenario-btn ${deployMode === 'manual' ? 'active' : ''}`}
                  onClick={() => { setDeployMode('manual'); setActiveTab('manual'); }}
                >
                  手动部署
                </button>
              </div>
            </div>

            {/* Tab 切换 */}
            <div className="result-tabs">
              {deployMode === 'pull' ? (
                <>
                  <button className={`tab-btn ${activeTab === 'pull' ? 'active' : ''}`} onClick={() => setActiveTab('pull')}>
                    拉取命令
                  </button>
                  <button className={`tab-btn ${activeTab === 'config' ? 'active' : ''}`} onClick={() => setActiveTab('config')}>
                    config.yaml
                  </button>
                  <button className={`tab-btn ${activeTab === 'script' ? 'active' : ''}`} onClick={() => setActiveTab('script')}>
                    部署脚本
                  </button>
                  {osTarget === 'windows' && (
                    <button className={`tab-btn ${activeTab === 'ps' ? 'active' : ''}`} onClick={() => setActiveTab('ps')}>
                      PowerShell
                    </button>
                  )}
                </>
              ) : (
                <>
                  <button className={`tab-btn ${activeTab === 'manual' ? 'active' : ''}`} onClick={() => setActiveTab('manual')}>
                    部署指引
                  </button>
                  <button className={`tab-btn ${activeTab === 'build' ? 'active' : ''}`} onClick={() => setActiveTab('build')}>
                    编译命令
                  </button>
                  <button className={`tab-btn ${activeTab === 'config' ? 'active' : ''}`} onClick={() => setActiveTab('config')}>
                    config.yaml
                  </button>
                  <button className={`tab-btn ${activeTab === 'script' ? 'active' : ''}`} onClick={() => setActiveTab('script')}>
                    部署脚本
                  </button>
                </>
              )}
              <button className={`tab-btn ${activeTab === 'cli' ? 'active' : ''}`} onClick={() => setActiveTab('cli')}>
                CLI 命令
              </button>
              <button className={`tab-btn ${activeTab === 'service' ? 'active' : ''}`} onClick={() => setActiveTab('service')}>
                文件清单
              </button>
            </div>

            {/* 一键拉取命令 */}
            {activeTab === 'pull' && (
              <div className="result-section">
                <div className="result-header">
                  <span className="result-label">
                    在目标主机上执行以下命令即可自动拉取部署：
                  </span>
                  <button className="btn btn-sm" onClick={() => copyToClipboard(artifact.pull_command)}>
                    复制命令
                  </button>
                </div>
                <pre className="code-block cmd-block">{artifact.pull_command}</pre>
                <div className="verify-section" style={{marginTop: '1rem'}}>
                  <p style={{color: '#666', fontSize: '0.85rem', marginBottom: '0.5rem'}}>
                    此命令会自动从管理端下载配置文件和部署脚本，从 GitHub Releases 拉取预编译二进制，完成部署后自动注册并启动服务。
                  </p>
                </div>
              </div>
            )}

            {/* 手动部署指引 */}
            {activeTab === 'manual' && (
              <div className="result-section">
                <div className="result-header">
                  <span className="result-label">手动部署完整指引：</span>
                  <button className="btn btn-sm" onClick={() => copyToClipboard(artifact.manual_guide)}>
                    复制指引
                  </button>
                </div>
                <pre className="code-block">{artifact.manual_guide}</pre>
              </div>
            )}

            {/* 编译命令 */}
            {activeTab === 'build' && (
              <div className="result-section">
                <div className="result-header">
                  <span className="result-label">本地交叉编译命令 (macOS/Linux 上执行)：</span>
                  <button className="btn btn-sm" onClick={() => copyToClipboard(artifact.build_command)}>
                    复制命令
                  </button>
                </div>
                <pre className="code-block cmd-block">{artifact.build_command}</pre>
                <div className="verify-section" style={{marginTop: '1rem'}}>
                  <p style={{color: '#666', fontSize: '0.85rem', marginBottom: '0.5rem'}}>
                    编译完成后将生成 {artifact.binary_name}（约14MB），将其与部署脚本和配置文件一同发送到目标主机，然后执行部署脚本即可。
                  </p>
                </div>
              </div>
            )}

            {/* CLI 命令 (保留兼容两种模式) */}
            {activeTab === 'cli' && (
              <div className="result-section">
                <div className="result-header">
                  <span className="result-label">快速一键命令（从 Release 下载 + 配置 + 启动）：</span>
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
                  <span className="result-label">
                    {osTarget === 'linux' ? 'Bash 自动部署脚本（含 systemd 服务注册）：' : '部署脚本：'}
                  </span>
                  <button className="btn btn-sm" onClick={() => copyToClipboard(artifact.deploy_script)}>
                    复制脚本
                  </button>
                </div>
                <pre className="code-block">{artifact.deploy_script}</pre>
              </div>
            )}

            {/* PowerShell 部署脚本 */}
            {activeTab === 'ps' && osTarget === 'windows' && (
              <div className="result-section">
                <div className="result-header">
                  <span className="result-label">Windows PowerShell 部署脚本：</span>
                  <button className="btn btn-sm" onClick={() => copyToClipboard(artifact.install_script_ps)}>
                    复制脚本
                  </button>
                </div>
                <pre className="code-block">{artifact.install_script_ps}</pre>
              </div>
            )}

            {/* config.yaml */}
            {activeTab === 'config' && (
              <div className="result-section">
                <div className="result-header">
                  <span className="result-label">Agent 配置文件：</span>
                  <button className="btn btn-sm" onClick={() => copyToClipboard(artifact.config_yaml)}>
                    复制配置
                  </button>
                </div>
                <pre className="code-block">{artifact.config_yaml}</pre>
              </div>
            )}

            {/* 文件清单 */}
            {activeTab === 'service' && (
              <div className="result-section">
                <div className="result-header">
                  <span className="result-label">部署包文件清单：</span>
                  <button
                    className="btn btn-sm btn-primary"
                    onClick={() => {
                      const baseUrl = window.location.origin;
                      const url = `${baseUrl}${artifact.package_url}`;
                      window.open(url, '_blank');
                    }}
                  >
                    下载部署包 (ZIP)
                  </button>
                </div>
                <table className="file-list-table" style={{width: '100%', borderCollapse: 'collapse', marginTop: '0.5rem'}}>
                  <thead>
                    <tr style={{background: '#f5f5f5', textAlign: 'left'}}>
                      <th style={{padding: '8px 12px', borderBottom: '2px solid #ddd'}}>文件名</th>
                      <th style={{padding: '8px 12px', borderBottom: '2px solid #ddd'}}>说明</th>
                    </tr>
                  </thead>
                  <tbody>
                    {artifact.file_list.map((f, i) => (
                      <tr key={i} style={{borderBottom: '1px solid #eee'}}>
                        <td style={{padding: '8px 12px', fontFamily: 'monospace', fontWeight: 600}}>{f.name}</td>
                        <td style={{padding: '8px 12px', color: '#666', fontSize: '0.9rem'}}>{f.description}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
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
