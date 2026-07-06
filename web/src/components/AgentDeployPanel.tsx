import { useState, useEffect, useRef, useCallback } from 'react';
import { apiFetch } from '../api';
import { SCENARIO_LABELS, SERVICE_LABELS, SERVICE_DESC } from '../constants';

interface ScenarioInfo {
  key: string;
  description: string;
  services: string[];
}

interface CompileResult {
  job_id: string;
  status: string; // "compiling" | "complete" | "failed"
  progress: number; // 0-100
  error?: string;
  os_target: string;
  goarch: string;
  binary_name: string;
  binary_size: number;
  package_size: number;
  package_name: string;
  files: CompileFile[];
  commands: DeployCommand[];
  duration_sec: number;
  started_at: string;
  finished_at?: string;
}

interface CompileFile {
  name: string;
  description: string;
  size: number;
}

interface DeployCommand {
  step: number;
  title: string;
  command: string;
  description?: string;
}

const ARCH_LABELS: Record<string, string> = {
  amd64: 'x86_64 / AMD64',
  arm64: 'ARM64 / aarch64',
};

function formatSize(bytes: number): string {
  if (bytes === 0) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(1024));
  return `${(bytes / Math.pow(1024, i)).toFixed(1)} ${units[i]}`;
}

function formatDuration(sec: number): string {
  if (sec < 1) return '< 1s';
  if (sec < 60) return `${sec.toFixed(1)}s`;
  const m = Math.floor(sec / 60);
  const s = Math.round(sec % 60);
  return `${m}m ${s}s`;
}

export default function AgentDeployPanel() {
  // 表单状态
  const [managerAddr, setManagerAddr] = useState('10.0.0.1:8443');
  const [nodeName, setNodeName] = useState('');
  const [osTarget, setOsTarget] = useState<'linux' | 'windows'>('linux');
  const [goarch, setGoarch] = useState<'amd64' | 'arm64'>('amd64');
  const [scenario, setScenario] = useState('web');
  const [customServices, setCustomServices] = useState<string[]>([]);
  const [tlsInsecure, setTlsInsecure] = useState(false);

  // 编译状态
  const [compileResult, setCompileResult] = useState<CompileResult | null>(null);
  const [compiling, setCompiling] = useState(false);
  const [compileError, setCompileError] = useState('');
  const [toastMsg, setToastMsg] = useState('');
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);

  // 场景元数据
  const [scenarios, setScenarios] = useState<ScenarioInfo[]>([]);

  // 可用的所有服务
  const allServices = ['http', 'mysql', 'redis', 'ssh', 'ftp', 'ldap', 'dns', 'smb', 'rdp'];

  useEffect(() => {
    const host = window.location.hostname;
    if (host && host !== 'localhost' && host !== '127.0.0.1') {
      setManagerAddr(`${host}:8443`);
    }
    apiFetch('/api/traps/config')
      .then(r => r.json())
      .then(d => { if (d.scenarios) setScenarios(d.scenarios); })
      .catch(() => {});
  }, []);

  // 清理轮询
  useEffect(() => {
    return () => {
      if (pollRef.current) clearInterval(pollRef.current);
    };
  }, []);

  const toast = useCallback((msg: string) => {
    setToastMsg(msg);
    setTimeout(() => setToastMsg(''), 2000);
  }, []);

  const getPreviewServices = (): string[] => {
    const found = scenarios.find(s => s.key === scenario);
    return found?.services || [];
  };

  const toggleCustomService = (svc: string) => {
    setCustomServices(prev =>
      prev.includes(svc) ? prev.filter(s => s !== svc) : [...prev, svc]
    );
  };

  const stopPolling = () => {
    if (pollRef.current) {
      clearInterval(pollRef.current);
      pollRef.current = null;
    }
  };

  const handleCompile = async () => {
    if (!managerAddr.trim()) {
      setCompileError('请输入管理端地址');
      return;
    }

    setCompiling(true);
    setCompileError('');
    setCompileResult(null);
    stopPolling();

    const req = {
      manager_addr: managerAddr.trim(),
      scenario,
      custom_services: scenario === 'custom' ? customServices : [],
      tls_insecure: tlsInsecure,
      node_name: nodeName.trim(),
      os_target: osTarget,
      goarch,
    };

    try {
      const resp = await apiFetch('/api/cluster/agent/compile', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(req),
      });

      if (!resp.ok) {
        const err = await resp.json();
        throw new Error(err.error || `HTTP ${resp.status}`);
      }

      const initial: CompileResult = await resp.json();
      setCompileResult(initial);

      // 开始轮询编译进度
      pollRef.current = setInterval(async () => {
        try {
          const statusResp = await apiFetch(
            `/api/cluster/agent/compile/status?job_id=${initial.job_id}`
          );
          if (!statusResp.ok) return;
          const data: CompileResult = await statusResp.json();
          setCompileResult(data);

          if (data.status === 'complete' || data.status === 'failed') {
            stopPolling();
            setCompiling(false);
            if (data.status === 'failed') {
              setCompileError(data.error || '编译失败');
            }
          }
        } catch {
          // 网络错误时继续重试
        }
      }, 1000);

    } catch (e) {
      setCompileError((e as Error).message);
      setCompiling(false);
    }
  };

  const handleDownload = () => {
    if (!compileResult || compileResult.status !== 'complete') return;
    const url = `/api/cluster/agent/compile/download?job_id=${compileResult.job_id}`;
    window.open(url, '_blank');
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text).then(() => toast('已复制到剪贴板'));
  };

  const copyAllCommands = () => {
    if (!compileResult) return;
    const all = compileResult.commands
      .map(c => `# 步骤 ${c.step}: ${c.title}\n${c.command}`)
      .join('\n\n');
    navigator.clipboard.writeText(all).then(() => toast('全部命令已复制'));
  };

  return (
    <div className="panel">
      <div className="panel-header">
        <h2>Agent 部署</h2>
        <span className="panel-subtitle">
          在管理端交叉编译生成目标平台的独立可执行文件，无需目标机器预装任何运行环境
        </span>
      </div>

      <div className="panel-body">
        {/* ========== 配置表单 ========== */}
        <div className="deploy-form">
          <div className="form-row" style={{ marginBottom: 16 }}>
            <div className="form-group">
              <label>管理端地址</label>
              <input
                type="text"
                value={managerAddr}
                onChange={e => setManagerAddr(e.target.value)}
                placeholder="10.0.0.1:8443"
              />
              <span className="form-hint">Agent 连接的管理节点 TLS 地址</span>
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

          {/* 目标平台选择 */}
          <div className="form-row" style={{ marginBottom: 16 }}>
            <div className="form-group">
              <label>目标操作系统</label>
              <div className="scenario-selector">
                <button
                  className={`scenario-btn ${osTarget === 'linux' ? 'active' : ''}`}
                  onClick={() => setOsTarget('linux')}
                >Linux</button>
                <button
                  className={`scenario-btn ${osTarget === 'windows' ? 'active' : ''}`}
                  onClick={() => setOsTarget('windows')}
                >Windows</button>
              </div>
            </div>
            <div className="form-group">
              <label>CPU 架构</label>
              <div className="scenario-selector">
                {(['amd64', 'arm64'] as const).map(a => (
                  <button
                    key={a}
                    className={`scenario-btn ${goarch === a ? 'active' : ''}`}
                    onClick={() => setGoarch(a)}
                  >{ARCH_LABELS[a]}</button>
                ))}
              </div>
            </div>
          </div>

          {/* 陷阱场景 */}
          <div className="form-group">
            <label>陷阱场景选配</label>
            <div className="scenario-selector">
              {['web', 'database', 'remote_access', 'infrastructure', 'full', 'custom'].map(s => (
                <button
                  key={s}
                  className={`scenario-btn ${scenario === s ? 'active' : ''}`}
                  onClick={() => setScenario(s)}
                >{SCENARIO_LABELS[s] || s}</button>
              ))}
            </div>
            <span className="form-hint">
              {scenario !== 'custom'
                ? `启用服务: ${getPreviewServices().join(', ') || '（无）'}`
                : '请在下方勾选需要启用的服务'}
            </span>
          </div>

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
                    {SERVICE_LABELS[svc] || svc}
                  </label>
                ))}
              </div>
            </div>
          )}

          {/* 服务预览 */}
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
            </div>
          )}

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

          {/* 零依赖提示 */}
          <div className="compile-hint">
            <strong>零依赖部署</strong> — 管理端将交叉编译生成静态链接的独立可执行文件
            (CGO_ENABLED=0)，目标机器仅需基础操作系统（bash/systemd 或 PowerShell），
            无需安装 Go、Runtime 或任何外部依赖。
          </div>

          <button
            className="btn btn-primary btn-generate"
            onClick={handleCompile}
            disabled={compiling}
          >
            {compiling ? '编译中...' : '编译并生成部署包'}
          </button>
        </div>

        {/* ========== 错误提示 ========== */}
        {compileError && (
          <div className="alert alert-error">{compileError}</div>
        )}

        {/* ========== Toast ========== */}
        {toastMsg && (
          <div className="toast-notification toast-visible">{toastMsg}</div>
        )}

        {/* ========== 编译进度 ========== */}
        {compiling && compileResult && (
          <div className="compile-progress-panel">
            <h3>编译进度</h3>
            <div className="progress-bar-wrap">
              <div
                className="progress-bar-fill"
                style={{ width: `${compileResult.progress}%` }}
              />
            </div>
            <div className="progress-info">
              <span className="progress-text">
                {compileResult.progress < 40 && '正在编译 Agent 可执行文件...'}
                {compileResult.progress >= 40 && compileResult.progress < 65 && '正在生成配置文件...'}
                {compileResult.progress >= 65 && compileResult.progress < 90 && '正在生成部署脚本与打包...'}
                {compileResult.progress >= 90 && compileResult.progress < 100 && '正在生成部署命令...'}
                {compileResult.progress >= 100 && '编译完成!'}
              </span>
              <span className="progress-pct">{compileResult.progress}%</span>
            </div>
            <div className="progress-meta">
              目标: {compileResult.os_target}/{compileResult.goarch} | 任务: {compileResult.job_id}
            </div>
          </div>
        )}

        {/* ========== 编译结果 ========== */}
        {compileResult && compileResult.status === 'complete' && (
          <div className="compile-result-panel">
            {/* 概览卡片 */}
            <div className="result-overview">
              <div className="overview-card">
                <span className="overview-label">编译耗时</span>
                <span className="overview-value">{formatDuration(compileResult.duration_sec)}</span>
              </div>
              <div className="overview-card">
                <span className="overview-label">二进制大小</span>
                <span className="overview-value">{formatSize(compileResult.binary_size)}</span>
              </div>
              <div className="overview-card">
                <span className="overview-label">部署包大小</span>
                <span className="overview-value">{formatSize(compileResult.package_size)}</span>
              </div>
              <div className="overview-card">
                <span className="overview-label">目标平台</span>
                <span className="overview-value">{compileResult.os_target}/{compileResult.goarch}</span>
              </div>
            </div>

            {/* 产物文件列表 */}
            <div className="result-section-card">
              <div className="section-card-header">
                <h4>生成文件</h4>
                <button className="btn btn-sm btn-primary" onClick={handleDownload}>
                  下载部署包 ({compileResult.package_name})
                </button>
              </div>
              <div className="file-list">
                {compileResult.files.map((f, i) => (
                  <div key={i} className="file-item">
                    <div className="file-icon">
                      {f.name.endsWith('.exe') || f.name === 'honeypot-agent' ? '⚙' :
                       f.name.endsWith('.yaml') ? '📋' :
                       f.name.endsWith('.sh') || f.name.endsWith('.ps1') ? '📜' :
                       f.name.endsWith('.pem') ? '🔑' : '📄'}
                    </div>
                    <div className="file-info">
                      <span className="file-name">{f.name}</span>
                      <span className="file-desc">{f.description}</span>
                    </div>
                    <span className="file-size">{formatSize(f.size)}</span>
                  </div>
                ))}
              </div>
            </div>

            {/* 部署命令 */}
            <div className="result-section-card">
              <div className="section-card-header">
                <h4>部署命令（目标机器无依赖执行）</h4>
                <button className="btn btn-sm" onClick={copyAllCommands}>一键复制全部</button>
              </div>
              <div className="deploy-cmd-list">
                {compileResult.commands.map((cmd) => (
                  <div key={cmd.step} className="deploy-cmd-item">
                    <div className="cmd-header">
                      <span className="cmd-step">步骤 {cmd.step}</span>
                      <span className="cmd-title">{cmd.title}</span>
                      <button
                        className="btn btn-xs"
                        onClick={() => copyToClipboard(cmd.command)}
                      >复制</button>
                    </div>
                    <pre className="code-block cmd-block">{cmd.command}</pre>
                    {cmd.description && (
                      <p className="cmd-desc">{cmd.description}</p>
                    )}
                  </div>
                ))}
              </div>
            </div>

            {/* 零依赖说明 */}
            <div className="zero-dep-hint">
              <strong>目标机器运行要求:</strong> 无需安装任何额外软件。
              {compileResult.os_target === 'linux' && (
                <span> 仅需 bash + systemd（所有主流 Linux 发行版均内置）。</span>
              )}
              {compileResult.os_target === 'windows' && (
                <span> 仅需 PowerShell 5.1+（Windows 10+/Server 2016+ 均内置）。</span>
              )}
              部署包内的所有文件均为自包含格式，直接复制到目标机器执行部署脚本即可完成安装。
            </div>

            {/* 验证提示 */}
            <div className="verify-section">
              <h4>部署后验证</h4>
              <pre className="code-block">{compileResult.os_target === 'windows' ? `# Windows 验证命令
sc.exe query HoneypotAgent
Get-Content "C:\\Program Files\\Honeypot\\data\\agent.log" -Tail 20` : `# Linux 验证命令
systemctl status honeypot-agent
journalctl -u honeypot-agent -f
curl http://<agent-ip>:8080/healthz`}</pre>
              <p style={{ color: '#64748b', fontSize: '12px', marginTop: 8 }}>
                确认 Agent 上线后，在"集群管理"面板查看节点状态。
              </p>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
