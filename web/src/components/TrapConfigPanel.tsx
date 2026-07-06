import { useState, useEffect } from 'react';
import { apiFetch } from '../api';
import { SCENARIO_LABELS, SERVICE_LABELS, SERVICE_DESC } from '../constants';

interface ScenarioInfo {
  key: string;
  description: string;
  services: string[];
}

interface TrapConfig {
  scenarios: ScenarioInfo[];
  current_scenario: string;
  enabled_services: string[];
  all_services: string[];
}

export default function TrapConfigPanel() {
  const [config, setConfig] = useState<TrapConfig | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  const fetchConfig = async () => {
    try {
      setLoading(true);
      const resp = await apiFetch('/api/traps/config');
      if (!resp.ok) throw new Error('HTTP ' + resp.status);
      const data = await resp.json();
      setConfig(data);
      setError('');
    } catch (e) {
      setError('无法加载陷阱配置: ' + (e as Error).message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchConfig();
  }, []);

  if (loading) {
    return (
      <div className="panel">
        <div className="panel-header"><h2>陷阱选配</h2></div>
        <div className="panel-body"><p>加载中...</p></div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="panel">
        <div className="panel-header"><h2>陷阱选配</h2></div>
        <div className="panel-body">
          <div className="alert alert-error">{error}</div>
        </div>
      </div>
    );
  }

  if (!config) return null;

  const currentScenario = config.scenarios.find(s => s.key === config.current_scenario);
  const currentLabel = SCENARIO_LABELS[config.current_scenario] || config.current_scenario;

  return (
    <div className="panel">
      <div className="panel-header">
        <h2>陷阱选配</h2>
        <span className="panel-subtitle">场景化陷阱模块选配 — 根据部署环境按需启用诱捕陷阱</span>
      </div>

      <div className="panel-body">
        {/* 当前场景 */}
        <section className="config-section">
          <h3>当前部署场景</h3>
          <div className="current-scenario-card">
            <div className="scenario-badge scenario-{config.current_scenario}">
              {currentLabel}
            </div>
            <p className="scenario-desc">
              {currentScenario?.description || '自定义选配'}
            </p>
          </div>
        </section>

        {/* 已启用服务 */}
        <section className="config-section">
          <h3>
            已启用陷阱服务
            <span className="count-badge">{config.enabled_services.length}/{config.all_services.length}</span>
          </h3>
          <div className="services-grid">
            {config.all_services.map(svc => {
              const enabled = config.enabled_services.includes(svc);
              return (
                <div
                  key={svc}
                  className={`service-card ${enabled ? 'enabled' : 'disabled'}`}
                >
                  <div className="service-header">
                    <span className={`status-dot ${enabled ? 'online' : 'offline'}`} />
                    <span className="service-name">{SERVICE_LABELS[svc] || svc}</span>
                  </div>
                  <p className="service-desc">{SERVICE_DESC[svc] || `${svc} 蜜罐服务`}</p>
                  <span className="service-state">{enabled ? '已启用' : '未启用'}</span>
                </div>
              );
            })}
          </div>
        </section>

        {/* 预设场景说明 */}
        <section className="config-section">
          <h3>可用场景</h3>
          <div className="scenario-list">
            {config.scenarios
              .filter(s => s.key !== 'custom')
              .map(s => (
                <div
                  key={s.key}
                  className={`scenario-card ${s.key === config.current_scenario ? 'active' : ''}`}
                >
                  <div className="scenario-top">
                    <span className="scenario-name">{SCENARIO_LABELS[s.key] || s.key}</span>
                    {s.key === config.current_scenario && (
                      <span className="tag tag-current">当前</span>
                    )}
                  </div>
                  <p className="scenario-desc-small">{s.description}</p>
                  <div className="scenario-services">
                    {s.services.map(svc => (
                      <span key={svc} className="svc-tag">{SERVICE_LABELS[svc] || svc}</span>
                    ))}
                  </div>
                </div>
              ))}
          </div>
        </section>

        {/* 引流链路说明 */}
        <section className="config-section">
          <h3>引流链路</h3>
          <div className="flow-info">
            <div className="flow-diagram">
              <span className="flow-node">攻击者</span>
              <span className="flow-arrow">→</span>
              <span className="flow-node">负载均衡 (面包屑路径匹配)</span>
              <span className="flow-arrow">→</span>
              <span className="flow-node">蜜罐 Agent</span>
              <span className="flow-arrow">→</span>
              <span className="flow-node">已启用陷阱服务</span>
            </div>
            <div className="flow-note">
              <p><strong>面包屑引流机制：</strong>攻击者字典中存在但合法业务流量不会访问的异常路径（如 /actuator/env、/.git/config、/etc/passwd），由负载均衡层面的路径匹配规则统一引流至蜜罐 Agent 节点。</p>
              <p><strong>当前仅启用的陷阱服务会响应：</strong>未选配的陷阱服务不会监听端口，不产生无效资源占用。HTTP 蜜罐未启用时，面包屑路径和反制载荷均不会生效。</p>
            </div>
          </div>
        </section>

        {/* 配置指南 */}
        <section className="config-section">
          <h3>配置方式</h3>
          <div className="config-guide">
            <p>编辑 <code>config.yaml</code> 中的 <code>honeypot-engine</code> 配置段：</p>
            <pre className="code-block">{`honeypot-engine:
  enabled: true
  trap_scenario: "web"       # 场景选择: web|database|remote_access|infrastructure|full|custom
  # 自定义选配（仅 trap_scenario=custom 时生效）
  # custom_services:
  #   - http
  #   - mysql
  #   - ssh`}</pre>
          </div>
        </section>
      </div>
    </div>
  );
}
