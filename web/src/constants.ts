// 共享常量 — 陷阱场景 & 蜜罐服务标签

export const SCENARIO_LABELS: Record<string, string> = {
  web: 'Web 业务',
  database: '数据库',
  remote_access: '远程访问',
  infrastructure: '基础设施',
  full: '全量部署',
  custom: '自定义',
};

export const SERVICE_LABELS: Record<string, string> = {
  http: 'HTTP', mysql: 'MySQL', redis: 'Redis', ssh: 'SSH',
  ftp: 'FTP', ldap: 'LDAP', dns: 'DNS', smb: 'SMB', rdp: 'RDP',
};

export const SERVICE_DESC: Record<string, string> = {
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
