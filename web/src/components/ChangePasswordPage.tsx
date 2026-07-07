import { useState, FormEvent } from 'react';
import { changeOwnPassword } from '../api';

interface ChangePasswordPageProps {
  onPasswordChanged: () => void;
  onLogout: () => void;
}

const PASSWORD_RULES = [
  '至少 16 个字符',
  '至少 1 个大写字母 (A-Z)',
  '至少 1 个小写字母 (a-z)',
  '至少 1 个数字 (0-9)',
  '至少 1 个特殊字符 (!@#$%^&*()-_+=[]{}|:;,.?)',
  '不含连续 3 个相同字符',
];

export default function ChangePasswordPage({ onPasswordChanged, onLogout }: ChangePasswordPageProps) {
  const [oldPassword, setOldPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    setError('');
    setSuccess('');

    if (!oldPassword || !newPassword || !confirmPassword) {
      setError('请填写所有密码字段');
      return;
    }
    if (newPassword !== confirmPassword) {
      setError('两次输入的新密码不一致');
      return;
    }
    if (newPassword === oldPassword) {
      setError('新密码不能与当前密码相同');
      return;
    }

    setLoading(true);
    try {
      const result = await changeOwnPassword(oldPassword, newPassword);
      if (result.success) {
        setSuccess('密码修改成功，即将跳转到管理面板...');
        setTimeout(() => onPasswordChanged(), 1500);
      } else {
        setError(result.error || '密码修改失败');
      }
    } catch {
      setError('网络错误');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="login-page">
      <div className="login-card change-password-card">
        <div className="login-header">
          <h1 className="login-title">首次登录</h1>
          <p className="login-subtitle">
            为保障系统安全，请设置您的专属密码
          </p>
        </div>

        <div className="password-rules">
          密码要求：
          <ul>
            {PASSWORD_RULES.map((rule, i) => (
              <li key={i}>{rule}</li>
            ))}
          </ul>
        </div>

        <form className="login-form" onSubmit={handleSubmit}>
          <div className="form-group">
            <label htmlFor="old-password">当前密码（初始密码）</label>
            <input
              id="old-password"
              type="password"
              placeholder="输入终端显示的初始密码"
              value={oldPassword}
              onChange={(e) => setOldPassword(e.target.value)}
              autoFocus
              autoComplete="current-password"
            />
          </div>
          <div className="form-group">
            <label htmlFor="new-password">新密码</label>
            <input
              id="new-password"
              type="password"
              placeholder="输入符合规则的新密码"
              value={newPassword}
              onChange={(e) => setNewPassword(e.target.value)}
              autoComplete="new-password"
            />
          </div>
          <div className="form-group">
            <label htmlFor="confirm-password">确认新密码</label>
            <input
              id="confirm-password"
              type="password"
              placeholder="再次输入新密码"
              value={confirmPassword}
              onChange={(e) => setConfirmPassword(e.target.value)}
              autoComplete="new-password"
            />
          </div>
          {error && <div className="login-error">{error}</div>}
          {success && <div className="login-success">{success}</div>}
          <button type="submit" className="login-btn" disabled={loading}>
            {loading ? '修改中...' : '修改密码并进入系统'}
          </button>
        </form>

        <button className="login-btn login-btn-secondary" onClick={onLogout}>
          退出登录
        </button>
      </div>
    </div>
  );
}
