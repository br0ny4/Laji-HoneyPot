// Toast 通知模块 — 命令式 API，显示短暂通知后自动消失
let activeToast: HTMLDivElement | null = null;

export function showToast(message: string, duration = 3000): void {
  // 移除已有 toast
  if (activeToast) {
    activeToast.remove();
    activeToast = null;
  }

  const toast = document.createElement('div');
  toast.className = 'toast-notification';
  toast.textContent = message;
  document.body.appendChild(toast);

  // 触发入场动画
  requestAnimationFrame(() => {
    toast.classList.add('toast-visible');
  });

  activeToast = toast;

  setTimeout(() => {
    toast.classList.remove('toast-visible');
    setTimeout(() => {
      if (activeToast === toast) {
        toast.remove();
        activeToast = null;
      }
    }, 300);
  }, duration);
}
