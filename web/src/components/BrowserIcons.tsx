// Inline SVG browser icons for FingerprintPanel

export function getBrowserIcon(uaName: string): JSX.Element {
  const lower = uaName.toLowerCase();
  if (lower.includes('chrome') && !lower.includes('edg')) {
    return ChromeIcon;
  }
  if (lower.includes('firefox')) {
    return FirefoxIcon;
  }
  if (lower.includes('safari') && !lower.includes('chrome')) {
    return SafariIcon;
  }
  if (lower.includes('edg')) {
    return EdgeIcon;
  }
  if (lower.includes('opera') || lower.includes('opr')) {
    return OperaIcon;
  }
  return GenericBrowserIcon;
}

const ChromeIcon = (
  <svg width="18" height="18" viewBox="0 0 18 18" fill="none" xmlns="http://www.w3.org/2000/svg">
    <circle cx="9" cy="9" r="8" fill="#1a73e8" />
    <circle cx="9" cy="9" r="4" fill="#fff" />
    <circle cx="9" cy="9" r="2.5" fill="#1a73e8" />
    <path d="M9 1 A8 8 0 0 1 15 5 L13 4 A6 6 0 0 0 9 3 Z" fill="#ea4335" opacity="0.8" />
    <path d="M15 13 A8 8 0 0 1 9 17 L10 15 A6 6 0 0 0 13 12 Z" fill="#34a853" opacity="0.8" />
    <path d="M3 13 A8 8 0 0 0 9 17 L8 15 A6 6 0 0 1 5 12 Z" fill="#fbbc04" opacity="0.8" />
  </svg>
);

const FirefoxIcon = (
  <svg width="18" height="18" viewBox="0 0 18 18" fill="none" xmlns="http://www.w3.org/2000/svg">
    <circle cx="9" cy="9" r="8" fill="#ff7139" />
    <circle cx="6.5" cy="5.5" r="3" fill="#e66000" opacity="0.7" />
    <circle cx="12" cy="12" r="3.5" fill="#e66000" opacity="0.7" />
    <circle cx="6" cy="12" r="3" fill="#ff9400" opacity="0.6" />
    <circle cx="11" cy="5" r="2.5" fill="#ff9400" opacity="0.5" />
    <circle cx="9" cy="9" r="4" fill="#20123a" opacity="0.5" />
    <circle cx="8.5" cy="8.5" r="2.5" fill="#ff7139" />
  </svg>
);

const SafariIcon = (
  <svg width="18" height="18" viewBox="0 0 18 18" fill="none" xmlns="http://www.w3.org/2000/svg">
    <circle cx="9" cy="9" r="8" fill="#0fb5ff" />
    <circle cx="9" cy="9" r="6" fill="#fff" />
    <line x1="9" y1="3" x2="9" y2="5" stroke="#0fb5ff" strokeWidth="1.2" />
    <line x1="9" y1="13" x2="9" y2="15" stroke="#0fb5ff" strokeWidth="1.2" />
    <line x1="3" y1="9" x2="5" y2="9" stroke="#0fb5ff" strokeWidth="1.2" />
    <line x1="13" y1="9" x2="15" y2="9" stroke="#0fb5ff" strokeWidth="1.2" />
    <line x1="4.76" y1="4.76" x2="6.17" y2="6.17" stroke="#0fb5ff" strokeWidth="1.2" />
    <line x1="11.83" y1="11.83" x2="13.24" y2="13.24" stroke="#0fb5ff" strokeWidth="1.2" />
    <line x1="4.76" y1="13.24" x2="6.17" y2="11.83" stroke="#0fb5ff" strokeWidth="1.2" />
    <line x1="11.83" y1="6.17" x2="13.24" y2="4.76" stroke="#0fb5ff" strokeWidth="1.2" />
    <circle cx="9" cy="9" r="1.2" fill="#ff3b30" />
    <path d="M9 3.5 L8 8 L3 9 L8 10 L9 14.5 L10 10 L15 9 L10 8 Z" fill="#0fb5ff" opacity="0.3" />
  </svg>
);

const EdgeIcon = (
  <svg width="18" height="18" viewBox="0 0 18 18" fill="none" xmlns="http://www.w3.org/2000/svg">
    <circle cx="9" cy="9" r="8" fill="#0078d4" />
    <path
      d="M11.5 3.5 C14 5 14.5 8 13.5 10 C13 11.5 11.5 13 9.5 14 C10 12 10 10 9.5 8.5 C9 7 8 6 6.5 5.5 C7.5 4 9.5 3 11.5 3.5Z"
      fill="#fff"
      opacity="0.9"
    />
    <path
      d="M6 5 C7.5 5.5 8.5 6.5 9 8 C9.5 9.5 9.5 11.5 9 13.5 C7 13 5.5 11 4.5 9 C3.5 7 4 5 6 5Z"
      fill="#60cdff"
      opacity="0.7"
    />
  </svg>
);

const OperaIcon = (
  <svg width="18" height="18" viewBox="0 0 18 18" fill="none" xmlns="http://www.w3.org/2000/svg">
    <circle cx="9" cy="9" r="8" fill="#ff1b2d" />
    <circle cx="9" cy="9" r="5.5" fill="#fff" />
    <circle cx="9" cy="9" r="4.5" fill="#ff1b2d" />
    <path
      d="M9 3 C5 3 3.5 6 3.5 9 C3.5 12 5 15 9 15 C13 15 14.5 12 14.5 9 C14.5 6 13 3 9 3Z"
      fill="none"
      stroke="#fff"
      strokeWidth="1.2"
    />
    <circle cx="9" cy="9" r="2" fill="#fff" />
    <circle cx="9" cy="9" r="1" fill="#ff1b2d" />
  </svg>
);

const GenericBrowserIcon = (
  <svg width="18" height="18" viewBox="0 0 18 18" fill="none" xmlns="http://www.w3.org/2000/svg">
    <circle cx="9" cy="9" r="8" fill="#607d8b" />
    <rect x="5" y="5" width="8" height="8" rx="1.5" fill="#fff" opacity="0.3" />
    <line x1="5" y1="9" x2="13" y2="9" stroke="#fff" strokeWidth="1.2" />
    <line x1="9" y1="5" x2="9" y2="13" stroke="#fff" strokeWidth="1.2" />
    <circle cx="9" cy="9" r="1.5" fill="#fff" />
  </svg>
);
