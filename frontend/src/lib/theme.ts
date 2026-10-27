/**
 * Console theme: "dark" (Midnight) or "light" (Daylight). The choice is kept
 * per browser; the first visit follows the operating system setting.
 */

export type Theme = 'dark' | 'light';

const KEY = 'aegis.theme';

export function storedTheme(): Theme {
  try {
    const saved = window.localStorage.getItem(KEY);
    if (saved === 'dark' || saved === 'light') return saved;
  } catch {
    // Storage blocked: fall back to the system preference.
  }
  return window.matchMedia?.('(prefers-color-scheme: light)').matches ? 'light' : 'dark';
}

export function applyTheme(theme: Theme): void {
  document.documentElement.dataset.theme = theme;
  document.querySelector('meta[name="theme-color"]')?.setAttribute('content', theme === 'light' ? '#F6F4EF' : '#0B0B0C');
  try {
    window.localStorage.setItem(KEY, theme);
  } catch {
    // Not persisted; still applied for this visit.
  }
}
