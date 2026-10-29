import { useEffect, useState } from 'react';

/**
 * Console theme: "dark" (Orbit) or "light" (Daylight). The choice is kept
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
  document.querySelector('meta[name="theme-color"]')?.setAttribute('content', theme === 'light' ? '#F5F6FB' : '#000000');
  try {
    window.localStorage.setItem(KEY, theme);
  } catch {
    // Not persisted; still applied for this visit.
  }
}

/** The theme currently applied to the page; follows the toggle as it changes. */
export function useTheme(): Theme {
  const read = (): Theme => (document.documentElement.dataset.theme === 'light' ? 'light' : 'dark');
  const [theme, setTheme] = useState<Theme>(read);
  useEffect(() => {
    const observer = new MutationObserver(() => setTheme(read()));
    observer.observe(document.documentElement, { attributes: true, attributeFilter: ['data-theme'] });
    return () => observer.disconnect();
  }, []);
  return theme;
}
