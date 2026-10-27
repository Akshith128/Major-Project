/**
 * Cursor spotlight: tells the card under the pointer where the pointer is, so
 * its border glow and soft fill (CSS in index.css, `.aegis-glass`) follow it.
 * One passive listener for the whole page; skipped for reduced motion.
 */
export function enableSpotlight(): void {
  if (window.matchMedia?.('(prefers-reduced-motion: reduce)').matches) return;
  let frame = 0;
  let last: PointerEvent | null = null;
  window.addEventListener(
    'pointermove',
    (event) => {
      last = event;
      if (frame) return;
      frame = requestAnimationFrame(() => {
        frame = 0;
        const target = (last?.target as Element | null)?.closest?.('.aegis-glass') as HTMLElement | null;
        if (!target || !last) return;
        const box = target.getBoundingClientRect();
        target.style.setProperty('--mx', `${last.clientX - box.left}px`);
        target.style.setProperty('--my', `${last.clientY - box.top}px`);
      });
    },
    { passive: true },
  );
}
