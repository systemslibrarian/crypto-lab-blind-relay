/** Tiny DOM helpers — this lab renders with template strings + escape. */

export function esc(s: string): string {
  return s
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

export function byId<T extends HTMLElement>(id: string): T {
  const el = document.getElementById(id);
  if (!el) throw new Error(`missing element #${id}`);
  return el as T;
}

/** Group hex into 8-char words so long values wrap at sane points. */
export function hexPretty(hex: string): string {
  return hex.replace(/(.{8})/g, '$1 ').trim();
}
