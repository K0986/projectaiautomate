(() => {
  const root = document.documentElement;
  const systemTheme = window.matchMedia('(prefers-color-scheme: dark)');
  let preference = null;

  try {
    const saved = localStorage.getItem('still-theme');
    if (saved === 'light' || saved === 'dark') preference = saved;
  } catch {
    // The toggle still works when browser storage is unavailable.
  }

  function applyTheme() {
    const theme = preference || (systemTheme.matches ? 'dark' : 'light');
    root.dataset.theme = theme;
    const toggle = document.querySelector('.theme-toggle');
    if (toggle) toggle.setAttribute('aria-pressed', String(theme === 'dark'));
  }

  // Apply before the stylesheet loads to avoid a flash of the wrong theme.
  applyTheme();
  systemTheme.addEventListener('change', applyTheme);

  document.addEventListener('DOMContentLoaded', () => {
    const toggle = document.querySelector('.theme-toggle');
    if (!toggle) return;
    toggle.hidden = false;
    applyTheme();
    toggle.addEventListener('click', () => {
      preference = root.dataset.theme === 'dark' ? 'light' : 'dark';
      try {
        localStorage.setItem('still-theme', preference);
      } catch {
        // Keep the selection for this page even if it cannot be saved.
      }
      applyTheme();
    });
  });
})();
