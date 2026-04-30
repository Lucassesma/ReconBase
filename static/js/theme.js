/* ReconBase Theme Toggle v2 — más robusto y visible.
   - Botón flotante con SVG (sin emojis: más fiable cross-browser).
   - Si el body tiene .rb-no-theme-toggle, no se muestra.
   - Aplica cambio + log de debug. */
(function(){
  var KEY = 'rb_theme';
  function getTheme(){
    try { var v = localStorage.getItem(KEY); return v === 'light' ? 'light' : 'dark'; } catch(_) { return 'dark'; }
  }
  function applyTheme(t){
    if (t === 'light') {
      document.documentElement.setAttribute('data-theme','light');
    } else {
      document.documentElement.removeAttribute('data-theme');
    }
  }
  function setTheme(t){
    try { localStorage.setItem(KEY, t); } catch(_) {}
    applyTheme(t);
    console.log('[RB-Theme] aplicado:', t);
  }

  // Aplicar el tema actual
  applyTheme(getTheme());

  function buildButton(){
    if (document.querySelector('.rb-theme-toggle')) return;
    if (document.body && document.body.classList.contains('rb-no-theme-toggle')) return;

    var btn = document.createElement('button');
    btn.className = 'rb-theme-toggle';
    btn.type = 'button';
    btn.setAttribute('aria-label', 'Cambiar tema claro/oscuro');
    btn.title = 'Cambiar tema (claro/oscuro)';

    // SVG para evitar problemas de renderizado de emojis
    btn.innerHTML =
      '<svg class="icon-moon" xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/></svg>' +
      '<svg class="icon-sun" xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.93 4.93l1.41 1.41M17.66 17.66l1.41 1.41M2 12h2M20 12h2M4.93 19.07l1.41-1.41M17.66 6.34l1.41-1.41"/></svg>';

    btn.addEventListener('click', function(e){
      e.preventDefault();
      var current = getTheme();
      var next = (current === 'light') ? 'dark' : 'light';
      setTheme(next);
    });

    if (document.body) document.body.appendChild(btn);
    console.log('[RB-Theme] botón creado, tema actual:', getTheme());
  }

  if (document.body) {
    buildButton();
  } else {
    document.addEventListener('DOMContentLoaded', buildButton, {once:true});
  }
})();
