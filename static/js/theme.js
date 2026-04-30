/* ReconBase Theme Toggle
   Mantiene la elección en localStorage clave 'rb_theme' = 'dark' | 'light'.
   El bootstrap (aplicar el tema antes de pintar) se hace inline en cada
   <head> con un microscript — esto solo gestiona el botón. */
(function(){
  function getTheme(){
    try { return localStorage.getItem('rb_theme') || 'dark'; } catch(_) { return 'dark'; }
  }
  function setTheme(t){
    try { localStorage.setItem('rb_theme', t); } catch(_) {}
    if (t === 'light') document.documentElement.setAttribute('data-theme','light');
    else document.documentElement.removeAttribute('data-theme');
  }
  function buildButton(){
    if (document.querySelector('.rb-theme-toggle')) return;
    var btn = document.createElement('button');
    btn.className = 'rb-theme-toggle';
    btn.type = 'button';
    btn.setAttribute('aria-label', 'Cambiar tema claro/oscuro');
    btn.title = 'Cambiar tema';
    btn.innerHTML = '<span class="icon-sun" aria-hidden="true">☀️</span><span class="icon-moon" aria-hidden="true">🌙</span>';
    btn.onclick = function(){
      setTheme(getTheme() === 'light' ? 'dark' : 'light');
    };
    document.body.appendChild(btn);
  }
  // Re-aplica por si el bootstrap inline no llegó (defensa en profundidad)
  setTheme(getTheme());
  if (document.body) buildButton();
  else document.addEventListener('DOMContentLoaded', buildButton, {once:true});
})();
