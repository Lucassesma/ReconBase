/* ReconBase — consentimiento de cookies (LSSI art. 22.2 y guía de la AEPD).
   · Google Tag Manager y Google Analytics solo se cargan si el visitante acepta.
   · "Aceptar" y "Rechazar" tienen el mismo peso visual.
   · Cualquier enlace con data-rb-cookies reabre el banner para cambiar la decisión.
   · Al rechazar o retirar el consentimiento se borran las cookies de Google Analytics. */
(function () {
  'use strict';
  var COOKIE = 'rb_cookies';            // 'analitica' | 'rechazadas'
  var DURACION = 60 * 60 * 24 * 180;     // se vuelve a preguntar a los 6 meses
  var cargado = false;

  function leer() {
    var m = document.cookie.match(/(?:^|;\s*)rb_cookies=(analitica|rechazadas)/);
    return m ? m[1] : null;
  }

  function guardar(valor) {
    document.cookie = COOKIE + '=' + valor + '; Max-Age=' + DURACION + '; Path=/; SameSite=Lax' +
      (location.protocol === 'https:' ? '; Secure' : '');
  }

  function borrarCookiesGoogle() {
    var host = location.hostname;
    var dominios = ['', host, '.' + host, '.' + host.split('.').slice(-2).join('.')];
    document.cookie.split(';').forEach(function (c) {
      var nombre = c.split('=')[0].trim();
      if (/^(_ga|_gid|_gat|_gcl)/.test(nombre)) {
        dominios.forEach(function (d) {
          document.cookie = nombre + '=; Max-Age=0; Path=/' + (d ? '; Domain=' + d : '');
        });
      }
    });
  }

  function cargarGoogle() {
    if (cargado) return;
    cargado = true;
    window.gtag && window.gtag('consent', 'update', { 'analytics_storage': 'granted' });
    if (window.RB_GTM_ID) {
      window.dataLayer = window.dataLayer || [];
      window.dataLayer.push({ 'gtm.start': new Date().getTime(), event: 'gtm.js' });
      var s = document.createElement('script');
      s.async = true;
      s.src = 'https://www.googletagmanager.com/gtm.js?id=' + encodeURIComponent(window.RB_GTM_ID);
      document.head.appendChild(s);
    }
    if (window.RB_GA_ID) {
      var g = document.createElement('script');
      g.async = true;
      g.src = 'https://www.googletagmanager.com/gtag/js?id=' + encodeURIComponent(window.RB_GA_ID);
      document.head.appendChild(g);
      window.gtag('js', new Date());
      window.gtag('config', window.RB_GA_ID);
    }
  }

  function cerrarBanner() {
    var b = document.getElementById('rb-cookie-banner');
    if (b) b.parentNode.removeChild(b);
  }

  function decidir(valor) {
    var anterior = leer();
    guardar(valor);
    cerrarBanner();
    if (valor === 'analitica') {
      cargarGoogle();
    } else {
      borrarCookiesGoogle();
      // Si ya estaba cargado, recargar para detener las etiquetas de Google.
      if (anterior === 'analitica' || cargado) location.reload();
    }
  }

  function mostrarBanner() {
    if (document.getElementById('rb-cookie-banner')) return;
    var b = document.createElement('div');
    b.id = 'rb-cookie-banner';
    b.setAttribute('role', 'dialog');
    b.setAttribute('aria-label', 'Preferencias de cookies');
    b.style.cssText = 'position:fixed;left:0;right:0;bottom:0;z-index:2147483000;background:#0A1410;' +
      'border-top:1px solid #1F3A2A;padding:1rem 5%;display:flex;flex-wrap:wrap;align-items:center;' +
      'justify-content:space-between;gap:1rem;font-family:Inter,system-ui,sans-serif;box-shadow:0 -8px 24px rgba(0,0,0,.35)';
    var estiloBoton = 'min-width:130px;padding:.65rem 1.2rem;border-radius:8px;font-weight:700;font-size:.85rem;' +
      'cursor:pointer;font-family:inherit;background:#E2EDF8;color:#0A1410;border:1px solid #E2EDF8';
    b.innerHTML =
      '<p style="flex:1;min-width:260px;margin:0;font-size:.84rem;line-height:1.55;color:#CBD5E1">' +
      'Usamos cookies técnicas, necesarias para que la web funcione, y, <strong style="color:#F0FDF4">solo si las aceptas</strong>, ' +
      'cookies de analítica de Google Analytics para saber cómo se usa la web. No usamos cookies de publicidad. ' +
      'Puedes cambiar tu decisión cuando quieras desde «Configurar cookies» en el pie de página. ' +
      '<a href="/cookies" style="color:#86EFAC;text-decoration:underline">Política de cookies</a></p>' +
      '<div style="display:flex;gap:.6rem;flex-wrap:wrap">' +
      '<button type="button" id="rb-cookies-rechazar" style="' + estiloBoton + '">Rechazar</button>' +
      '<button type="button" id="rb-cookies-aceptar" style="' + estiloBoton + '">Aceptar</button>' +
      '</div>';
    document.body.appendChild(b);
    document.getElementById('rb-cookies-rechazar').onclick = function () { decidir('rechazadas'); };
    document.getElementById('rb-cookies-aceptar').onclick = function () { decidir('analitica'); };
  }

  window.rbConfigurarCookies = function (ev) {
    if (ev && ev.preventDefault) ev.preventDefault();
    mostrarBanner();
  };

  function iniciar() {
    var valor = leer();
    if (valor === 'analitica') {
      cargarGoogle();
    } else {
      borrarCookiesGoogle();
      if (!valor) mostrarBanner();
    }
    document.addEventListener('click', function (e) {
      var el = e.target && e.target.closest ? e.target.closest('[data-rb-cookies]') : null;
      if (el) window.rbConfigurarCookies(e);
    });
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', iniciar);
  else iniciar();
})();
