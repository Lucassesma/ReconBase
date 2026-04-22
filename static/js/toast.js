/* ReconBase — Sistema de toasts / banners
   Sustituye a alert() con una UI consistente.
   Uso:
     toast('Mensaje')               → toast neutro
     toast('OK', 'ok')              → verde
     toast('Error', 'err')          → rojo
     toast('Aviso', 'warn')         → amarillo
     toastHtml('<b>Lo que sea</b>') → permite HTML
   Los toasts se apilan y desaparecen solos en 4-6s.
*/
(function(){
  var css = '#rb-toast-wrap{position:fixed;top:1rem;right:1rem;z-index:99999;display:flex;flex-direction:column;gap:.5rem;max-width:380px;pointer-events:none}' +
    '.rb-toast{pointer-events:auto;background:#0A1410;border:1px solid #152B1E;border-radius:8px;padding:.85rem 1rem;color:#E2EDF8;font-family:Inter,Arial,sans-serif;font-size:.88rem;line-height:1.5;box-shadow:0 4px 24px rgba(0,0,0,.4);animation:rbSlide .25s ease-out;display:flex;align-items:flex-start;gap:.65rem;word-break:break-word}' +
    '.rb-toast.ok{border-color:rgba(34,197,94,.35);background:rgba(16,185,129,.08)}' +
    '.rb-toast.err{border-color:rgba(239,68,68,.35);background:rgba(239,68,68,.08)}' +
    '.rb-toast.warn{border-color:rgba(245,158,11,.35);background:rgba(245,158,11,.08)}' +
    '.rb-toast.closing{animation:rbFade .25s ease-in forwards}' +
    '.rb-toast-ico{font-size:1.05rem;line-height:1;flex-shrink:0;margin-top:1px}' +
    '.rb-toast-msg{flex:1}' +
    '.rb-toast-x{cursor:pointer;color:#475569;font-size:1.1rem;line-height:1;padding:0 .15rem;background:none;border:none;font-family:inherit}' +
    '.rb-toast-x:hover{color:#E2EDF8}' +
    '@keyframes rbSlide{from{transform:translateX(110%);opacity:0}to{transform:translateX(0);opacity:1}}' +
    '@keyframes rbFade{to{opacity:0;transform:translateX(40%)}}' +
    '@media(max-width:600px){#rb-toast-wrap{left:1rem;right:1rem;max-width:none}}';
  var style = document.createElement('style');
  style.textContent = css;
  document.head.appendChild(style);

  function wrap(){
    var w = document.getElementById('rb-toast-wrap');
    if(!w){ w = document.createElement('div'); w.id = 'rb-toast-wrap'; document.body.appendChild(w); }
    return w;
  }
  function icono(t){ return t==='ok'?'✓':t==='err'?'✕':t==='warn'?'⚠':'ℹ'; }
  function show(msg, type, html, opts){
    opts = opts || {};
    var el = document.createElement('div');
    el.className = 'rb-toast ' + (type||'');
    var ico = document.createElement('span'); ico.className = 'rb-toast-ico'; ico.textContent = icono(type);
    var m = document.createElement('span'); m.className = 'rb-toast-msg';
    if(html) m.innerHTML = msg; else m.textContent = msg;
    var x = document.createElement('button'); x.className = 'rb-toast-x'; x.type='button'; x.textContent = '×';
    var close = function(){ if(el.parentNode){ el.classList.add('closing'); setTimeout(function(){ if(el.parentNode) el.parentNode.removeChild(el); }, 240); } };
    x.addEventListener('click', close);
    el.appendChild(ico); el.appendChild(m); el.appendChild(x);
    wrap().appendChild(el);
    var dur = opts.duration || (type==='err' ? 6500 : 4500);
    setTimeout(close, dur);
    return close;
  }
  window.toast = function(msg, type, opts){ return show(String(msg||''), type, false, opts); };
  window.toastHtml = function(html, type, opts){ return show(String(html||''), type, true, opts); };
})();
