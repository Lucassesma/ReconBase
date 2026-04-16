/* ═══════════════════════════════════════════════
   ReconBase — ESCÁNER INTEGRADO (funciones sc*)
   Requiere: window.RB = { isLoggedIn: bool } definido en el template
═══════════════════════════════════════════════ */
var isLoggedIn = (window.RB && window.RB.isLoggedIn) === true;
var scCurrentData = null;
var scGaugeChart = null, scHeadersChart = null, scRadarChart = null;
var scDashHeadersChart = null, scDashRadarChart = null, scDashBarChart = null;
var scTendChart = null;
var scProgInterval = null;

function scSwitch(tab, el) {
  document.querySelectorAll('.sc-tab').forEach(function(t){t.classList.remove('active');});
  document.querySelectorAll('.sc-panel').forEach(function(p){p.classList.remove('active');});
  el.classList.add('active');
  document.getElementById('sc-' + tab).classList.add('active');
  if (tab === 'historial') scLoadHistorial();
  if (tab === 'tendencia') scRenderTendencia();
  if (tab === 'dashboard' && scCurrentData) scRenderDashboard(scCurrentData);
  if (tab === 'exportar' && scCurrentData) scRenderExport(scCurrentData);
}

function scLanzar() {
  var v = (document.getElementById('sc-objetivo').value || '').trim();
  if (!v) { document.getElementById('sc-objetivo').focus(); return; }
  var btn = document.getElementById('sc-btn');
  btn.textContent = 'Analizando...'; btn.disabled = true;
  document.getElementById('sc-loading').style.display = 'block';
  document.getElementById('sc-results').style.display = 'none';
  document.getElementById('sc-empty').style.display = 'none';

  [0,1,2,3,4].forEach(function(i) {
    var dot = document.getElementById('sd' + i);
    var txt = document.getElementById('st' + i);
    if (dot) dot.classList.remove('active', 'done');
    if (txt) txt.style.opacity = '0.4';
  });
  var step = 0;
  var dotInterval = setInterval(function() {
    if (step > 0) { var prev = document.getElementById('sd'+(step-1)); if(prev){prev.classList.remove('active');prev.classList.add('done');} }
    var dot = document.getElementById('sd'+step); var txt = document.getElementById('st'+step);
    if (dot) dot.classList.add('active');
    if (txt) txt.style.opacity = '1';
    step++;
    if (step >= 5) clearInterval(dotInterval);
  }, 1400);

  var prog = document.getElementById('sc-prog'); if(prog) prog.style.width = '0%';
  var p = 0;
  scProgInterval = setInterval(function() {
    p += Math.random() * 8 + 2;
    if (p > 90) p = 90;
    if (prog) prog.style.width = p + '%';
  }, 600);

  fetch('/api/scan', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({objetivo:v})})
  .then(function(r){return r.json();})
  .then(function(d) {
    scResetLoading();
    btn.textContent = 'ESCANEAR'; btn.disabled = false;
    clearInterval(dotInterval);
    if (d.error) { alert(d.error); document.getElementById('sc-empty').style.display='block'; return; }
    scCurrentData = d;
    scRenderResults(d);
    if (d.scan_id) { scActivarBtnPDF(d.scan_id); }
  })
  .catch(function() {
    scResetLoading();
    btn.textContent = 'ESCANEAR'; btn.disabled = false;
    clearInterval(dotInterval);
    alert('Error de conexión. Inténtalo de nuevo.');
    document.getElementById('sc-empty').style.display = 'block';
  });
}

function scResetLoading() {
  clearInterval(scProgInterval);
  var prog = document.getElementById('sc-prog'); if(prog) prog.style.width = '100%';
  setTimeout(function() {
    document.getElementById('sc-loading').style.display = 'none';
  }, 300);
}

function scRenderResults(d) {
  var col = d.riesgo >= 70 ? '#DC2626' : d.riesgo >= 40 ? '#D97706' : '#16A34A';
  document.getElementById('sc-res-obj').textContent = d.objetivo;
  document.getElementById('sc-res-ts').textContent = d.timestamp;

  var rEl = document.getElementById('sc-m-riesgo'); if(rEl) { rEl.textContent = d.riesgo + '%'; rEl.style.color = col; }
  var lEl = document.getElementById('sc-m-label'); if(lEl) { lEl.textContent = d.label; lEl.style.color = col; }
  document.getElementById('sc-m-puertos').textContent = (d.puertos || []).length;
  document.getElementById('sc-m-subs').textContent = (d.subs || []).length;
  var spf = d.dns && d.dns.SPF, dmarc = d.dns && d.dns.DMARC;
  var dnsEl = document.getElementById('sc-m-dns'); if(dnsEl) dnsEl.textContent = (spf && dmarc) ? '✓' : (spf || dmarc) ? '~' : '✗';
  var dnsSub = document.getElementById('sc-m-dns-sub'); if(dnsSub) dnsSub.textContent = (spf && dmarc) ? 'OK' : (!spf && !dmarc) ? 'Ambos ausentes' : 'Parcial';
  document.getElementById('sc-m-leaks').textContent = d.leaks || 0;

  document.getElementById('sc-results').style.display = 'block';

  scRenderGauge(d.riesgo, d.label);
  scRenderCards(d);
  scRenderHeadersChart(d.headers, 'sc-ch');
  scRenderRadarChart(d, 'sc-cr');

  var subsEl = document.getElementById('sc-subs-sec');
  if ((d.subs || []).length > 0) {
    subsEl.style.display = 'block';
    var tbody = document.getElementById('sc-subs-body');
    tbody.innerHTML = d.subs.map(function(s, i) {
      return '<tr><td>' + (i+1) + '</td><td>' + (s.subdominio || s) + '</td><td style="color:var(--muted)">' + (s.ip || '—') + '</td></tr>';
    }).join('');
  } else { subsEl.style.display = 'none'; }
}

function scRenderGauge(pct, lbl) {
  var col = pct >= 70 ? '#DC2626' : pct >= 40 ? '#D97706' : '#16A34A';
  var canvas = document.getElementById('sc-gauge');
  if (!canvas) return;
  if (scGaugeChart) scGaugeChart.destroy();
  scGaugeChart = new Chart(canvas, {
    type: 'doughnut',
    data: { datasets: [{ data: [pct, 100 - pct], backgroundColor: [col, '#E2E8F0'], borderWidth: 0, circumference: 180, rotation: 270 }] },
    options: { responsive: false, plugins: { legend: { display: false }, tooltip: { enabled: false } }, cutout: '75%' }
  });
  var pctEl = document.getElementById('sc-gpct'); if(pctEl) { pctEl.textContent = pct + '%'; pctEl.style.color = col; }
  var lblEl = document.getElementById('sc-glbl'); if(lblEl) lblEl.textContent = lbl;
}

function scRenderCards(d) {
  var html = '';
  var serviciosCrit = ["RDP","Telnet","MySQL","MongoDB","Redis","PostgreSQL","MSSQL","Docker API","Elasticsearch","VNC"];
  var critPorts = (d.puertos || []).filter(function(p){ return serviciosCrit.indexOf(p.servicio) !== -1; });
  if (critPorts.length) html += scCard('crit', critPorts.length + ' puerto' + (critPorts.length > 1 ? 's críticos' : ' crítico') + ' expuesto' + (critPorts.length > 1 ? 's' : ''), 'Accesibles: ' + critPorts.map(function(p){return p.puerto+'/'+p.servicio;}).join(', ') + '. Ciérralos en el firewall.', 'puerto');
  else if ((d.puertos || []).length === 0) html += scCard('ok', 'Sin puertos críticos expuestos', 'No se detectaron servicios sensibles accesibles.');
  else html += scCard('ok', 'Puertos bajo control', 'Solo puertos estándar detectados.');

  if (d.dns) {
    if (!d.dns.SPF && !d.dns.DMARC) html += scCard('crit', 'SPF y DMARC ausentes', 'Cualquiera puede enviar emails haciéndose pasar por tu empresa.', 'spf');
    else if (!d.dns.DMARC) html += scCard('warn', 'DMARC no configurado', 'Tu dominio puede ser suplantado. Añade el registro TXT.', 'dmarc');
    else if (!d.dns.SPF) html += scCard('warn', 'SPF no configurado', 'Riesgo de suplantación de correo.', 'spf');
    else html += scCard('ok', 'SPF y DMARC correctos', 'Tu dominio está protegido contra suplantación.');
  }

  if (d.headers) {
    var miss = [];
    if (!d.headers['X-Frame-Options'] && !d.headers['Content-Security-Policy']) miss.push('X-Frame-Options');
    if (!d.headers['Content-Security-Policy']) miss.push('CSP');
    if (!d.headers['X-Content-Type-Options']) miss.push('X-Content-Type-Options');
    if (miss.length >= 2) html += scCard('warn', miss.length + ' cabeceras HTTP ausentes', miss.slice(0,3).join(', ') + ' — expuesto a XSS y clickjacking.', 'headers');
    else if (miss.length === 1) html += scCard('warn', 'Cabecera ' + miss[0] + ' ausente', 'Configúrala en tu servidor.', 'headers');
    else html += scCard('ok', 'Cabeceras HTTP correctas', 'Las principales cabeceras de seguridad están configuradas.');
  }

  if (d.ssl) {
    if (!d.ssl.tiene_ssl) html += scCard('crit', 'Sin certificado SSL/TLS', 'Tu dominio no tiene HTTPS.', 'ssl');
    else if (d.ssl.caducado) html += scCard('crit', 'Certificado SSL caducado', 'Expiró el ' + (d.ssl.expira || '?') + '.', 'ssl');
    else if (d.ssl.pronto_a_caducar) html += scCard('warn', 'SSL caduca en ' + d.ssl.dias_restantes + ' días', 'Renuévalo pronto.', 'ssl');
    else html += scCard('ok', 'SSL/TLS válido', 'Caduca en ' + (d.ssl.dias_restantes || '?') + ' días.');
  }

  if ((d.leaks || 0) > 0) {
    html += scCard('crit', d.leaks + ' filtración' + (d.leaks > 1 ? 'es' : '') + ' detectada' + (d.leaks > 1 ? 's' : ''), (d.leaks_raw||[]).slice(0,3).map(function(f){return f.fuente||f;}).join(', ') || 'Credenciales comprometidas encontradas.', 'leaks');
  } else {
    html += scCard('ok', 'Sin filtraciones conocidas', 'No se encontraron datos en bases de brechas.');
  }

  document.getElementById('sc-cards').innerHTML = html;
}

var SC_REMEDIATION = {
  'puerto':   ['1. Accede al panel de firewall de tu hosting o servidor.', '2. Bloquea el tráfico entrante en los puertos listados (salvo si los necesitas explícitamente).', '3. Si son servicios internos (MySQL, Redis), asegúrate de que solo escuchan en 127.0.0.1.', '4. Vuelve a escanear para confirmar que están cerrados.'],
  'spf':      ['1. Accede al panel DNS de tu dominio (GoDaddy, Cloudflare, etc.).', '2. Crea un registro TXT con el valor: v=spf1 include:_spf.google.com ~all (ajusta según tu proveedor de email).', '3. Los cambios DNS tardan hasta 48h en propagarse.', '4. Verifica con: dig TXT tudominio.com'],
  'dmarc':    ['1. Accede al panel DNS de tu dominio.', '2. Crea un registro TXT en _dmarc.tudominio.com con: v=DMARC1; p=quarantine; rua=mailto:dmarc@tudominio.com', '3. Empieza con p=none para monitorizar antes de bloquear.', '4. Verifica con: dig TXT _dmarc.tudominio.com'],
  'headers':  ['1. Accede a la configuración de tu servidor web (nginx/Apache) o panel de hosting.', '2. Añade las cabeceras faltantes en la configuración HTTP.', '3. Ejemplo nginx: add_header X-Frame-Options "SAMEORIGIN";', '4. Recarga la configuración del servidor y vuelve a escanear.'],
  'ssl':      ['1. Accede al panel de tu proveedor de hosting.', '2. Busca la sección "SSL/TLS" o "Certificados".', '3. Si usas Let\'s Encrypt, ejecuta: sudo certbot renew', '4. Activa la renovación automática para evitar que caduque de nuevo.'],
  'leaks':    ['1. Identifica qué contraseñas están comprometidas en el informe detallado.', '2. Cámbia esas contraseñas INMEDIATAMENTE en todos los servicios afectados.', '3. Activa la autenticación en dos factores (2FA) en los servicios críticos.', '4. Notifica a los empleados afectados y registra el incidente (obligatorio en RGPD).']
};

function scCard(type, title, desc, remedKey) {
  var C = {
    crit: {b:'#FEE2E2',l:'#DC2626',bg:'#FEF2F2',c:'#DC2626',lbl:'CRÍTICO'},
    warn: {b:'#FEF3C7',l:'#D97706',bg:'#FFFBEB',c:'#D97706',lbl:'ADVERTENCIA'},
    ok:   {b:'#DCFCE7',l:'#16A34A',bg:'#F0FDF4',c:'#16A34A',lbl:'OK'}
  };
  var s = C[type] || C.ok;
  var remedHtml = '';
  if (remedKey && SC_REMEDIATION[remedKey] && type !== 'ok') {
    var steps = SC_REMEDIATION[remedKey].map(function(s){ return '<li style="margin-bottom:.3rem">' + s + '</li>'; }).join('');
    var uid = 'remed-' + Math.random().toString(36).slice(2,8);
    remedHtml = '<div style="margin-top:.6rem">' +
      '<span onclick="var el=document.getElementById(\'' + uid + '\');el.style.display=el.style.display===\'none\'?\'block\':\'none\'" style="font-size:.72rem;color:' + s.c + ';cursor:pointer;font-weight:600">▸ Cómo solucionarlo</span>' +
      '<ol id="' + uid + '" style="display:none;margin-top:.5rem;padding-left:1.2rem;font-size:.75rem;color:#475569;line-height:1.7">' + steps + '</ol>' +
      '</div>';
  }
  return '<div style="background:' + s.bg + ';border:1px solid ' + s.b + ';border-left:3px solid ' + s.l + ';border-radius:8px;padding:.9rem 1rem;margin-bottom:.5rem">' +
    '<span style="font-size:.6rem;font-family:\'JetBrains Mono\',monospace;background:' + s.b + ';color:' + s.c + ';padding:.15rem .5rem;border-radius:4px;font-weight:700;letter-spacing:.08em">' + s.lbl + '</span>' +
    '<div style="font-size:.85rem;font-weight:700;color:#0F172A;margin:.4rem 0 .2rem">' + title + '</div>' +
    '<div style="font-size:.78rem;color:#64748B">' + desc + '</div>' + remedHtml + '</div>';
}

function scRenderHeadersChart(headers, canvasId) {
  var canvas = document.getElementById(canvasId);
  if (!canvas) return;
  if (canvasId === 'sc-ch' && scHeadersChart) { scHeadersChart.destroy(); scHeadersChart = null; }
  if (canvasId === 'sc-dh' && scDashHeadersChart) { scDashHeadersChart.destroy(); scDashHeadersChart = null; }
  var keys = ['Content-Security-Policy','X-Frame-Options','X-Content-Type-Options','Strict-Transport-Security','Referrer-Policy','Permissions-Policy'];
  var labels = ['CSP','X-Frame','X-Type','HSTS','Referrer','Permissions'];
  var presente = keys.map(function(k){ return headers && headers[k] ? true : false; });
  var colors = presente.map(function(v){ return v ? 'rgba(22,163,74,.85)' : 'rgba(220,38,38,.75)'; });
  var newChart = new Chart(canvas, {
    type: 'bar',
    data: { labels: labels, datasets: [{ data: presente.map(function(){ return 1; }), backgroundColor: colors, borderRadius: 4, barThickness: 16 }] },
    options: {
      indexAxis: 'y', responsive: true, maintainAspectRatio: false,
      plugins: { legend: { display: false }, tooltip: { callbacks: { label: function(c){ return presente[c.dataIndex] ? '✓ Presente' : '✗ Ausente'; } } } },
      scales: { x: { display: false, max: 1, min: 0 }, y: { ticks: { font: { size: 10, family: 'JetBrains Mono' }, color: '#64748B' }, grid: { display: false } } }
    }
  });
  if (canvasId === 'sc-ch') scHeadersChart = newChart;
  else if (canvasId === 'sc-dh') scDashHeadersChart = newChart;
}

function scRenderRadarChart(d, canvasId) {
  var canvas = document.getElementById(canvasId);
  if (!canvas) return;
  var puertos = Math.min((d.puertos||[]).length * 10, 100);
  var dns = (d.dns && d.dns.SPF && d.dns.DMARC) ? 0 : (d.dns && (d.dns.SPF || d.dns.DMARC)) ? 40 : 80;
  var headers = 100 - Math.min(Object.values(d.headers||{}).filter(Boolean).length * 15, 100);
  var ssl = d.ssl && d.ssl.tiene_ssl && !d.ssl.caducado ? 0 : 70;
  var leaks = Math.min((d.leaks||0) * 25, 100);
  var newChart = new Chart(canvas, {
    type: 'radar',
    data: { labels: ['Puertos','DNS','Cabeceras','SSL','Filtraciones'], datasets: [{ data: [puertos, dns, headers, ssl, leaks], backgroundColor: 'rgba(220,38,38,.15)', borderColor: '#DC2626', borderWidth: 2, pointBackgroundColor: '#DC2626', pointRadius: 3 }] },
    options: { responsive: true, maintainAspectRatio: false, plugins: { legend: { display: false } }, scales: { r: { min: 0, max: 100, ticks: { display: false }, grid: { color: '#E2E8F0' }, pointLabels: { font: { size: 10 }, color: '#64748B' } } } }
  });
  if (canvasId === 'sc-cr') scRadarChart = newChart;
  else if (canvasId === 'sc-dr') scDashRadarChart = newChart;
}

function scRenderDashboard(d) {
  if (!d) return;
  document.getElementById('sc-dash-empty').style.display = 'none';
  document.getElementById('sc-dash-content').style.display = 'block';
  scRenderHeadersChart(d.headers, 'sc-dh');
  scRenderRadarChart(d, 'sc-dr');
  var canvas = document.getElementById('sc-dd');
  if (canvas) {
    if (scDashBarChart) scDashBarChart.destroy();
    var col = d.riesgo >= 70 ? '#DC2626' : d.riesgo >= 40 ? '#D97706' : '#16A34A';
    scDashBarChart = new Chart(canvas, {
      type: 'bar',
      data: { labels: [d.objetivo || 'Objetivo'], datasets: [{ data: [d.riesgo], backgroundColor: col, borderRadius: 6, barThickness: 32 }] },
      options: { indexAxis: 'y', responsive: true, maintainAspectRatio: false, plugins: { legend: { display: false } }, scales: { x: { max: 100, ticks: { color: '#64748B' }, grid: { color: '#F1F5F9' } }, y: { ticks: { color: '#64748B', font: { size: 11 } }, grid: { display: false } } } }
    });
  }
}

function scRenderExport(d) {
  if (!d) return;
  document.getElementById('sc-exp-empty').style.display = 'none';
  document.getElementById('sc-exp-content').style.display = 'block';
  var sum = document.getElementById('sc-exp-summary');
  if (sum) sum.innerHTML = '<strong>' + d.objetivo + '</strong> — Riesgo: <strong style="color:' + (d.riesgo>=70?'#DC2626':d.riesgo>=40?'#D97706':'#16A34A') + '">' + d.riesgo + '%</strong> · ' + d.timestamp;
  scUpdatePdfFreeCard(d);
}

function scUpdatePdfFreeCard(d) {
  var desc = document.getElementById('sc-pdf-desc');
  var icon = document.getElementById('sc-pdf-icon');
  var btn = document.getElementById('sc-pdf-btn');
  if (!desc) return;
  if (d && d.riesgo !== undefined) {
    desc.textContent = 'Informe listo para: ' + d.objetivo + ' (' + d.riesgo + '% riesgo). Requiere plan Pro.';
    if (icon) icon.textContent = '🔒';
    if (btn) btn.innerHTML = '<button class="sc-btn-exp p" onclick="scComprarInforme()" style="cursor:pointer">Desbloquear PDF — Pro 29€/mes</button>';
  }
}

function scComprarInforme() { pagarPlanLanding('pro'); }

function scActivarBtnPDF(scanId) {
  var btn = document.getElementById('sc-pdf-btn-buy');
  if (!btn) return;
  btn.disabled = false;
  btn.style.opacity = '1';
  btn.style.cursor = 'pointer';
  btn.textContent = 'Desbloquear informe — 9€';
  btn.onclick = function() { scComprarInforme9(scanId); };
}

function scPDFLoginRequired() {
  rbToast('Inicia sesión para desbloquear el informe PDF', 'error');
  setTimeout(function(){ window.location.href = '/login'; }, 1400);
}

function scComprarInforme9(scanId) {
  fetch('/api/checkout-informe', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({scan_id: scanId})
  })
  .then(function(r){ return r.json(); })
  .then(function(d){
    if (d.url) { window.open(d.url, '_blank'); }
    else { alert(d.error || 'Error al iniciar el pago'); }
  })
  .catch(function(){ alert('Error de conexión'); });
}

function scDescargarPDF() {
  if (!scCurrentData) return;
  fetch('/api/informe-pdf', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(scCurrentData) })
  .then(function(r){ return r.blob(); })
  .then(function(b) {
    var url = URL.createObjectURL(b);
    var a = document.createElement('a'); a.href = url; a.download = 'reconbase-' + (scCurrentData.objetivo||'informe') + '.pdf';
    document.body.appendChild(a); a.click(); document.body.removeChild(a); URL.revokeObjectURL(url);
  }).catch(function(){ alert('Error al generar el PDF.'); });
}

function scDescargarJSON() {
  if (!scCurrentData) return;
  var blob = new Blob([JSON.stringify(scCurrentData, null, 2)], {type:'application/json'});
  var url = URL.createObjectURL(blob);
  var a = document.createElement('a'); a.href = url; a.download = 'reconbase-' + (scCurrentData.objetivo||'datos') + '.json';
  document.body.appendChild(a); a.click(); document.body.removeChild(a); URL.revokeObjectURL(url);
}

function scLoadComparar(scans) {
  var selA = document.getElementById('sc-cmp-a');
  var selB = document.getElementById('sc-cmp-b');
  var empty = document.getElementById('sc-cmp-empty');
  if (!selA || !selB) return;
  if (!scans || scans.length < 2) {
    if (empty) empty.style.display = 'block';
    return;
  }
  if (empty) empty.style.display = 'none';
  selA.innerHTML = '<option value="">— Selecciona —</option>';
  selB.innerHTML = '<option value="">— Selecciona —</option>';
  scans.forEach(function(s, i) {
    var label = (s.objetivo || s.dominio) + ' · ' + (s.timestamp || '') + ' · ' + s.riesgo + '%';
    selA.innerHTML += '<option value="' + i + '">' + label + '</option>';
    selB.innerHTML += '<option value="' + i + '">' + label + '</option>';
  });
  selA.value = scans.length - 1;
  selB.value = 0;
  window._scCmpScans = scans;
}

function scComparar() {
  var selA = document.getElementById('sc-cmp-a');
  var selB = document.getElementById('sc-cmp-b');
  var result = document.getElementById('sc-cmp-result');
  if (!selA.value || !selB.value || selA.value === selB.value) {
    alert('Selecciona dos escaneos distintos.'); return;
  }
  var scans = window._scCmpScans || [];
  var a = scans[parseInt(selA.value)];
  var b = scans[parseInt(selB.value)];
  if (!a || !b) return;

  function delta(val_b, val_a, invert) {
    var d = val_b - val_a;
    if (d === 0) return '<span style="color:#64748B">= sin cambio</span>';
    var better = invert ? d < 0 : d > 0;
    var color = better ? '#DC2626' : '#16A34A';
    var arrow = d > 0 ? '▲' : '▼';
    return '<span style="color:' + color + '">' + arrow + ' ' + Math.abs(d) + '</span>';
  }

  var rows = [
    ['Riesgo', a.riesgo + '%', b.riesgo + '%', delta(b.riesgo, a.riesgo, false)],
    ['Puertos expuestos', (a.puertos||[]).length, (b.puertos||[]).length, delta((b.puertos||[]).length, (a.puertos||[]).length, false)],
    ['Filtraciones', a.leaks||0, b.leaks||0, delta(b.leaks||0, a.leaks||0, false)],
    ['Subdominios', (a.subs||[]).length, (b.subs||[]).length, delta((b.subs||[]).length, (a.subs||[]).length, true)],
    ['SPF', a.dns&&a.dns.SPF?'✓':'✗', b.dns&&b.dns.SPF?'✓':'✗', ''],
    ['DMARC', a.dns&&a.dns.DMARC?'✓':'✗', b.dns&&b.dns.DMARC?'✓':'✗', ''],
  ];

  var html = '<div style="overflow-x:auto"><table class="sc-hist-tbl"><thead><tr>' +
    '<th>Métrica</th><th>Escaneo A<br><span style="font-weight:400;color:var(--muted)">' + (a.timestamp||'') + '</span></th>' +
    '<th>Escaneo B<br><span style="font-weight:400;color:var(--muted)">' + (b.timestamp||'') + '</span></th><th>Cambio</th></tr></thead><tbody>';
  rows.forEach(function(r) {
    html += '<tr><td>' + r[0] + '</td><td>' + r[1] + '</td><td>' + r[2] + '</td><td>' + r[3] + '</td></tr>';
  });
  html += '</tbody></table></div>';

  var puertosA = (a.puertos||[]).map(function(p){return p.puerto;});
  var puertosNuevos = (b.puertos||[]).filter(function(p){return puertosA.indexOf(p.puerto) === -1;});
  if (puertosNuevos.length) {
    html += '<div style="margin-top:1rem;background:#FEF2F2;border:1px solid #FEE2E2;border-radius:8px;padding:.85rem 1rem">' +
      '<div style="font-size:.72rem;font-family:\'JetBrains Mono\',monospace;color:#DC2626;font-weight:700;margin-bottom:.4rem">NUEVOS PUERTOS EN B</div>' +
      '<div style="font-size:.8rem;color:#7F1D1D">' + puertosNuevos.map(function(p){return p.puerto+'/'+p.servicio;}).join(', ') + '</div></div>';
  }

  result.innerHTML = html;
  result.style.display = 'block';
}

function scLoadHistorial() {
  fetch('/api/historial').then(function(r){return r.json();}).then(function(d){
    var scans = d.scans || [];
    scRenderHistorial(scans);
    scLoadComparar(scans);
  }).catch(function(){ scRenderHistorial([]); scLoadComparar([]); });
}

function scRenderHistorial(scans) {
  var empty = document.getElementById('sc-hist-empty');
  var content = document.getElementById('sc-hist-content');
  var tbody = document.getElementById('sc-hist-body');
  if (!scans || scans.length === 0) {
    empty.style.display = 'block'; content.style.display = 'none'; return;
  }
  empty.style.display = 'none'; content.style.display = 'block';
  tbody.innerHTML = scans.map(function(s, i) {
    var col = s.riesgo >= 70 ? '#DC2626' : s.riesgo >= 40 ? '#D97706' : '#16A34A';
    return '<tr>' +
      '<td style="color:var(--muted)">' + (i+1) + '</td>' +
      '<td><code style="font-size:.8rem">' + s.objetivo + '</code></td>' +
      '<td><span style="color:' + col + ';font-weight:700">' + s.riesgo + '%</span></td>' +
      '<td>' + (s.puertos||[]).length + '</td>' +
      '<td>' + (s.leaks||0) + '</td>' +
      '<td style="color:var(--muted);font-size:.78rem">' + (s.timestamp||'') + '</td>' +
      '<td><button onclick="scVerScanHistorial(' + s.scan_id + ')" style="background:var(--surface);border:1px solid var(--border);color:var(--text);padding:.3rem .75rem;border-radius:5px;font-size:.75rem;cursor:pointer">Ver</button></td>' +
      '</tr>';
  }).join('');
}

function scVerScanHistorial(id) {
  fetch('/api/scan/' + id).then(function(r){return r.json();}).then(function(d){
    if (d.error) { alert(d.error); return; }
    scCurrentData = d;
    var tabs = document.querySelectorAll('.sc-tab');
    tabs.forEach(function(t){ t.classList.remove('active'); });
    if (tabs[0]) tabs[0].classList.add('active');
    document.querySelectorAll('.sc-panel').forEach(function(p){ p.classList.remove('active'); });
    document.getElementById('sc-auditoria').classList.add('active');
    document.getElementById('sc-objetivo').value = d.objetivo;
    scRenderResults(d);
    document.getElementById('escaner').scrollIntoView({behavior:'smooth', block:'start'});
  }).catch(function(){ alert('Error al cargar el escaneo.'); });
}

/* Palette for multi-domain chart lines */
var _SC_COLORS = [
  { line: '#DC2626', bg: 'rgba(220,38,38,.10)' },
  { line: '#2563EB', bg: 'rgba(37,99,235,.10)' },
  { line: '#D97706', bg: 'rgba(217,119,6,.10)'  },
  { line: '#7C3AED', bg: 'rgba(124,58,237,.10)' },
  { line: '#059669', bg: 'rgba(5,150,105,.10)'  },
  { line: '#DB2777', bg: 'rgba(219,39,119,.10)' },
];

function scRenderTendencia() {
  fetch('/api/evolucion').then(function(r){return r.json();}).then(function(d){
    var series = d.series || {};
    var domainKeys = Object.keys(series);
    var empty = document.getElementById('sc-tend-empty');
    var content = document.getElementById('sc-tend-content');

    /* Need at least one domain with ≥2 points */
    var hasData = domainKeys.some(function(k){ return (series[k]||[]).length >= 2; });
    if (!hasData) { empty.style.display = 'block'; content.style.display = 'none'; return; }
    empty.style.display = 'none'; content.style.display = 'block';

    /* Build a unified sorted set of dates across all domains */
    var dateSet = {};
    domainKeys.forEach(function(k){
      (series[k]||[]).forEach(function(p){ dateSet[p.fecha] = true; });
    });
    var labels = Object.keys(dateSet).sort();

    /* Aggregate all values for global stats */
    var allValues = [];
    domainKeys.forEach(function(k){
      (series[k]||[]).forEach(function(p){ allValues.push(p.riesgo); });
    });
    var avg = Math.round(allValues.reduce(function(a,b){return a+b;},0) / (allValues.length||1));
    var minV = Math.min.apply(null, allValues), maxV = Math.max.apply(null, allValues);

    /* Per-domain trend (last − first) for each domain */
    var trendHtml = domainKeys.map(function(k, i){
      var pts = (series[k]||[]).slice().sort(function(a,b){return a.fecha>b.fecha?1:-1;});
      var col = _SC_COLORS[i % _SC_COLORS.length];
      var tval = pts.length >= 2 ? pts[pts.length-1].riesgo - pts[0].riesgo : 0;
      var tcolor = tval > 0 ? '#DC2626' : tval < 0 ? '#16A34A' : '#64748B';
      return '<div style="background:var(--surface);border:1px solid ' + col.line + '44;border-radius:8px;padding:.75rem 1rem;display:flex;align-items:center;gap:.6rem">' +
        '<span style="display:inline-block;width:10px;height:10px;border-radius:50%;background:' + col.line + ';flex-shrink:0"></span>' +
        '<div style="flex:1;min-width:0"><div style="font-size:.62rem;font-family:\'JetBrains Mono\',monospace;color:var(--muted);text-transform:uppercase;letter-spacing:.06em;white-space:nowrap;overflow:hidden;text-overflow:ellipsis">' + k + '</div>' +
        '<div style="font-size:1.1rem;font-weight:800;color:' + tcolor + '">' + (tval > 0 ? '+' : '') + tval + '%</div></div></div>';
    }).join('');

    var statsEl = document.getElementById('sc-tend-stats');
    if (statsEl) {
      /* Override grid cols to fit domain cards + global stats */
      statsEl.style.gridTemplateColumns = 'repeat(auto-fill,minmax(140px,1fr))';
      statsEl.innerHTML =
        '<div style="background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:1rem;text-align:center"><div style="font-size:.65rem;font-family:\'JetBrains Mono\',monospace;color:var(--muted);margin-bottom:.4rem">PROMEDIO GLOBAL</div><div style="font-size:1.5rem;font-weight:800">' + avg + '%</div></div>' +
        '<div style="background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:1rem;text-align:center"><div style="font-size:.65rem;font-family:\'JetBrains Mono\',monospace;color:var(--muted);margin-bottom:.4rem">MÍNIMO</div><div style="font-size:1.5rem;font-weight:800;color:#16A34A">' + minV + '%</div></div>' +
        '<div style="background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:1rem;text-align:center"><div style="font-size:.65rem;font-family:\'JetBrains Mono\',monospace;color:var(--muted);margin-bottom:.4rem">MÁXIMO</div><div style="font-size:1.5rem;font-weight:800;color:#DC2626">' + maxV + '%</div></div>' +
        '<div style="background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:1rem;text-align:center"><div style="font-size:.65rem;font-family:\'JetBrains Mono\',monospace;color:var(--muted);margin-bottom:.4rem">DOMINIOS</div><div style="font-size:1.5rem;font-weight:800">' + domainKeys.length + '</div></div>';
      /* Trend chips per domain below stats (only if >1 domain) */
      if (domainKeys.length > 0) {
        var trendWrapper = document.getElementById('sc-tend-trends');
        if (!trendWrapper) {
          trendWrapper = document.createElement('div');
          trendWrapper.id = 'sc-tend-trends';
          trendWrapper.style.cssText = 'display:grid;grid-template-columns:repeat(auto-fill,minmax(160px,1fr));gap:.5rem;margin-top:.75rem';
          statsEl.parentNode.insertBefore(trendWrapper, statsEl.nextSibling);
        }
        trendWrapper.innerHTML = trendHtml;
      }
    }

    /* Build Chart.js datasets — one per domain */
    var datasets = domainKeys.map(function(k, i){
      var col = _SC_COLORS[i % _SC_COLORS.length];
      var pts = series[k] || [];
      /* Map to label positions (sparse: null where no data for that date) */
      var dataMap = {};
      pts.forEach(function(p){ dataMap[p.fecha] = p.riesgo; });
      var data = labels.map(function(l){ return dataMap[l] !== undefined ? dataMap[l] : null; });
      return {
        label: k,
        data: data,
        borderColor: col.line,
        backgroundColor: col.bg,
        tension: 0.35,
        fill: domainKeys.length === 1,  /* fill only when single domain */
        pointBackgroundColor: col.line,
        pointRadius: 4,
        spanGaps: true
      };
    });

    var canvas = document.getElementById('sc-tend-chart');
    if (canvas) {
      if (scTendChart) scTendChart.destroy();
      scTendChart = new Chart(canvas, {
        type: 'line',
        data: { labels: labels, datasets: datasets },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          interaction: { mode: 'index', intersect: false },
          plugins: {
            legend: {
              display: domainKeys.length > 1,
              labels: { color: '#94A3B8', font: { family: "'JetBrains Mono',monospace", size: 11 }, boxWidth: 12, boxHeight: 12 }
            },
            tooltip: {
              callbacks: {
                label: function(ctx) { return ' ' + ctx.dataset.label + ': ' + (ctx.parsed.y !== null ? ctx.parsed.y + '%' : '—'); }
              }
            }
          },
          scales: {
            y: { min: 0, max: 100, ticks: { color: '#64748B', callback: function(v){ return v + '%'; } }, grid: { color: 'rgba(255,255,255,.05)' } },
            x: { ticks: { color: '#64748B', font: { size: 10 } }, grid: { display: false } }
          }
        }
      });
    }

    /* Table: all scans across all domains sorted by date desc */
    var allScans = [];
    domainKeys.forEach(function(k){
      (series[k]||[]).forEach(function(p){ allScans.push(Object.assign({}, p, {dominio: k})); });
    });
    allScans.sort(function(a,b){ return a.fecha > b.fecha ? -1 : 1; });
    var tbody = document.getElementById('sc-tend-body');
    if (tbody) tbody.innerHTML = allScans.map(function(s, i){
      var col = s.riesgo >= 70 ? '#DC2626' : s.riesgo >= 40 ? '#D97706' : '#16A34A';
      var di = domainKeys.indexOf(s.dominio);
      var dc = _SC_COLORS[di >= 0 ? di % _SC_COLORS.length : 0].line;
      return '<tr><td>' + (i+1) + '</td><td><code style="font-size:.78rem;color:' + dc + '">' + (s.dominio||s.objetivo||'—') + '</code></td><td style="color:' + col + ';font-weight:700">' + s.riesgo + '%</td><td>—</td><td>—</td><td>—</td><td style="font-size:.78rem;color:var(--muted)">' + (s.label||s.fecha||'') + '</td></tr>';
    }).join('');
  }).catch(function(){
    /* Fallback to historial if evolucion not available */
    fetch('/api/historial').then(function(r){return r.json();}).then(function(d){
      var scans = (d.scans || d || []).slice().reverse();
      var empty = document.getElementById('sc-tend-empty');
      var content = document.getElementById('sc-tend-content');
      if (scans.length < 2) { empty.style.display = 'block'; content.style.display = 'none'; return; }
      empty.style.display = 'none'; content.style.display = 'block';
      var riesgos = scans.map(function(s){return s.riesgo;});
      var avg = Math.round(riesgos.reduce(function(a,b){return a+b;},0)/riesgos.length);
      var min = Math.min.apply(null, riesgos), max = Math.max.apply(null, riesgos);
      var trend = riesgos[riesgos.length-1] - riesgos[0];
      var statsEl = document.getElementById('sc-tend-stats');
      if (statsEl) statsEl.innerHTML =
        '<div style="background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:1rem;text-align:center"><div style="font-size:.65rem;font-family:\'JetBrains Mono\',monospace;color:var(--muted);margin-bottom:.4rem">PROMEDIO</div><div style="font-size:1.5rem;font-weight:800">' + avg + '%</div></div>' +
        '<div style="background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:1rem;text-align:center"><div style="font-size:.65rem;font-family:\'JetBrains Mono\',monospace;color:var(--muted);margin-bottom:.4rem">MÍNIMO</div><div style="font-size:1.5rem;font-weight:800;color:#16A34A">' + min + '%</div></div>' +
        '<div style="background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:1rem;text-align:center"><div style="font-size:.65rem;font-family:\'JetBrains Mono\',monospace;color:var(--muted);margin-bottom:.4rem">MÁXIMO</div><div style="font-size:1.5rem;font-weight:800;color:#DC2626">' + max + '%</div></div>' +
        '<div style="background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:1rem;text-align:center"><div style="font-size:.65rem;font-family:\'JetBrains Mono\',monospace;color:var(--muted);margin-bottom:.4rem">TENDENCIA</div><div style="font-size:1.5rem;font-weight:800;color:' + (trend>0?'#DC2626':trend<0?'#16A34A':'#64748B') + '">' + (trend>0?'+':'') + trend + '%</div></div>';
      var canvas = document.getElementById('sc-tend-chart');
      if (canvas) {
        if (scTendChart) scTendChart.destroy();
        scTendChart = new Chart(canvas, { type:'line', data:{ labels:scans.map(function(s){return(s.timestamp||'').split(' ')[0];}), datasets:[{label:'Riesgo (%)',data:riesgos,borderColor:'#DC2626',backgroundColor:'rgba(220,38,38,.08)',tension:0.4,fill:true,pointBackgroundColor:'#DC2626',pointRadius:4}]}, options:{responsive:true,maintainAspectRatio:false,plugins:{legend:{display:false}},scales:{y:{min:0,max:100,ticks:{color:'#64748B'},grid:{color:'rgba(255,255,255,.05)'}},x:{ticks:{color:'#64748B',font:{size:10}},grid:{display:false}}}}});
      }
      var tbody = document.getElementById('sc-tend-body');
      if (tbody) tbody.innerHTML = scans.map(function(s,i){ var col=s.riesgo>=70?'#DC2626':s.riesgo>=40?'#D97706':'#16A34A'; return '<tr><td>'+(i+1)+'</td><td><code style="font-size:.78rem">'+s.objetivo+'</code></td><td style="color:'+col+';font-weight:700">'+s.riesgo+'%</td><td>'+(s.puertos||[]).length+'</td><td>'+(s.leaks||0)+'</td><td>'+(s.subs||[]).length+'</td><td style="font-size:.78rem;color:var(--muted)">'+(s.timestamp||'')+'</td></tr>'; }).join('');
    }).catch(function(){});
  });
}

function scToggleVig() {
  var activo = document.getElementById('sc-vig-activo').checked;
  var config = document.getElementById('sc-vig-config');
  var saveOff = document.getElementById('sc-vig-save-off');
  if (config) config.style.display = activo ? 'block' : 'none';
  if (saveOff) saveOff.style.display = activo ? 'none' : 'block';
}

function scGuardarHorario() {
  var activo = document.getElementById('sc-vig-activo') && document.getElementById('sc-vig-activo').checked;
  var hora = activo ? parseInt(document.getElementById('sc-vig-hora').value) : 3;
  var dias = [];
  if (activo) {
    [0,1,2,3,4,5,6].forEach(function(d) {
      var el = document.getElementById('sc-dia-' + d);
      if (el && el.checked) dias.push(d);
    });
  }
  fetch('/api/horario', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({hora:hora, dias:dias, activo:activo})})
  .then(function(r){return r.json();})
  .then(function(d) {
    var msg = document.getElementById('sc-vig-msg');
    if (msg) { msg.textContent = d.ok ? '✓ Guardado correctamente' : (d.error || 'Error al guardar'); msg.style.color = d.ok ? '#16A34A' : '#DC2626'; msg.style.display = 'block'; setTimeout(function(){msg.style.display='none';},3000); }
  }).catch(function(){});
}

function cerrarSesionLanding() {
  fetch('/api/logout', {method:'POST'}).then(function(){window.location.href='/';}).catch(function(){window.location.href='/';});
}

function rbToast(msg, type) {
  var existing = document.getElementById('rb-toast');
  if (existing) existing.remove();
  var t = document.createElement('div');
  t.id = 'rb-toast';
  var isOk = type !== 'error';
  t.style.cssText = 'position:fixed;bottom:1.75rem;left:50%;transform:translateX(-50%);z-index:99999;background:#0A1410;border:1px solid '+(isOk?'#166534':'#7F1D1D')+';color:'+(isOk?'#4ADE80':'#F87171')+';padding:.85rem 1.75rem;border-radius:9px;font-size:.87rem;font-weight:600;white-space:nowrap;box-shadow:0 8px 30px rgba(0,0,0,.5);transition:opacity .3s';
  t.textContent = msg;
  document.body.appendChild(t);
  setTimeout(function(){
    t.style.opacity = '0';
    setTimeout(function(){ if (t.parentNode) t.parentNode.removeChild(t); }, 300);
  }, 3200);
}

function activarTrial() {
  var btn = document.getElementById('btn-trial');
  if (btn) { btn.disabled = true; btn.textContent = 'Activando...'; }
  fetch('/api/activar-trial', {method:'POST', headers:{'Content-Type':'application/json'}})
  .then(function(r){ return r.json(); })
  .then(function(d) {
    if (d.ok) {
      rbToast('✓ Trial Pro activado hasta el ' + d.trial_end, 'ok');
      setTimeout(function(){ location.reload(); }, 1800);
    } else {
      rbToast(d.error || 'Error al activar el trial', 'error');
      if (btn) { btn.disabled = false; btn.textContent = '7 días Pro gratis →'; }
    }
  })
  .catch(function(){ rbToast('Error de conexión', 'error'); if (btn) { btn.disabled = false; } });
}

var billingAnual = false;
function toggleBilling() {
  billingAnual = !billingAnual;
  var knob = document.getElementById('billing-knob');
  var toggle = document.getElementById('billing-toggle');
  var lblM = document.getElementById('lbl-mensual');
  var lblA = document.getElementById('lbl-anual');
  var price = document.getElementById('pro-price');
  var note = document.getElementById('pro-anual-note');
  var btn = document.getElementById('btn-pro-subscribe');
  if (billingAnual) {
    if (knob) knob.style.left = '23px';
    if (toggle) toggle.style.background = '#166534';
    if (lblM) lblM.style.color = '#64748B';
    if (lblA) lblA.style.color = '#E2EDF8';
    if (price) price.textContent = '24';
    if (note) note.style.display = 'block';
    if (btn) btn.textContent = 'Suscribirse — 290€/año';
  } else {
    if (knob) knob.style.left = '3px';
    if (toggle) toggle.style.background = '#152B1E';
    if (lblM) lblM.style.color = '#E2EDF8';
    if (lblA) lblA.style.color = '#64748B';
    if (price) price.textContent = '29';
    if (note) note.style.display = 'none';
    if (btn) btn.textContent = 'Suscribirse — 29€/mes';
  }
}
function pagarPlanActual() {
  var plan = billingAnual ? 'pro_anual' : 'pro';
  pagarPlanLanding(plan);
}

function pagarPlanLanding(plan) {
  fetch('/api/checkout', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({plan:plan})})
  .then(function(r){return r.json();})
  .then(function(d){ if(d.url){window.open(d.url,'_blank');}else{alert(d.error||'Error al iniciar el pago');} })
  .catch(function(){alert('Error de conexión.');});
}

// Auto-rellenar objetivo desde ?target=
(function() {
  var params = new URLSearchParams(window.location.search);
  var target = params.get('target');
  if (target) {
    var inp = document.getElementById('sc-objetivo');
    if (inp) { inp.value = target; }
    var heroInp = document.getElementById('hero-domain');
    if (heroInp) heroInp.value = target;
    var secEl = document.getElementById('escaner');
    if (secEl) setTimeout(function(){ secEl.scrollIntoView({behavior:'smooth',block:'start'}); }, 400);
  }
  var tab = params.get('tab');
  if (tab) {
    var tabEl = document.querySelector('.sc-tab[onclick*="\'' + tab + '\'"]');
    if (tabEl) tabEl.click();
  }
  if (params.get('pago') === 'ok') {
    setTimeout(function(){ alert('¡Pago completado! Tu plan Pro ya está activo. Recarga la página si no ves los cambios.'); }, 800);
  }
})();
