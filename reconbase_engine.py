import concurrent.futures
import requests
import socket
import ssl
import datetime
import re as _re
import time
import schedule

try:
    import dns.resolver
    DNS_DISPONIBLE = True
except ImportError:
    DNS_DISPONIBLE = False

# ─────────────────────────────────────────────────────────────
# MÓDULO 1: FILTRACIONES (Have I Been Pwned)
# ─────────────────────────────────────────────────────────────
def check_leaks_real(email, api_key, timeout=8):
    if not api_key:
        return None
    url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}"
    headers = {"hibp-api-key": api_key, "user-agent": "ReconBase-Enterprise-v2"}
    try:
        r = requests.get(url, headers=headers, params={"truncateResponse":"false"}, timeout=timeout)
        if r.status_code == 200: return r.json()
        if r.status_code == 404: return []
    except Exception as e:
        print(f"[!] HIBP error: {e}")
    return None

# ─────────────────────────────────────────────────────────────
# MÓDULO 2: AUTENTICACIÓN DE CORREO (SPF / DMARC)
# ─────────────────────────────────────────────────────────────
def check_email_spoofing(domain, timeout=5):
    resultados = {"SPF": False, "DMARC": False, "SPF_raw": "", "DMARC_raw": ""}

    if not DNS_DISPONIBLE:
        try:
            r = requests.get(f"https://dns.google/resolve?name={domain}&type=TXT", timeout=timeout).json()
            for a in r.get("Answer",[]):
                if "v=spf1" in a.get("data",""):
                    resultados["SPF"] = True; break
            r2 = requests.get(f"https://dns.google/resolve?name=_dmarc.{domain}&type=TXT", timeout=timeout).json()
            for a in r2.get("Answer",[]):
                if "v=DMARC1" in a.get("data",""):
                    resultados["DMARC"] = True; break
        except Exception: pass
        return resultados

    try:
        res = dns.resolver.Resolver(); res.lifetime = timeout
        for rd in res.resolve(domain,"TXT"):
            if "v=spf1" in rd.to_text():
                resultados["SPF"] = True; break
    except Exception: pass
    try:
        res = dns.resolver.Resolver(); res.lifetime = timeout
        for rd in res.resolve(f"_dmarc.{domain}","TXT"):
            if "v=DMARC1" in rd.to_text():
                resultados["DMARC"] = True; break
    except Exception: pass
    return resultados

# ─────────────────────────────────────────────────────────────
# MÓDULO 3: ESCÁNER DE PUERTOS
# ─────────────────────────────────────────────────────────────
PUERTOS = {
    21:"FTP",22:"SSH",23:"Telnet",25:"SMTP",53:"DNS",80:"HTTP",
    110:"POP3",143:"IMAP",443:"HTTPS",445:"SMB",1433:"MSSQL",
    1521:"Oracle DB",2375:"Docker API",3306:"MySQL",3389:"RDP",
    5432:"PostgreSQL",5900:"VNC",6379:"Redis",8080:"HTTP-alt",
    8443:"HTTPS-alt",8888:"Jupyter",9200:"Elasticsearch",27017:"MongoDB",
}

def check_single_port(domain, port, timeout=1.5):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        r = s.connect_ex((domain, port))
    except Exception:
        r = 1
    finally:
        s.close()
    return port if r == 0 else None

def scan_critical_ports_fast(domain, max_workers=50, timeout=1.5):
    abiertos = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = {ex.submit(check_single_port, domain, p, timeout): p for p in PUERTOS}
        for f in concurrent.futures.as_completed(futures):
            p = f.result()
            if p: abiertos.append({"puerto": p, "servicio": PUERTOS[p]})
    return sorted(abiertos, key=lambda x: x["puerto"])

# ─────────────────────────────────────────────────────────────
# MÓDULO 4: CABECERAS HTTP
# ─────────────────────────────────────────────────────────────
CABECERAS = {
    "Strict-Transport-Security": "HSTS",
    "X-Frame-Options":           "Anti-Clickjacking",
    "X-Content-Type-Options":    "MIME-Sniffing",
    "Content-Security-Policy":   "CSP",
    "Referrer-Policy":           "Referrer-Policy",
    "Permissions-Policy":        "Permissions-Policy",
}

def check_security_headers(domain, timeout=6):
    """Comprueba cabeceras de seguridad. Usa UA de navegador real para evitar
    que Cloudflare/CDNs sirvan una página de bot-challenge sin las cabeceras
    reales del sitio (que era lo que pasaba con UA 'ReconBase-Enterprise-v2')."""
    resultados = {v: False for v in CABECERAS.values()}
    browser_ua = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                  "AppleWebKit/537.36 (KHTML, like Gecko) "
                  "Chrome/126.0.0.0 Safari/537.36")
    for scheme in ["https","http"]:
        try:
            r = requests.get(f"{scheme}://{domain}", timeout=timeout,
                             allow_redirects=True,
                             headers={
                                 "User-Agent": browser_ua,
                                 "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                                 "Accept-Language": "es-ES,es;q=0.9,en;q=0.8",
                             })
            for k, v in CABECERAS.items():
                if k in r.headers: resultados[v] = True
            return resultados
        except Exception:
            continue
    return resultados

# ─────────────────────────────────────────────────────────────
# MÓDULO 5: SUBDOMINIOS
# ─────────────────────────────────────────────────────────────
SUBDOMINIOS = [
    "www","mail","webmail","smtp","ftp","vpn","remote","rdp",
    "admin","panel","cpanel","webadmin","portal","app","api","api2",
    "dev","development","staging","stage","test","qa","beta",
    "blog","shop","store","cdn","static","assets","media",
    "old","backup","legacy","intranet","internal",
    "jira","gitlab","jenkins","grafana","kibana","monitor",
    "db","mysql","postgres","redis","mongo",
    "auth","login","sso","docs","help","support","status",
]

def check_subdomain(sub, domain, timeout=2):
    target = f"{sub}.{domain}"
    try:
        ip = socket.gethostbyname(target)
        return {"subdominio": target, "ip": ip}
    except Exception:
        return None

def scan_subdomains(domain, max_workers=30):
    found = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = [ex.submit(check_subdomain, s, domain) for s in SUBDOMINIOS]
        for f in concurrent.futures.as_completed(futures):
            r = f.result()
            if r: found.append(r)
    return sorted(found, key=lambda x: x["subdominio"])

# ─────────────────────────────────────────────────────────────
# MÓDULO 6: DETECCIÓN DE CMS
# ─────────────────────────────────────────────────────────────
CMS_SIGNATURES = {
    "WordPress": {
        "html": ["wp-content/", "wp-includes/", "wp-json"],
        "headers": {"x-powered-by": "wordpress"},
        "paths": ["/wp-login.php", "/wp-admin/"],
        "meta_generator": "wordpress",
    },
    "Joomla": {
        "html": ["/components/com_", "/media/jui/", "joomla"],
        "headers": {},
        "paths": ["/administrator/"],
        "meta_generator": "joomla",
    },
    "Drupal": {
        "html": ["/sites/default/files/", "drupal.js", "Drupal.settings"],
        "headers": {"x-generator": "drupal", "x-drupal-cache": ""},
        "paths": [],
        "meta_generator": "drupal",
    },
    "PrestaShop": {
        "html": ["/themes/default-bootstrap/", "prestashop", "/modules/blockcart/"],
        "headers": {"x-powered-by": "prestashop"},
        "paths": [],
        "meta_generator": "prestashop",
    },
    "Magento": {
        "html": ["mage/cookies.js", "Magento_", "/skin/frontend/"],
        "headers": {"x-powered-by": "phusion"},
        "paths": ["/admin/", "/downloader/"],
        "meta_generator": "magento",
    },
    "Shopify": {
        "html": ["cdn.shopify.com", "shopify.com/s/files", "Shopify.theme"],
        "headers": {"x-shopid": "", "x-shopify-stage": ""},
        "paths": [],
        "meta_generator": "shopify",
    },
    "Wix": {
        "html": ["static.wixstatic.com", "wix-code-sdk", "_wix_"],
        "headers": {"x-wix-request-id": ""},
        "paths": [],
        "meta_generator": "wix",
    },
    "Squarespace": {
        "html": ["squarespace.com", "static1.squarespace.com"],
        "headers": {"x-powered-by": "squarespace"},
        "paths": [],
        "meta_generator": "squarespace",
    },
}

def detect_cms(domain, timeout=7):
    """Detecta el CMS del dominio. Devuelve dict con cms, version, riesgo."""
    result = {"cms": None, "version": None, "riesgo": False, "detalle": ""}
    try:
        for scheme in ["https", "http"]:
            try:
                r = requests.get(
                    f"{scheme}://{domain}", timeout=timeout,
                    allow_redirects=True,
                    headers={"User-Agent": "Mozilla/5.0 (compatible; ReconBase/2.0)"}
                )
                html = r.text.lower()
                headers = {k.lower(): v.lower() for k, v in r.headers.items()}

                # Extract meta generator
                import re
                gen_match = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)["\']', r.text, re.I)
                generator = gen_match.group(1) if gen_match else ""

                for cms_name, sigs in CMS_SIGNATURES.items():
                    detected = False
                    version = None

                    # Check meta generator
                    if sigs["meta_generator"] in generator.lower():
                        detected = True
                        # Try to extract version from generator tag
                        ver_match = re.search(r'(\d+\.\d+[\.\d]*)', generator)
                        if ver_match:
                            version = ver_match.group(1)

                    # Check HTML signatures
                    if not detected:
                        for sig in sigs["html"]:
                            if sig.lower() in html:
                                detected = True
                                break

                    # Check response headers
                    if not detected:
                        for hdr, val in sigs["headers"].items():
                            if hdr in headers and (not val or val in headers[hdr]):
                                detected = True
                                break

                    if detected:
                        result["cms"] = cms_name
                        result["version"] = version
                        # WordPress: check version via wp-json
                        if cms_name == "WordPress" and not version:
                            try:
                                wp = requests.get(f"{scheme}://{domain}/wp-json/", timeout=4,
                                                  headers={"User-Agent": "Mozilla/5.0"})
                                if wp.status_code == 200:
                                    import json
                                    wp_data = wp.json()
                                    version = wp_data.get("version")
                                    if version:
                                        result["version"] = str(version)
                            except Exception:
                                pass
                        # Mark as risky if version exposed or specific CMS
                        result["riesgo"] = cms_name in ["WordPress", "Joomla", "PrestaShop", "Magento"]
                        if result["riesgo"]:
                            result["detalle"] = (
                                f"Se ha detectado {cms_name}"
                                + (f" v{version}" if version else "")
                                + ". Los CMS desactualizados son el vector de ataque mas comun en PYMEs. Mantén siempre la última versión y sus plugins actualizados."
                            )
                        else:
                            result["detalle"] = f"Se ha detectado {cms_name}. Asegurate de mantenerlo actualizado."
                        return result
                return result  # No CMS detected
            except requests.exceptions.SSLError:
                continue
            except Exception:
                break
    except Exception:
        pass
    return result

# ─────────────────────────────────────────────────────────────
# MÓDULO 6b: AUDITORÍA WORDPRESS DEDICADA
# ─────────────────────────────────────────────────────────────
# Versión de referencia (latest stable). Actualizar manualmente cada release.
_WP_LATEST_VERSION = "6.7"

# Plugins WordPress con vulnerabilidades conocidas (ejemplos comunes 2024-2026).
# Cuando detectamos uno de estos, lo marcamos como riesgo crítico.
_WP_VULNERABLE_PLUGINS = {
    # plugin_slug: (vuln descripcion, severidad)
    "wp-file-manager":     ("RCE pre-auth conocido (CVE-2020-25213) — actualizar urgente", "critical"),
    "wp-statistics":       ("SQLi y XSS en versiones <14.x", "high"),
    "elementor":           ("Verifica versión <3.20 — XSS conocidos", "medium"),
    "duplicator":          ("RCE en versiones <1.5.4 — actualizar", "critical"),
    "all-in-one-seo-pack": ("XSS reflejado en versiones antiguas", "medium"),
    "advanced-custom-fields": ("Verifica versión <6.2 — escalation conocida", "high"),
    "woocommerce":         ("Mantener al día — vector típico de skimmers", "medium"),
    "contact-form-7":      ("Versiones <5.7 con upload vulnerable", "high"),
    "really-simple-ssl":   ("Versiones <7.1 con escalation de privilegios", "high"),
    "wpforms-lite":        ("XSS en versiones antiguas", "medium"),
}


def _safe_get(url, timeout=5, headers=None):
    """GET defensivo. Devuelve response o None."""
    try:
        h = headers or {"User-Agent": "Mozilla/5.0 (compatible; ReconBase-WP/2.0)"}
        return requests.get(url, timeout=timeout, allow_redirects=True, headers=h)
    except Exception:
        return None


def _wp_version_outdated(version):
    """Compara versión detectada con _WP_LATEST_VERSION. Devuelve bool y diff approx."""
    if not version:
        return False, None
    try:
        cur_parts = [int(x) for x in version.split(".")[:2]]
        latest_parts = [int(x) for x in _WP_LATEST_VERSION.split(".")[:2]]
        while len(cur_parts) < 2: cur_parts.append(0)
        while len(latest_parts) < 2: latest_parts.append(0)
        # Mayor o menor
        if cur_parts[0] < latest_parts[0]:
            return True, f"{latest_parts[0]-cur_parts[0]} versiones mayores por detrás"
        if cur_parts[0] == latest_parts[0] and cur_parts[1] < latest_parts[1]:
            return True, f"{latest_parts[1]-cur_parts[1]} minor versions por detrás"
        return False, None
    except Exception:
        return False, None


def wordpress_audit(domain, timeout=6):
    """Auditoría WordPress completa: versión, plugins, xmlrpc, wp-json,
    enumeración de usuarios, archivos sensibles. Solo se llama si detect_cms()
    confirma WordPress."""
    result = {
        "is_wordpress": False,
        "version": None,
        "version_outdated": False,
        "version_diff": None,
        "xmlrpc_exposed": False,
        "users_enumerable": False,
        "users_found": [],
        "plugins": [],
        "vulnerable_plugins": [],
        "theme": None,
        "sensitive_files": [],
        "checks_count": 0,  # total de checks realizados
        "issues_count": 0,  # total de issues encontrados
    }

    base = None
    # Encontrar scheme + base
    for scheme in ["https", "http"]:
        r = _safe_get(f"{scheme}://{domain}", timeout=timeout)
        if r and r.status_code < 500:
            base = f"{scheme}://{domain}"
            html = r.text
            break
    if not base:
        return result

    # 1) Detectar versión via meta generator
    import re
    m = re.search(r'<meta\s+name=["\']generator["\']\s+content=["\']WordPress\s+([\d.]+)', html, re.I)
    if m:
        result["is_wordpress"] = True
        result["version"] = m.group(1)
    # Fallback: feed RSS
    if not result["version"]:
        rss = _safe_get(f"{base}/feed/", timeout=4)
        if rss and rss.status_code == 200:
            mm = re.search(r'<generator>https?://wordpress\.org/\?v=([\d.]+)</generator>', rss.text, re.I)
            if mm:
                result["is_wordpress"] = True
                result["version"] = mm.group(1)
    # Fallback: wp-json
    if not result["version"]:
        wpj = _safe_get(f"{base}/wp-json/", timeout=4)
        if wpj and wpj.status_code == 200:
            try:
                data = wpj.json()
                if data.get("namespaces") or data.get("routes"):
                    result["is_wordpress"] = True
                if "wp/v2" in (data.get("namespaces") or []):
                    pass  # confirmed but no version exposed
            except Exception:
                pass
    # Heurística final: /wp-login.php o /wp-content/ accesibles
    if not result["is_wordpress"]:
        wpl = _safe_get(f"{base}/wp-login.php", timeout=3)
        if wpl and wpl.status_code in (200, 302) and ("wp-submit" in (wpl.text or "") or "wordpress" in (wpl.text or "").lower()):
            result["is_wordpress"] = True

    if not result["is_wordpress"]:
        return result

    # 2) Versión obsoleta
    if result["version"]:
        outdated, diff = _wp_version_outdated(result["version"])
        result["version_outdated"] = outdated
        result["version_diff"] = diff
        result["checks_count"] += 1
        if outdated:
            result["issues_count"] += 1

    # 3) xmlrpc.php expuesto
    result["checks_count"] += 1
    xr = _safe_get(f"{base}/xmlrpc.php", timeout=3)
    if xr and xr.status_code == 200 and "XML-RPC" in (xr.text or "")[:500]:
        result["xmlrpc_exposed"] = True
        result["issues_count"] += 1

    # 4) Enumeración de usuarios via wp-json/wp/v2/users
    result["checks_count"] += 1
    users_resp = _safe_get(f"{base}/wp-json/wp/v2/users", timeout=4)
    if users_resp and users_resp.status_code == 200:
        try:
            users = users_resp.json()
            if isinstance(users, list) and users:
                result["users_enumerable"] = True
                result["issues_count"] += 1
                # Capturar primeros 5 usernames (sin email/datos sensibles)
                for u in users[:5]:
                    if isinstance(u, dict):
                        name = u.get("name") or u.get("slug")
                        if name:
                            result["users_found"].append(str(name)[:50])
        except Exception:
            pass

    # 5) Plugins visibles en HTML (URLs /wp-content/plugins/PLUGIN_SLUG/)
    result["checks_count"] += 1
    plugin_matches = re.findall(r'/wp-content/plugins/([a-z0-9\-_]+)/', html or "", re.I)
    plugins_unique = list({p.lower() for p in plugin_matches})[:15]
    result["plugins"] = plugins_unique
    # Cruzar con lista vulnerable
    for p in plugins_unique:
        if p in _WP_VULNERABLE_PLUGINS:
            desc, sev = _WP_VULNERABLE_PLUGINS[p]
            result["vulnerable_plugins"].append({"name": p, "desc": desc, "severity": sev})
            result["issues_count"] += 1

    # 6) Theme visible en HTML
    result["checks_count"] += 1
    theme_match = re.search(r'/wp-content/themes/([a-z0-9\-_]+)/', html or "", re.I)
    if theme_match:
        result["theme"] = theme_match.group(1).lower()

    # 7) Archivos sensibles típicos
    sensitive_paths = [
        ("/wp-config.php.bak", "backup wp-config.php expuesto"),
        ("/wp-config.php~",    "backup wp-config.php (tilde) expuesto"),
        ("/.wp-config.php.swp","swap file wp-config.php expuesto"),
        ("/wp-admin/install.php", "install.php accesible (re-instalación posible)"),
        ("/readme.html",       "readme.html con versión WP filtrada"),
        ("/wp-content/debug.log", "debug.log público"),
    ]
    for path, desc in sensitive_paths:
        result["checks_count"] += 1
        sf = _safe_get(f"{base}{path}", timeout=3)
        if sf and sf.status_code == 200 and len(sf.text or "") > 50:
            # Filtrar: install.php redirige a /wp-admin/ tras instalar, OK
            if path == "/wp-admin/install.php" and "already installed" in (sf.text or "").lower():
                continue
            result["sensitive_files"].append({"path": path, "desc": desc})
            result["issues_count"] += 1

    return result


# ─────────────────────────────────────────────────────────────
# MÓDULO 6b: PRESTASHOP AUDIT
# ─────────────────────────────────────────────────────────────
_PS_LATEST_VERSION = "8.2"

# Módulos PrestaShop con vulnerabilidades conocidas o vectores comunes 2024-2026.
_PS_VULNERABLE_MODULES = {
    "blockwishlist":    ("SQLi conocido en versiones <2.x — actualizar", "high"),
    "ps_facetedsearch": ("SSRF en versiones <3.13 — actualizar", "high"),
    "contactform":      ("Spam / abuso de formulario sin captcha", "medium"),
    "gamification":     ("RCE histórico en versiones antiguas — recomendado desinstalar si no se usa", "high"),
    "ps_emailsubscription": ("XSS reflejado en versiones antiguas", "medium"),
    "productcomments":  ("XSS persistente en comentarios sin sanitizar", "medium"),
    "ps_linklist":      ("XSS en versiones <5.x", "medium"),
}

# Lista corta de dominios o patrones JS conocidos como skimmers de checkout (Magecart-style).
# Si aparecen en el HTML del checkout, alerta crítica.
_PS_SKIMMER_PATTERNS = [
    "eval(atob(", "eval(unescape(", "document.write(unescape(",
    "creditcard", "card_number", "cvv", "cvc",  # solo activan si están en JS inline + URLs raras
]
_PS_SKIMMER_DOMAINS = [
    "magento-cdn.net", "googletagsmanager.com",  # typosquats clásicos
    "googie-analytics.com", "gstaticc.com",
    "js-stats.com", "trackjs.io",
]


def _ps_version_outdated(version):
    """Compara versión detectada con _PS_LATEST_VERSION."""
    if not version:
        return False, None
    try:
        cur = [int(x) for x in version.split(".")[:2]]
        latest = [int(x) for x in _PS_LATEST_VERSION.split(".")[:2]]
        while len(cur) < 2: cur.append(0)
        while len(latest) < 2: latest.append(0)
        if cur[0] < latest[0]:
            return True, f"{latest[0]-cur[0]} versiones mayores por detrás"
        if cur[0] == latest[0] and cur[1] < latest[1]:
            return True, f"{latest[1]-cur[1]} minor versions por detrás"
        return False, None
    except Exception:
        return False, None


def prestashop_audit(domain, timeout=6):
    """Auditoría PrestaShop: versión, /install/, /admin sin renombrar,
    módulos vulnerables, archivos sensibles, HTTPS checkout, skimmers.
    Solo se llama si detect_cms() confirma PrestaShop."""
    import re
    result = {
        "is_prestashop":     False,
        "version":           None,
        "version_outdated":  False,
        "version_diff":      None,
        "admin_path_default":  False,   # /admin/ accesible (mala práctica)
        "admin_path_found":    None,    # ruta detectada si existe
        "install_dir_exposed": False,
        "sensitive_files":     [],
        "modules_detected":    [],
        "vulnerable_modules":  [],
        "https_forced":        True,
        "skimmer_suspect":     False,
        "skimmer_evidence":    [],
        "checks_count":        0,
        "issues_count":        0,
    }

    base = None
    html = ""
    for scheme in ["https", "http"]:
        r = _safe_get(f"{scheme}://{domain}", timeout=timeout)
        if r and r.status_code < 500:
            base = f"{scheme}://{domain}"
            html = r.text or ""
            break
    if not base:
        return result

    # 1) Confirmar PrestaShop + versión
    # Heurísticas: meta generator, /themes/, header Powered-By, /modules/, var prestashop
    if re.search(r'<meta\s+name=["\']generator["\']\s+content=["\']PrestaShop\s*([\d.]*)', html, re.I):
        result["is_prestashop"] = True
        m = re.search(r'PrestaShop\s+([\d.]+)', html, re.I)
        if m: result["version"] = m.group(1)
    if "/themes/classic/" in html or "var prestashop" in html.lower() or "/modules/" in html:
        result["is_prestashop"] = True
    # Fallback: /modules/ps_emailsubscription/
    if not result["version"]:
        readme = _safe_get(f"{base}/INSTALL.txt", timeout=3)
        if readme and readme.status_code == 200:
            mm = re.search(r'PrestaShop\s+([\d.]+)', readme.text or "", re.I)
            if mm:
                result["is_prestashop"] = True
                result["version"] = mm.group(1)
                result["sensitive_files"].append({"path": "/INSTALL.txt", "desc": "fichero INSTALL.txt filtra versión PrestaShop"})
                result["issues_count"] += 1
    if not result["is_prestashop"]:
        return result

    # 2) Versión obsoleta
    if result["version"]:
        outdated, diff = _ps_version_outdated(result["version"])
        result["version_outdated"] = outdated
        result["version_diff"] = diff
        result["checks_count"] += 1
        if outdated:
            result["issues_count"] += 1

    # 3) Panel /admin/ sin renombrar (mala práctica clásica de PrestaShop)
    result["checks_count"] += 1
    for path in ["/admin/", "/administracion/", "/administrator/", "/back-office/", "/bo/"]:
        adm = _safe_get(f"{base}{path}", timeout=3)
        if adm and adm.status_code in (200, 302) and ("prestashop" in (adm.text or "").lower() or "back office" in (adm.text or "").lower()):
            result["admin_path_default"] = True
            result["admin_path_found"] = path
            result["issues_count"] += 1
            break

    # 4) Directorio /install/ accesible (DEBE eliminarse tras instalar)
    result["checks_count"] += 1
    inst = _safe_get(f"{base}/install/", timeout=3)
    if inst and inst.status_code == 200 and ("install" in (inst.text or "").lower() or "prestashop" in (inst.text or "").lower()):
        result["install_dir_exposed"] = True
        result["issues_count"] += 1

    # 5) Archivos sensibles típicos
    sensitive_paths = [
        ("/README.md",                  "README.md público — filtra estructura"),
        ("/CONTRIBUTING.md",            "CONTRIBUTING.md filtra detalles del repo"),
        ("/composer.lock",              "composer.lock expuesto — revela dependencias y versiones"),
        ("/var/logs/prod.log",          "logs de producción accesibles"),
        ("/app/config/parameters.php",  "fichero de configuración expuesto"),
        ("/.git/config",                "directorio .git accesible — código fuente comprometido"),
        ("/.env",                       "fichero .env público — credenciales filtradas"),
    ]
    for path, desc in sensitive_paths:
        result["checks_count"] += 1
        sf = _safe_get(f"{base}{path}", timeout=3)
        if sf and sf.status_code == 200 and len(sf.text or "") > 30:
            ct = (sf.headers.get("Content-Type") or "").lower()
            if "text/html" in ct and "<html" in (sf.text or "")[:300].lower():
                continue  # es la home, ignorar (catch-all del CMS)
            result["sensitive_files"].append({"path": path, "desc": desc})
            result["issues_count"] += 1

    # 6) Módulos detectados desde HTML y módulos vulnerables conocidos
    result["checks_count"] += 1
    mod_matches = re.findall(r'/modules/([a-z0-9_]+)/', html, re.I)
    mods_unique = list({m.lower() for m in mod_matches})[:20]
    result["modules_detected"] = mods_unique
    for m in mods_unique:
        if m in _PS_VULNERABLE_MODULES:
            desc, sev = _PS_VULNERABLE_MODULES[m]
            result["vulnerable_modules"].append({"name": m, "desc": desc, "severity": sev})
            result["issues_count"] += 1

    # 7) HTTPS forzado (si http:// devuelve 200 sin redirigir a https → mal)
    result["checks_count"] += 1
    if base.startswith("https://"):
        rh = _safe_get(f"http://{domain}/", timeout=4)
        if rh and rh.status_code == 200 and not (rh.url or "").startswith("https://"):
            result["https_forced"] = False
            result["issues_count"] += 1
    else:
        result["https_forced"] = False
        result["issues_count"] += 1

    # 8) Skimmer detection — análisis del HTML de la home y del checkout
    result["checks_count"] += 1
    checkout_url = f"{base}/order"
    ck = _safe_get(checkout_url, timeout=5)
    target_html = (html or "") + " " + (ck.text if ck else "")
    target_lower = target_html.lower()
    # 8a) Dominios sospechosos en scripts
    for dom in _PS_SKIMMER_DOMAINS:
        if dom in target_lower:
            result["skimmer_suspect"] = True
            result["skimmer_evidence"].append(f"dominio sospechoso en JS: {dom}")
    # 8b) Patrones de código ofuscado típico de Magecart
    obfuscated = 0
    for pat in _PS_SKIMMER_PATTERNS:
        if pat in target_lower:
            obfuscated += 1
    if obfuscated >= 2:
        result["skimmer_suspect"] = True
        result["skimmer_evidence"].append(f"{obfuscated} patrones de ofuscación / robo de tarjeta en JS")
    if result["skimmer_suspect"]:
        result["issues_count"] += 1

    return result


# ─────────────────────────────────────────────────────────────
# ROUTER: cms_audit — punto único de entrada
# ─────────────────────────────────────────────────────────────
def cms_audit(domain, timeout=6, cms_hint=None):
    """Router unificado de auditoría CMS.

    Detecta el CMS (o lo recibe en cms_hint para evitar doble detección) y
    devuelve un objeto homogéneo con:
        cms, version, is_audited, findings[], score_penalty, raw

    'findings' es una lista de dicts {severity, title, evidence} normalizada
    para que la UI / PDF / dashboard la consuman sin ramificar por tipo de CMS.
    """
    if cms_hint:
        cms_name = cms_hint
    else:
        cms_info = detect_cms(domain, timeout=timeout)
        cms_name = (cms_info or {}).get("cms")

    out = {
        "cms":            cms_name,
        "version":        None,
        "is_audited":     False,
        "findings":       [],
        "score_penalty":  0,
        "raw":            {},
    }

    if not cms_name:
        return out

    # ── WordPress ──
    if cms_name == "WordPress":
        wp = wordpress_audit(domain, timeout=timeout)
        out["raw"] = wp
        if not wp.get("is_wordpress"):
            return out
        out["is_audited"] = True
        out["version"]    = wp.get("version")

        if wp.get("version_outdated"):
            out["findings"].append({"severity": "high",   "title": "WordPress desactualizado",
                                    "evidence": wp.get("version_diff") or ""})
            out["score_penalty"] += 10
        if wp.get("xmlrpc_exposed"):
            out["findings"].append({"severity": "high",   "title": "xmlrpc.php expuesto",
                                    "evidence": "vector clásico de fuerza bruta y pingback DDoS"})
            out["score_penalty"] += 10
        if wp.get("users_enumerable"):
            out["findings"].append({"severity": "high",   "title": "Usuarios enumerables vía wp-json",
                                    "evidence": ", ".join(wp.get("users_found", [])[:5])})
            out["score_penalty"] += 10
        for v in wp.get("vulnerable_plugins", []):
            sev = v.get("severity", "medium")
            out["findings"].append({"severity": sev, "title": f"Plugin vulnerable: {v.get('name')}",
                                    "evidence": v.get("desc", "")})
            out["score_penalty"] += {"critical": 15, "high": 10, "medium": 5}.get(sev, 3)
        for sf in wp.get("sensitive_files", []):
            out["findings"].append({"severity": "high", "title": f"Fichero sensible expuesto: {sf.get('path')}",
                                    "evidence": sf.get("desc", "")})
            out["score_penalty"] += 8
        return out

    # ── PrestaShop ──
    if cms_name == "PrestaShop":
        ps = prestashop_audit(domain, timeout=timeout)
        out["raw"] = ps
        if not ps.get("is_prestashop"):
            return out
        out["is_audited"] = True
        out["version"]    = ps.get("version")

        if ps.get("version_outdated"):
            out["findings"].append({"severity": "high",     "title": "PrestaShop desactualizado",
                                    "evidence": ps.get("version_diff") or ""})
            out["score_penalty"] += 10
        if ps.get("admin_path_default"):
            out["findings"].append({"severity": "critical", "title": "Panel admin sin renombrar",
                                    "evidence": f"ruta detectada: {ps.get('admin_path_found')}"})
            out["score_penalty"] += 15
        if ps.get("install_dir_exposed"):
            out["findings"].append({"severity": "critical", "title": "/install/ accesible",
                                    "evidence": "permite reinstalación maliciosa de la tienda"})
            out["score_penalty"] += 18
        for v in ps.get("vulnerable_modules", []):
            sev = v.get("severity", "medium")
            out["findings"].append({"severity": sev, "title": f"Módulo vulnerable: {v.get('name')}",
                                    "evidence": v.get("desc", "")})
            out["score_penalty"] += {"critical": 15, "high": 10, "medium": 5}.get(sev, 3)
        for sf in ps.get("sensitive_files", []):
            out["findings"].append({"severity": "high", "title": f"Fichero sensible expuesto: {sf.get('path')}",
                                    "evidence": sf.get("desc", "")})
            out["score_penalty"] += 8
        if not ps.get("https_forced"):
            out["findings"].append({"severity": "high", "title": "HTTPS no forzado",
                                    "evidence": "checkout vulnerable a sniffing — riesgo PCI-DSS"})
            out["score_penalty"] += 10
        if ps.get("skimmer_suspect"):
            out["findings"].append({"severity": "critical", "title": "Posible skimmer digital detectado",
                                    "evidence": "; ".join(ps.get("skimmer_evidence", [])) or "patrón sospechoso en JS del checkout"})
            out["score_penalty"] += 25
        return out

    # CMS detectado pero sin auditor específico aún (Joomla, Drupal, etc.)
    return out


# ─────────────────────────────────────────────────────────────
# MÓDULO 7: VIGILANCIA NOCTURNA
# ─────────────────────────────────────────────────────────────
def enviar_alerta(mensaje):
    print(f"\n{'='*55}\n  ALERTA RECONBASE [{time.strftime('%Y-%m-%d %H:%M:%S')}]\n{'='*55}")
    print(mensaje)
    print('='*55+'\n')

def vigilancia_nocturna(clientes, api_key):
    print(f"[{time.strftime('%H:%M:%S')}] Iniciando ronda de vigilancia...")
    for c in clientes:
        dominio = c.get("dominio","")
        email   = c.get("email","")
        nombre  = c.get("nombre", dominio)
        alertas = []
        print(f"  Escaneando: {dominio}")
        p = scan_critical_ports_fast(dominio)
        criticos = [x for x in p if x["servicio"] in ["RDP","Telnet","MySQL","MongoDB","Redis","PostgreSQL","MSSQL","Docker API"]]
        if criticos:
            lista_criticos = ", ".join([str(x["puerto"]) + "/" + x["servicio"] for x in criticos])
            alertas.append("Puertos criticos: " + lista_criticos)
        dns = check_email_spoofing(dominio)
        if not dns["SPF"]:   alertas.append("SPF ausente")
        if not dns["DMARC"]: alertas.append("DMARC ausente")
        if email and api_key:
            leaks = check_leaks_real(email, api_key)
            if leaks: alertas.append(f"{len(leaks)} filtracion(es) para {email}")
        if alertas:
            msg = f"ALERTA: {nombre} ({dominio})\n" + "\n".join(f"  - {a}" for a in alertas)
            enviar_alerta(msg)
        else:
            print(f"    [{dominio}] Sin alertas.")
    print(f"[{time.strftime('%H:%M:%S')}] Ronda finalizada.")


# ─────────────────────────────────────────────────────────────
# MÓDULO 7: ANÁLISIS SSL/TLS
# ─────────────────────────────────────────────────────────────
def ssl_scan(target, port=443, timeout=6):
    """Analiza el certificado SSL/TLS y configuración de cifrado."""
    result = {
        "tiene_ssl": False,
        "expira": None,
        "dias_restantes": None,
        "version_ssl": None,
        "cifrado": None,
        "caducado": False,
        "pronto_a_caducar": False,
        "sujeto": None,
        "error": None,
    }
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((target, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=target) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                result["tiene_ssl"] = True
                result["version_ssl"] = ssock.version()
                result["cifrado"] = cipher[0] if cipher else None
                expire_str = cert.get("notAfter", "")
                if expire_str:
                    expire_dt = datetime.datetime.strptime(expire_str, "%b %d %H:%M:%S %Y %Z")
                    result["expira"] = expire_dt.strftime("%d/%m/%Y")
                    dias = (expire_dt - datetime.datetime.utcnow()).days
                    result["dias_restantes"] = dias
                    result["caducado"] = dias < 0
                    result["pronto_a_caducar"] = 0 <= dias < 30
                sujeto = dict(x[0] for x in cert.get("subject", []))
                result["sujeto"] = sujeto.get("commonName", "")
    except ssl.SSLCertVerificationError as e:
        result["tiene_ssl"] = True
        result["error"] = "Certificado no verificable: " + str(e)[:80]
    except ConnectionRefusedError:
        result["error"] = "Puerto 443 cerrado"
    except Exception as e:
        result["error"] = str(e)[:80]
    return result


# ─────────────────────────────────────────────────────────────
# MÓDULO 8: BANNER GRABBING Y DETECCIÓN DE OS
# ─────────────────────────────────────────────────────────────
_PROBES = {
    21:   b"",
    22:   b"",
    25:   b"EHLO recon\r\n",
    80:   b"HEAD / HTTP/1.0\r\nHost: target\r\n\r\n",
    110:  b"",
    143:  b"",
    3306: b"",
    5432: b"",
    6379: b"PING\r\n",
    8080: b"HEAD / HTTP/1.0\r\nHost: target\r\n\r\n",
    9200: b"",
}

def banner_grab(target, puertos_abiertos, timeout=2):
    """Captura banners de servicios en puertos abiertos.
    Sanitiza el output: PostgreSQL JSONB rechaza \\u0000 (null byte) y
    otros caracteres de control que pueden venir en banners raw de
    SMTP/IMAP/MySQL/Redis/etc."""
    banners = {}
    for p_info in puertos_abiertos:
        port = p_info["puerto"]
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect((target, port))
            probe = _PROBES.get(port, b"")
            if probe:
                try:
                    s.send(probe)
                except Exception:
                    pass
            try:
                banner = s.recv(1024).decode("utf-8", errors="ignore").strip()
            except Exception:
                banner = ""
            # Sanitizar: quitar null bytes y caracteres de control no imprimibles
            # (excepto \t, \n, \r). Esto evita DataError en PostgreSQL JSONB.
            banner = banner.replace("\x00", "")
            banner = "".join(c for c in banner if c == "\t" or c == "\n" or c == "\r" or (ord(c) >= 32 and ord(c) != 0x7F))
            if banner:
                banners[port] = banner[:300]
            s.close()
        except Exception:
            pass
    return banners


def detect_os_from_banners(banners):
    """Infiere el sistema operativo a partir de los banners capturados."""
    for banner in banners.values():
        b = banner.lower()
        if "ubuntu" in b:                       return "Linux (Ubuntu)"
        if "debian" in b:                       return "Linux (Debian)"
        if "centos" in b:                       return "Linux (CentOS)"
        if "fedora" in b:                       return "Linux (Fedora)"
        if "red hat" in b:                      return "Linux (Red Hat)"
        if "freebsd" in b:                      return "FreeBSD"
        if "windows" in b or "microsoft" in b or "iis" in b: return "Windows Server"
        if "openssh" in b:                      return "Linux/Unix"
        if "nginx" in b:                        return "Linux (Nginx)"
        if "apache" in b:                       return "Linux (Apache)"
    return None


# ─────────────────────────────────────────────────────────────
# HELPER: DETECTAR SI EL TARGET ES IP O DOMINIO
# ─────────────────────────────────────────────────────────────
def es_ip(target):
    """Devuelve True si el target es una dirección IPv4."""
    return bool(_re.match(r'^\d{1,3}(\.\d{1,3}){3}$', target.strip()))

if __name__ == "__main__":
    import os
    from dotenv import load_dotenv
    load_dotenv()
    CLIENTES = [
        {"nombre":"Demo", "dominio":"scanme.nmap.org", "email":""},
    ]
    vigilancia_nocturna(CLIENTES, os.getenv("RECONBASE_API_KEY",""))
    schedule.every().day.at("03:00").do(vigilancia_nocturna, CLIENTES, os.getenv("RECONBASE_API_KEY",""))
    while True:
        schedule.run_pending()
        time.sleep(60)