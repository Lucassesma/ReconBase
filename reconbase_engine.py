import concurrent.futures
import ipaddress
import requests
import socket
import ssl
import datetime
import os
import re as _re
import time
from urllib.parse import urlsplit, urljoin

try:
    import dns.resolver
    DNS_DISPONIBLE = True
except ImportError:
    DNS_DISPONIBLE = False

# ─────────────────────────────────────────────────────────────
# VALIDACIÓN DE DESTINOS (anti-SSRF)
# ─────────────────────────────────────────────────────────────
# Cualquier visitante elige el dominio que escaneamos: sin este filtro podría
# apuntar el escáner a la red interna del servidor (localhost, 10.x,
# *.railway.internal, 169.254.169.254...).
_SUFIJOS_INTERNOS = (".internal", ".local", ".localhost", ".localdomain", ".lan", ".home.arpa")


def _normaliza_host(host):
    host = (host or "").strip().lower().rstrip(".")
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    return host


def _ip_publica(ip_str):
    try:
        ip = ipaddress.ip_address(ip_str.split("%", 1)[0])
    except ValueError:
        return False
    mapped = getattr(ip, "ipv4_mapped", None)
    if mapped is not None:
        ip = mapped
    return ip.is_global and not ip.is_multicast


def clasificar_destino(host):
    """Devuelve (estado, ips). estado: 'vacio' | 'interno' | 'no_resuelve' | 'publico'.
    Solo es 'publico' si el host resuelve EXCLUSIVAMENTE a IPs públicas."""
    host = _normaliza_host(host)
    if not host:
        return "vacio", []
    if host == "localhost" or host.endswith(_SUFIJOS_INTERNOS):
        return "interno", []
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except (socket.gaierror, UnicodeError, ValueError, OSError):
        return "no_resuelve", []
    ips = sorted({info[4][0] for info in infos})
    if not ips:
        return "no_resuelve", []
    if all(_ip_publica(ip) for ip in ips):
        return "publico", ips
    return "interno", ips


_RE_VERSION = _re.compile(r"^\d+(?:\.\d+){0,3}$")
_RE_HOST = _re.compile(r"^[a-z0-9.-]{1,253}$")


def _texto_seguro(valor, max_len=50):
    """Lo que devuelve una web escaneada acaba en el HTML de nuestros usuarios:
    solo se conservan letras, dígitos, espacios y . _ @ -"""
    return _re.sub(r"[^\w .@-]", "", str(valor))[:max_len].strip()


def destino_permitido(host):
    return clasificar_destino(host)[0] == "publico"


def es_destino_interno(host):
    return clasificar_destino(host)[0] == "interno"


def ip_publica_de(host, solo_ipv4=True):
    """IP pública ya validada de `host`, o None. Los sockets se conectan a esta IP
    y no al nombre: así una segunda resolución DNS no puede desviar la conexión
    a una red interna (DNS rebinding)."""
    estado, ips = clasificar_destino(host)
    if estado != "publico":
        return None
    v4 = [ip for ip in ips if ":" not in ip]
    if v4:
        return v4[0]
    return None if solo_ipv4 else ips[0]


# ─────────────────────────────────────────────────────────────
# IDENTIFICACIÓN DEL ESCÁNER Y MODOS DE ANÁLISIS
# ─────────────────────────────────────────────────────────────
# Todas las peticiones salen con un User-Agent que nos identifica y enlaza a la
# página pública que explica qué hace el escáner y cómo excluirse de él.
SCANNER_INFO_URL = os.getenv("BASE_URL", "https://reconbase.es").rstrip("/") + "/escaner-info"
USER_AGENT = f"Mozilla/5.0 (compatible; ReconBase/2.0; +{SCANNER_INFO_URL})"
_CABECERAS_BASE = {
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "es-ES,es;q=0.9,en;q=0.8",
}

# Pasivo: solo lo que la web publica o enlaza (home, recursos que carga, DNS,
# certificado) y consultas a servicios de terceros. Apto para cualquier dominio.
# Completo: además prueba rutas no enlazadas, puertos y servicios. Solo para
# dominios cuya titularidad o autorización ha verificado el usuario.
MODO_PASIVO = "pasivo"
MODO_COMPLETO = "completo"


def peticion_segura(url, timeout=5, headers=None, max_redirects=5, method="GET", stream=False):
    """requests que valida el destino de la URL inicial y de cada redirección.
    Lanza ValueError si algún salto apunta a una red interna."""
    cabeceras = dict(_CABECERAS_BASE)
    cabeceras.update(headers or {})
    cabeceras["User-Agent"] = USER_AGENT
    for _ in range(max_redirects + 1):
        partes = urlsplit(url)
        if partes.scheme not in ("http", "https") or not destino_permitido(partes.hostname or ""):
            raise ValueError("Destino no permitido")
        r = requests.request(method, url, timeout=timeout, headers=cabeceras,
                             allow_redirects=False, stream=stream)
        if not (r.is_redirect and r.headers.get("Location")):
            return r
        url = urljoin(url, r.headers["Location"])
        r.close()
    raise ValueError("Demasiadas redirecciones")


def get_seguro(url, timeout=5, headers=None, max_redirects=5):
    return peticion_segura(url, timeout=timeout, headers=headers, max_redirects=max_redirects)


def sondear_fichero(url, timeout=4):
    """Comprueba si un fichero es accesible SIN descargar su contenido: solo el
    código de respuesta y las cabeceras. Un .env o una copia de wp-config puede
    contener credenciales y no queremos leerlas ni guardarlas nunca."""
    try:
        r = peticion_segura(url, timeout=timeout, method="HEAD")
        if r.status_code in (405, 501):
            r.close()
            r = peticion_segura(url, timeout=timeout, method="GET", stream=True)
        try:
            longitud = int(r.headers.get("Content-Length", ""))
        except ValueError:
            longitud = None
        info = {"status": r.status_code,
                "content_type": (r.headers.get("Content-Type") or "").lower(),
                "length": longitud}
        r.close()
        return info
    except Exception:
        return None


def fichero_expuesto(info, min_len=30):
    """200 con un tipo que no es HTML. Las webs que responden a todo con la home
    (soft 404) devuelven text/html y no cuentan."""
    if not info or info["status"] != 200 or "text/html" in info["content_type"]:
        return False
    return info["length"] is None or info["length"] > min_len


def _leer_pagina(url, timeout=4, max_bytes=16384):
    """Lee como mucho `max_bytes` de una página HTML pública (pantallas de login,
    instaladores, readme). Devuelve (status, texto) o (None, "")."""
    try:
        r = peticion_segura(url, timeout=timeout, stream=True)
        cuerpo = b""
        for trozo in r.iter_content(4096):
            cuerpo += trozo
            if len(cuerpo) >= max_bytes:
                break
        r.close()
        return r.status_code, cuerpo[:max_bytes].decode(r.encoding or "utf-8", errors="ignore")
    except Exception:
        return None, ""

# ─────────────────────────────────────────────────────────────
# MÓDULO 1: FILTRACIONES (Have I Been Pwned)
# ─────────────────────────────────────────────────────────────
def check_leaks_real(email, api_key, timeout=8):
    if not api_key:
        return None
    url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}"
    headers = {"hibp-api-key": api_key, "user-agent": USER_AGENT}
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
    ip = ip_publica_de(domain)
    if not ip:
        return abiertos
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = {ex.submit(check_single_port, ip, p, timeout): p for p in PUERTOS}
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
    """Comprueba las cabeceras de seguridad de la home."""
    resultados = {v: False for v in CABECERAS.values()}
    for scheme in ["https","http"]:
        try:
            r = get_seguro(f"{scheme}://{domain}", timeout=timeout)
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
                r = get_seguro(f"{scheme}://{domain}", timeout=timeout)
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
                                wp = get_seguro(f"{scheme}://{domain}/wp-json/", timeout=4)
                                if wp.status_code == 200:
                                    import json
                                    wp_data = wp.json()
                                    version = wp_data.get("version")
                                    if version and _RE_VERSION.match(str(version)):
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
        return get_seguro(url, timeout=timeout, headers=headers)
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


# Rutas que una web WordPress no enlaza: solo se comprueban en modo completo.
# Los ficheros de datos (copias de wp-config, logs) se sondean sin leer su
# contenido; las páginas (instalador, readme) se leen como mucho 16 KB.
_WP_FICHEROS_SENSIBLES = [
    ("/wp-config.php.bak",     "copia de wp-config.php accesible"),
    ("/wp-config.php~",        "copia de wp-config.php (tilde) accesible"),
    ("/.wp-config.php.swp",    "fichero swap de wp-config.php accesible"),
    ("/wp-content/debug.log",  "debug.log público"),
]

OMITIDOS_WP_PASIVO = ["xmlrpc.php", "usuarios enumerables (wp-json/wp/v2/users)",
                      "instalador y readme.html", "ficheros sensibles"]


def wordpress_audit(domain, timeout=6, modo=MODO_PASIVO):
    """Auditoría WordPress. En modo pasivo solo usa la home, el feed y la raíz de
    wp-json (las tres las enlaza la propia web). El modo completo añade rutas no
    enlazadas: xmlrpc.php, usuarios, instalador y ficheros sensibles."""
    completo = modo == MODO_COMPLETO
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
        "modo": MODO_COMPLETO if completo else MODO_PASIVO,
        "omitidos": [] if completo else list(OMITIDOS_WP_PASIVO),
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

    # 1) Versión: meta generator, feed RSS y raíz de wp-json
    import re
    m = re.search(r'<meta\s+name=["\']generator["\']\s+content=["\']WordPress\s+([\d.]+)', html, re.I)
    if m:
        result["is_wordpress"] = True
        result["version"] = m.group(1)
    if not result["version"]:
        rss = _safe_get(f"{base}/feed/", timeout=4)
        if rss and rss.status_code == 200:
            mm = re.search(r'<generator>https?://wordpress\.org/\?v=([\d.]+)</generator>', rss.text or "", re.I)
            if mm:
                result["is_wordpress"] = True
                result["version"] = mm.group(1)
    if not result["version"]:
        wpj = _safe_get(f"{base}/wp-json/", timeout=4)
        if wpj and wpj.status_code == 200:
            try:
                data = wpj.json()
                if isinstance(data, dict) and (data.get("namespaces") or data.get("routes")):
                    result["is_wordpress"] = True
            except Exception:
                pass
    if not result["is_wordpress"] and ("/wp-content/" in html or "/wp-includes/" in html):
        result["is_wordpress"] = True
    if result["version"] and not _RE_VERSION.match(result["version"]):
        result["version"] = None

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

    # 3) Plugins y tema visibles en el HTML de la home
    result["checks_count"] += 1
    plugin_matches = re.findall(r'/wp-content/plugins/([a-z0-9\-_]+)/', html, re.I)
    plugins_unique = sorted({p.lower() for p in plugin_matches})[:15]
    result["plugins"] = plugins_unique
    for p in plugins_unique:
        if p in _WP_VULNERABLE_PLUGINS:
            desc, sev = _WP_VULNERABLE_PLUGINS[p]
            result["vulnerable_plugins"].append({"name": p, "desc": desc, "severity": sev})
            result["issues_count"] += 1
    result["checks_count"] += 1
    theme_match = re.search(r'/wp-content/themes/([a-z0-9\-_]+)/', html, re.I)
    if theme_match:
        result["theme"] = theme_match.group(1).lower()

    if not completo:
        return result

    # 4) xmlrpc.php expuesto
    result["checks_count"] += 1
    status, texto = _leer_pagina(f"{base}/xmlrpc.php", timeout=3, max_bytes=2048)
    if status == 200 and "XML-RPC" in texto:
        result["xmlrpc_exposed"] = True
        result["issues_count"] += 1

    # 5) Enumeración de usuarios vía wp-json/wp/v2/users (solo nombres públicos)
    result["checks_count"] += 1
    users_resp = _safe_get(f"{base}/wp-json/wp/v2/users", timeout=4)
    if users_resp and users_resp.status_code == 200:
        try:
            users = users_resp.json()
            if isinstance(users, list) and users:
                result["users_enumerable"] = True
                result["issues_count"] += 1
                for u in users[:5]:
                    if isinstance(u, dict):
                        name = u.get("name") or u.get("slug")
                        if name:
                            limpio = _texto_seguro(name)
                            if limpio:
                                result["users_found"].append(limpio)
        except Exception:
            pass

    # 6) Instalador y readme.html (páginas HTML, lectura limitada)
    result["checks_count"] += 1
    status, texto = _leer_pagina(f"{base}/wp-admin/install.php", timeout=3)
    bajo = texto.lower()
    if status == 200 and "wordpress" in bajo and "already installed" not in bajo and "ya está instalado" not in bajo:
        result["sensitive_files"].append({"path": "/wp-admin/install.php",
                                          "desc": "install.php accesible (reinstalación posible)"})
        result["issues_count"] += 1
    result["checks_count"] += 1
    status, texto = _leer_pagina(f"{base}/readme.html", timeout=3, max_bytes=4096)
    if status == 200 and "wordpress" in texto.lower() and "<html" in texto.lower():
        result["sensitive_files"].append({"path": "/readme.html", "desc": "readme.html revela que es WordPress y su versión"})
        result["issues_count"] += 1

    # 7) Ficheros de datos: solo cabeceras, nunca el contenido
    for path, desc in _WP_FICHEROS_SENSIBLES:
        result["checks_count"] += 1
        if fichero_expuesto(sondear_fichero(f"{base}{path}", timeout=3), min_len=50):
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

# Patrones de código JS típicamente usados por skimmers Magecart 2024-2026.
# Solo cuentan si aparecen en JS inline del checkout, no en librerías legítimas.
_PS_SKIMMER_PATTERNS = [
    "eval(atob(", "eval(unescape(", "eval(decodeuricomponent(",
    "document.write(unescape(", "string.fromcharcode(parseint(",
    "addeventlistener('keydown'", "addeventlistener(\"keydown\"",
    "addeventlistener('submit'", "addeventlistener(\"submit\"",
    "creditcard", "card_number", "cardnumber", "cc_number",
    "cvv", "cvc", "card_cvc", "card_cvv",
    "card_holder", "cardholder", "expir_date", "expirationdate",
    "btoa(", "fetch('https://", 'fetch("https://',
]

# Typosquats y dominios de skimmers reales documentados en blocklists Magecart.
# Fuentes: PublicWWW, MalwareBazaar, sansec.io, EU CERT/CCN-CERT advisories.
_PS_SKIMMER_DOMAINS = [
    # Typosquats clásicos de servicios legítimos
    "googie-analytics.com", "googletagsmanager.com", "googleanalytlcs.com",
    "googlee-analytics.com", "google-analytlcs.com", "gstaticc.com",
    "stripe-cdn.com", "stripe-checkout.com", "paypal-cdn.com",
    "magento-cdn.net", "magento-css.com", "prestashopx.com",
    "presta-cdn.com", "prestasecure.com",
    "jqueryapi.io", "jquerycdn.com", "jquery-cdn.org", "jqueryxcdn.com",
    "bootstrap-cdn.org", "fontawesomex.com",
    # Sumideros de skimmers documentados 2024-2026
    "js-stats.com", "trackjs.io", "checkoutjs.com",
    "stat-js.com", "statsanalytics.io", "topjs.io",
    "cloudstats.org", "webanalytlcs.com",
    "myteen.io", "mybios.org",
    # Servicios de exfiltración usados como C2 por Magecart
    "tracking-api.live", "analytics-track.com", "data-collector.io",
]
# Dominios LEGÍTIMOS que pueden estar en el HTML y no deben alertar
_PS_SKIMMER_WHITELIST_DOMAINS = [
    "google-analytics.com", "googletagmanager.com", "google.com",
    "gstatic.com", "googleapis.com", "youtube.com", "doubleclick.net",
    "facebook.com", "facebook.net", "fbcdn.net", "instagram.com",
    "stripe.com", "paypal.com", "paypalobjects.com",
    "jquery.com", "jsdelivr.net", "cloudflare.com", "cdnjs.cloudflare.com",
    "bootstrapcdn.com", "fontawesome.com",
    "addtoany.com", "trustpilot.com", "hotjar.com",
    "prestashop.com", "prestashop.es",
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


_PS_FICHEROS_SENSIBLES = [
    ("/composer.lock",              "composer.lock expuesto: revela dependencias y versiones"),
    ("/var/logs/prod.log",          "logs de producción accesibles"),
    ("/app/config/parameters.php",  "fichero de configuración servido sin ejecutar"),
    ("/.git/config",                "directorio .git accesible: expone el código fuente"),
    ("/.env",                       "fichero .env accesible: puede contener credenciales"),
    ("/README.md",                  "README.md público: filtra la estructura del proyecto"),
]

OMITIDOS_PS_PASIVO = ["panel de administración sin renombrar", "directorio /install/",
                      "INSTALL.txt", "ficheros sensibles"]


def prestashop_audit(domain, timeout=6, modo=MODO_PASIVO):
    """Auditoría PrestaShop. En modo pasivo analiza la tienda pública: home,
    páginas de pedido, scripts que cargan y si fuerza HTTPS. El modo completo
    añade rutas no enlazadas: panel de administración, /install/ y ficheros
    sensibles (estos sin descargar su contenido)."""
    import re
    completo = modo == MODO_COMPLETO
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
        "modo":                MODO_COMPLETO if completo else MODO_PASIVO,
        "omitidos":            [] if completo else list(OMITIDOS_PS_PASIVO),
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

    # 1) Confirmar PrestaShop + versión (meta generator y marcas del HTML)
    if re.search(r'<meta\s+name=["\']generator["\']\s+content=["\']PrestaShop', html, re.I):
        result["is_prestashop"] = True
        m = re.search(r'PrestaShop\s+([\d.]+)', html, re.I)
        if m: result["version"] = m.group(1)
    if "/themes/classic/" in html or "var prestashop" in html.lower() or "/modules/" in html:
        result["is_prestashop"] = True
    if completo and not result["version"]:
        status, texto = _leer_pagina(f"{base}/INSTALL.txt", timeout=3, max_bytes=4096)
        if status == 200:
            mm = re.search(r'PrestaShop\s+([\d.]+)', texto, re.I)
            if mm:
                result["is_prestashop"] = True
                result["version"] = mm.group(1)
                result["sensitive_files"].append({"path": "/INSTALL.txt", "desc": "INSTALL.txt revela la versión de PrestaShop"})
                result["issues_count"] += 1
    if result["version"] and not _RE_VERSION.match(result["version"].strip(".")):
        result["version"] = None
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

    if completo:
        # 3) Panel /admin/ sin renombrar (mala práctica clásica de PrestaShop)
        result["checks_count"] += 1
        for path in ["/admin/", "/administracion/", "/administrator/", "/back-office/", "/bo/"]:
            status, texto = _leer_pagina(f"{base}{path}", timeout=3)
            bajo = texto.lower()
            if status == 200 and ("prestashop" in bajo or "back office" in bajo):
                result["admin_path_default"] = True
                result["admin_path_found"] = path
                result["issues_count"] += 1
                break

        # 4) Directorio /install/ accesible (DEBE eliminarse tras instalar)
        result["checks_count"] += 1
        status, texto = _leer_pagina(f"{base}/install/", timeout=3)
        if status == 200 and "prestashop" in texto.lower() and "install" in texto.lower():
            result["install_dir_exposed"] = True
            result["issues_count"] += 1

        # 5) Ficheros sensibles: solo código de respuesta y cabeceras
        for path, desc in _PS_FICHEROS_SENSIBLES:
            result["checks_count"] += 1
            if fichero_expuesto(sondear_fichero(f"{base}{path}", timeout=3)):
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

    # 8) Skimmer detection — análisis del HTML+JS de home + checkout
    result["checks_count"] += 1

    # 8.1) Descargar checkout (/order y /index.php?controller=order)
    checkout_html = ""
    for path in ["/order", "/index.php?controller=order", "/checkout"]:
        try:
            ck = _safe_get(f"{base}{path}", timeout=5)
            if ck and ck.status_code == 200 and len(ck.text or "") > 200:
                checkout_html = ck.text
                break
        except Exception:
            continue

    # 8.2) Extraer URLs de scripts externos del HTML (home + checkout)
    combined_html = (html or "") + " " + checkout_html
    script_srcs = re.findall(
        r'<script[^>]+src=["\']([^"\']+)["\']',
        combined_html, re.I
    )

    # 8.3) Para cada script externo: dominio en blocklist? bajar contenido si sospechoso
    domains_checked = set()
    external_js_content = ""
    for src in script_srcs:
        # Normalizar URL absoluta
        full = src
        if src.startswith("//"):
            full = "https:" + src
        elif src.startswith("/"):
            full = base + src
        elif not src.startswith("http"):
            continue
        # Extraer dominio
        try:
            host = full.split("://", 1)[1].split("/", 1)[0].split(":", 1)[0].lower()
        except Exception:
            continue
        # Saltar whitelist (CDNs legítimos comunes)
        if any(wl in host for wl in _PS_SKIMMER_WHITELIST_DOMAINS):
            continue
        # Saltar dominio propio
        if domain.lower() in host:
            # Descargar contenido propio: puede contener skimmer inyectado
            if host in domains_checked: continue
            domains_checked.add(host)
            try:
                jr = _safe_get(full, timeout=5)
                if jr and jr.status_code == 200 and len(jr.text or "") < 250000:
                    external_js_content += " " + (jr.text or "")
            except Exception:
                pass
            continue
        # Dominio externo no whitelisted: comprobar blocklist
        for dom in _PS_SKIMMER_DOMAINS:
            if dom in host:
                result["skimmer_suspect"] = True
                host_seguro = host if _RE_HOST.match(host) else _re.sub(r"[^a-z0-9.-]", "", host)
                result["skimmer_evidence"].append(f"script externo desde dominio en blocklist: {host_seguro}")
                break

    # 8.4) Buscar patrones ofuscados / robo de tarjeta en HTML+JS combinado
    target_lower = (combined_html + " " + external_js_content).lower()
    obfuscated_hits = []
    for pat in _PS_SKIMMER_PATTERNS:
        if pat in target_lower:
            obfuscated_hits.append(pat)
    # Umbral: >=3 patrones (más estricto que antes para reducir falsos positivos)
    if len(obfuscated_hits) >= 3:
        result["skimmer_suspect"] = True
        result["skimmer_evidence"].append(
            f"{len(obfuscated_hits)} patrones de ofuscación / robo de tarjeta detectados (ej: {', '.join(obfuscated_hits[:3])})"
        )

    # 8.5) Heurística adicional: <script> inline grande con base64 + eval cerca del </body>
    near_end = combined_html[-15000:].lower() if combined_html else ""
    if ("eval(" in near_end and ("atob(" in near_end or "fromcharcode" in near_end)
        and any(s in near_end for s in ("card", "cvv", "checkout", "payment"))):
        result["skimmer_suspect"] = True
        result["skimmer_evidence"].append(
            "código ofuscado al final del <body> con referencias a campos de pago"
        )

    # Dedupe evidence
    seen = set()
    dedupe = []
    for e in result["skimmer_evidence"]:
        if e not in seen:
            seen.add(e); dedupe.append(e)
    result["skimmer_evidence"] = dedupe[:5]

    if result["skimmer_suspect"]:
        result["issues_count"] += 1

    return result


# ─────────────────────────────────────────────────────────────
# ROUTER: cms_audit — punto único de entrada
# ─────────────────────────────────────────────────────────────
def cms_audit(domain, timeout=6, cms_hint=None, modo=MODO_PASIVO):
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
        wp = wordpress_audit(domain, timeout=timeout, modo=modo)
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
        ps = prestashop_audit(domain, timeout=timeout, modo=modo)
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
# MÓDULO 6c: LISTA NEGRA (Google Web Risk)
# ─────────────────────────────────────────────────────────────
# Web Risk es la versión comercial de Safe Browsing: su licencia permite usarlo
# en un producto de pago (Safe Browsing y el feed de URLhaus no). Sin clave
# configurada la comprobación queda desactivada, nunca se simula.
_WEB_RISK_URL = "https://webrisk.googleapis.com/v1/uris:search"
_WEB_RISK_TIPOS = {
    "MALWARE": "Malware",
    "SOCIAL_ENGINEERING": "Phishing / ingeniería social",
    "UNWANTED_SOFTWARE": "Software no deseado",
}
WEB_RISK_ATRIBUCION = "Datos de Google Web Risk"


def _consultar_web_risk(uri, api_key, timeout=8):
    """Devuelve la lista de amenazas de `uri` o lanza si la API falla."""
    params = [("uri", uri), ("key", api_key)] + [("threatTypes", t) for t in _WEB_RISK_TIPOS]
    r = requests.get(_WEB_RISK_URL, params=params, timeout=timeout,
                     headers={"User-Agent": USER_AGENT})
    r.raise_for_status()
    return (r.json().get("threat") or {}).get("threatTypes") or []


def check_blacklist(domain, web_risk_key=None):
    """¿Aparece el dominio en las listas de Google Web Risk? Devuelve un dict
    homogéneo; `disponible` es False si no hay clave o la consulta falló."""
    domain = _re.sub(r'^https?://', '', (domain or "").strip(), flags=_re.IGNORECASE)
    domain = domain.split("/")[0].split(":")[0].strip().lower()
    if domain.startswith("www."):
        domain = domain[4:]
    result = {"domain": domain, "listed": False, "sources": [], "checked_sources": [],
              "disponible": bool(web_risk_key), "atribucion": WEB_RISK_ATRIBUCION}
    if not domain or "." not in domain or not web_risk_key:
        return result
    amenazas = []
    try:
        for uri in (f"http://{domain}/", f"https://{domain}/"):
            for t in _consultar_web_risk(uri, web_risk_key):
                if t not in amenazas:
                    amenazas.append(t)
    except Exception as e:
        print(f"[!] Web Risk error: {e}")
        result["disponible"] = False
        return result
    result["checked_sources"].append("Google Web Risk")
    for t in amenazas:
        result["listed"] = True
        result["sources"].append({"name": "Google Web Risk", "threat": _WEB_RISK_TIPOS.get(t, t)})
    return result


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
    ip = ip_publica_de(target, solo_ipv4=False)
    if not ip:
        result["error"] = "Destino no permitido o no resuelve"
        return result
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((ip, port), timeout=timeout) as sock:
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
    ip = ip_publica_de(target)
    if not ip:
        return banners
    for p_info in puertos_abiertos:
        port = p_info["puerto"]
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect((ip, port))
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


# ─────────────────────────────────────────────────────────────
# ANÁLISIS COMPLETO DE UN OBJETIVO + PUNTUACIÓN
# ─────────────────────────────────────────────────────────────
# Punto único para todos los endpoints y crons: así ninguno puede saltarse la
# regla de modos por error. Las filtraciones (HIBP) las añade el servidor, que
# es quien sabe si el email pertenece al usuario o a un dominio verificado.
SERVICIOS_CRITICOS = ["RDP", "Telnet", "MySQL", "MongoDB", "Redis", "PostgreSQL",
                      "MSSQL", "Docker API", "Elasticsearch", "VNC"]
OMITIDOS_PASIVO = ["puertos y servicios expuestos", "identificación de servicios (banners)"]


def calcular_riesgo(puertos, dns, leaks, headers):
    score, desglose = 0, {}
    pts = 0
    for p in puertos:
        pts += 15 if p.get("servicio") in SERVICIOS_CRITICOS else 5
    pts = min(pts, 35)
    score += pts
    if pts: desglose["Red"] = pts
    spf   = 20 if dns and not dns.get("SPF")   else 0
    dmarc = 15 if dns and not dns.get("DMARC") else 0
    score += spf + dmarc
    if spf:   desglose["SPF ausente"]   = spf
    if dmarc: desglose["DMARC ausente"] = dmarc
    pts_l = min(len(leaks)*10, 30) if leaks else 0
    score += pts_l
    if pts_l: desglose["Filtraciones"] = pts_l
    return min(score, 100), desglose


def label_riesgo(score):
    if score >= 70: return "CRITICO",  "#EF4444"
    if score >= 40: return "MODERADO", "#F59E0B"
    return "BAJO", "#10B981"


def puntuar(res):
    """Calcula riesgo, etiqueta, color y desglose de un resultado y los guarda en él."""
    riesgo, desglose = calcular_riesgo(res.get("puertos") or [], res.get("dns") or {},
                                       res.get("leaks_raw") or [], res.get("headers") or {})

    def sumar(clave, pts):
        nonlocal riesgo
        riesgo = min(100, riesgo + pts)
        desglose[clave] = pts

    if (res.get("cms") or {}).get("riesgo"):
        sumar("CMS desactualizable", 10)
    wp = res.get("wp") or {}
    if wp.get("is_wordpress"):
        if wp.get("version_outdated"): sumar("WordPress obsoleto", 10)
        if wp.get("xmlrpc_exposed"):   sumar("xmlrpc.php expuesto", 5)
        if wp.get("users_enumerable"): sumar("Usuarios WP enumerables", 10)
        vp = len(wp.get("vulnerable_plugins") or [])
        if vp: sumar(f"{vp} plugin(s) vulnerable(s)", min(20, vp * 8))
        sf = len(wp.get("sensitive_files") or [])
        if sf: sumar(f"{sf} archivo(s) sensible(s) WP", min(15, sf * 5))
    ps = res.get("ps") or {}
    if ps.get("is_prestashop"):
        if ps.get("version_outdated"):    sumar("PrestaShop obsoleto", 10)
        if ps.get("admin_path_default"):  sumar("Admin PrestaShop sin renombrar", 15)
        if ps.get("install_dir_exposed"): sumar("/install/ PrestaShop accesible", 18)
        vm = len(ps.get("vulnerable_modules") or [])
        if vm: sumar(f"{vm} módulo(s) PS vulnerable(s)", min(20, vm * 8))
        sfp = len(ps.get("sensitive_files") or [])
        if sfp: sumar(f"{sfp} archivo(s) sensible(s) PS", min(15, sfp * 5))
        if not ps.get("https_forced"):    sumar("HTTPS no forzado (checkout)", 10)
        if ps.get("skimmer_suspect"):     sumar("Posible skimmer en checkout", 25)
    ssl_info = res.get("ssl") or {}
    if ssl_info.get("caducado"):
        sumar("SSL caducado", 20)
    elif ssl_info.get("pronto_a_caducar"):
        sumar("SSL por caducar", 10)

    label, color = label_riesgo(riesgo)
    res.update({"riesgo": riesgo, "label": label, "color": color, "desglose": desglose})
    return res


def _intentar(funcion, por_defecto, *args, **kwargs):
    try:
        return funcion(*args, **kwargs)
    except Exception:
        return por_defecto


def analizar(dominio, modo=MODO_PASIVO, subdominios=True, cms=True):
    """Ejecuta las comprobaciones que permite `modo` y devuelve el resultado
    (sin filtraciones ni puntuación: ver puntuar())."""
    completo = modo == MODO_COMPLETO
    ip = es_ip(dominio)
    cms_vacio = {"cms": None, "version": None, "riesgo": False, "detalle": ""}

    puertos = _intentar(scan_critical_ports_fast, [], dominio) if completo else []
    banners = _intentar(banner_grab, {}, dominio, puertos) if puertos else {}
    os_det = detect_os_from_banners(banners) if banners else None
    ssl_info = _intentar(ssl_scan, {}, dominio)
    headers = _intentar(check_security_headers, {}, dominio)

    dns, subs, cms_info = {}, [], dict(cms_vacio)
    wp = {"is_wordpress": False}
    ps = {"is_prestashop": False}
    if not ip:
        dns = _intentar(check_email_spoofing, {}, dominio)
        if subdominios:
            subs = _intentar(scan_subdomains, [], dominio)
        if cms:
            cms_info = _intentar(detect_cms, dict(cms_vacio), dominio)
            if cms_info.get("cms") == "WordPress":
                wp = _intentar(wordpress_audit, {"is_wordpress": False}, dominio, modo=modo)
            elif cms_info.get("cms") == "PrestaShop":
                ps = _intentar(prestashop_audit, {"is_prestashop": False}, dominio, modo=modo)

    omitidos = [] if completo else list(OMITIDOS_PASIVO)
    for auditoria in (wp, ps):
        omitidos += auditoria.get("omitidos") or []

    return {
        "dominio": dominio, "es_ip": ip,
        "puertos": puertos, "dns": dns,
        "headers": {k: bool(v) for k, v in headers.items()},
        "subs": subs, "leaks": 0, "leaks_raw": [],
        "cms": cms_info, "wp": wp, "ps": ps, "ssl": ssl_info,
        "banners": banners, "os": os_det,
        "modo": MODO_COMPLETO if completo else MODO_PASIVO,
        "parcial": not completo,
        "omitidos": omitidos,
        "timestamp": datetime.datetime.utcnow().strftime("%d/%m/%Y %H:%M"),
    }
