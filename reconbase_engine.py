import concurrent.futures
import requests
import socket
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
    resultados = {v: False for v in CABECERAS.values()}
    for scheme in ["https","http"]:
        try:
            r = requests.get(f"{scheme}://{domain}", timeout=timeout,
                             allow_redirects=True, headers={"User-Agent":"ReconBase-Enterprise-v2"})
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
                                    version = wp_data.get("version") or wp_data.get("gmt_offset") and None
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