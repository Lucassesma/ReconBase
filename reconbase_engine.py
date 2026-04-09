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
# MÓDULO 6: VIGILANCIA NOCTURNA
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