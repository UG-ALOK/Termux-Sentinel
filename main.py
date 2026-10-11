#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
TermuxSentinel - a defensive security toolkit for Termux (Android).

Pure Python 3, standard library only. For authorized, educational use.
See DISCLAIMER.md before using.

Modules:
  1. HTTP security-header audit (graded A-F)
  2. TLS certificate inspector
  3. DNS resolver
  4. Authorized TCP port checker (consent-gated, rate-limited)
  5. Device network info (offline, no external calls)
  6. Save session report (JSON)
"""

import argparse
import datetime
import ipaddress
import json
import os
import socket
import ssl
import sys
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed

__version__ = "1.0.0"
APP = "TermuxSentinel"
USER_AGENT = f"{APP}/{__version__} (+authorized-security-audit)"
REPORT_DIR = os.path.join(os.path.expanduser("~"), "sentinel_reports")

# ---------------------------------------------------------------- UI helpers


class C:
    """ANSI colors. Disabled when --no-color / NO_COLOR / not a TTY."""
    enabled = sys.stdout.isatty() and "NO_COLOR" not in os.environ

    @classmethod
    def _c(cls, code):
        return f"\033[{code}m" if cls.enabled else ""

    @classmethod
    def disable(cls):
        cls.enabled = False



def col(text, code):
    return f"{C._c(code)}{text}{C._c(0)}" if C.enabled else str(text)


def red(t): return col(t, "1;31")
def green(t): return col(t, "1;32")
def yellow(t): return col(t, "1;33")
def blue(t): return col(t, "1;34")
def magenta(t): return col(t, "1;35")
def cyan(t): return col(t, "1;36")
def dim(t): return col(t, "2")
def bold(t): return col(t, "1")


BANNER = r"""
  ______                          _____            _   _            _
 /_  __/__  _________ ___  __  __/ ___/___  ____  / |_(_)___  ___  / /
  / / / _ \/ ___/ __ `__ \/ / / /\__ \/ _ \/ __ \/ __/ / __ \/ _ \/ /
 / / /  __/ /  / / / / / / /_/ /___/ /  __/ / / / /_/ / / / /  __/ /
/_/  \___/_/  /_/ /_/ /_/\__,_//____/\___/_/ /_/\__/_/_/ /_/\___/_/
"""


def banner():
    os.system("clear" if os.name != "nt" else "cls")
    colors = ["1;35", "1;34", "1;36", "1;32", "1;33"]
    for i, line in enumerate(BANNER.strip("\n").splitlines()):
        print(col(line, colors[i % len(colors)]))
    print(dim("  Defensive toolkit for Termux  |  v%s  |  stdlib only" % __version__))
    print(dim("  Use only on systems you own or are authorized to test.\n"))


def box(title):
    line = "─" * (len(title) + 2)
    print(cyan(f"\n┌{line}┐\n│ {title} │\n└{line}┘"))


def ok(msg): print(f"  {green('[+]')} {msg}")
def warn(msg): print(f"  {yellow('[!]')} {msg}")
def bad(msg): print(f"  {red('[-]')} {msg}")
def info(msg): print(f"  {blue('[*]')} {msg}")


def ask(prompt):
    try:
        return input(f"  {magenta('›')} {prompt}").strip()
    except EOFError:
        return ""


def pause():
    ask(dim("Press Enter to continue..."))


# ------------------------------------------------------------ session store

SESSION = {"tool": APP, "version": __version__, "started": None, "results": []}


def record(module, target, data):
    SESSION["results"].append({
        "module": module,
        "target": target,
        "time": datetime.datetime.now().isoformat(timespec="seconds"),
        "data": data,
    })


# --------------------------------------------------------------- validation


def clean_host(raw):
    """Strip scheme/path/port-less junk and return a bare hostname."""
    raw = raw.strip()
    for p in ("https://", "http://"):
        if raw.lower().startswith(p):
            raw = raw[len(p):]
    raw = raw.split("/")[0].split("?")[0]
    if raw.count(":") == 1:  # host:port (IPv4/hostname)
        raw = raw.split(":")[0]
    return raw.strip().strip(".")


def valid_host(host):
    if not host or len(host) > 253:
        return False
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        pass
    allowed = set("abcdefghijklmnopqrstuvwxyz0123456789-.")
    return all(ch in allowed for ch in host.lower()) and not host.startswith("-")


def get_target(prompt="Target host or URL: "):
    host = clean_host(ask(prompt))
    if not valid_host(host):
        bad("Invalid host.")
        return None
    return host


# ------------------------------------------------------ 1. header audit

HEADER_CHECKS = [
    # (header, weight, advice)
    ("Strict-Transport-Security", 20, "Add HSTS: max-age=31536000; includeSubDomains"),
    ("Content-Security-Policy", 25, "Define a CSP to limit script/content sources"),
    ("X-Frame-Options", 10, "Use DENY/SAMEORIGIN (or CSP frame-ancestors)"),
    ("X-Content-Type-Options", 10, "Set to nosniff"),
    ("Referrer-Policy", 10, "Use e.g. strict-origin-when-cross-origin"),
    ("Permissions-Policy", 10, "Restrict browser features (camera, geolocation...)"),
    ("Cross-Origin-Opener-Policy", 5, "Use same-origin for isolation"),
]
LEAKY = ["Server", "X-Powered-By", "X-AspNet-Version", "X-Generator"]


def grade(score):
    for limit, letter in ((90, "A"), (75, "B"), (60, "C"), (40, "D")):
        if score >= limit:
            return letter
    return "F"


def fetch_headers(url, timeout=10):
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.geturl(), r.headers
    except urllib.error.HTTPError as e:  # 4xx/5xx still carry headers
        return e.code, url, e.headers


def audit_headers():
    box("HTTP SECURITY HEADER AUDIT")
    host = get_target()
    if not host:
        return
    result = None
    for scheme in ("https", "http"):
        url = f"{scheme}://{host}"
        info(f"Requesting {url} ...")
        try:
            status, final, headers = fetch_headers(url)
            result = (status, final, headers)
            break
        except (urllib.error.URLError, socket.timeout, ssl.SSLError, OSError) as e:
            warn(f"{scheme.upper()} failed: {getattr(e, 'reason', e)}")
    if not result:
        bad("Could not reach target.")
        return

    status, final, headers = result
    ok(f"HTTP {status}  ->  {final}")
    if final.startswith("http://"):
        warn("Site served over plain HTTP (no encryption).")

    score, missing, present = 0, [], []
    print()
    for name, weight, advice in HEADER_CHECKS:
        val = headers.get(name)
        if val:
            score += weight
            present.append(name)
            print(f"  {green('✔')} {name:<28} {dim(val[:50])}")
        else:
            missing.append({"header": name, "advice": advice})
            print(f"  {red('✘')} {name:<28} {yellow(advice)}")

    leaks = {h: headers.get(h) for h in LEAKY if headers.get(h)}
    for h, v in leaks.items():
        warn(f"Information disclosure: {h}: {v}")
        score -= 3

    cookie_issues = []
    for ck in headers.get_all("Set-Cookie") or []:
        low = ck.lower()
        name = ck.split("=")[0]
        for flag in ("secure", "httponly", "samesite"):
            if flag not in low:
                cookie_issues.append(f"{name}: missing {flag}")
    for issue in cookie_issues:
        warn(f"Cookie: {issue}")
        score -= 2

    score = max(0, min(100, score))
    g = grade(score)
    gc = green if g in "AB" else yellow if g in "CD" else red
    print(f"\n  Score: {bold(score)}/100   Grade: {gc(g)}")
    record("header_audit", host, {"status": status, "url": final, "score": score,
                                   "grade": g, "present": present, "missing": missing,
                                   "leaks": leaks, "cookie_issues": cookie_issues})


# --------------------------------------------------------- 2. TLS inspector


def inspect_tls():
    box("TLS CERTIFICATE INSPECTOR")
    host = get_target()
    if not host:
        return
    port_raw = ask("Port [443]: ") or "443"
    if not port_raw.isdigit() or not 1 <= int(port_raw) <= 65535:
        bad("Invalid port.")
        return
    port = int(port_raw)
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=8) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as s:
                cert, cipher, ver = s.getpeercert(), s.cipher(), s.version()
    except ssl.SSLCertVerificationError as e:
        bad(f"Certificate verification FAILED: {e.verify_message}")
        record("tls", host, {"verified": False, "error": e.verify_message})
        return
    except (socket.timeout, OSError, ssl.SSLError) as e:
        bad(f"Connection error: {e}")
        return

    def flat(rdn):
        return ", ".join(f"{k}={v}" for part in rdn for k, v in part)

    not_after = ssl.cert_time_to_seconds(cert["notAfter"])
    days = int((not_after - datetime.datetime.now().timestamp()) // 86400)
    sans = [v for k, v in cert.get("subjectAltName", ()) if k == "DNS"]

    ok("Certificate chain verified against system trust store")
    print(f"  {cyan('Subject '):<10}{flat(cert['subject'])}")
    print(f"  {cyan('Issuer  '):<10}{flat(cert['issuer'])}")
    print(f"  {cyan('Valid   '):<10}{cert['notBefore']}  →  {cert['notAfter']}")
    print(f"  {cyan('SANs    '):<10}{', '.join(sans[:6])}{' ...' if len(sans) > 6 else ''}")
    print(f"  {cyan('Protocol'):<10}{ver}")
    print(f"  {cyan('Cipher  '):<10}{cipher[0]} ({cipher[2]} bits)")

    findings = []
    if days < 0:
        findings.append("Certificate EXPIRED"); bad(findings[-1])
    elif days < 30:
        findings.append(f"Expires in {days} days"); warn(findings[-1])
    else:
        ok(f"{days} days until expiry")
    if ver in ("TLSv1", "TLSv1.1", "SSLv3"):
        findings.append(f"Weak protocol {ver}"); bad(findings[-1])
    record("tls", host, {"port": port, "verified": True, "subject": flat(cert["subject"]),
                         "issuer": flat(cert["issuer"]), "expires": cert["notAfter"],
                         "days_left": days, "protocol": ver, "cipher": cipher[0],
                         "findings": findings})


# ------------------------------------------------------------- 3. DNS


def dns_lookup():
    box("DNS RESOLVER")
    host = get_target("Hostname: ")
    if not host:
        return
    try:
        name, aliases, v4 = socket.gethostbyname_ex(host)
        ok(f"Canonical: {name}")
        for a in aliases:
            info(f"Alias: {a}")
        for ip in v4:
            ok(f"IPv4: {ip}")
    except socket.gaierror as e:
        bad(f"Resolution failed: {e}")
        return
    v6 = []
    try:
        for fam, _, _, _, sa in socket.getaddrinfo(host, None, socket.AF_INET6):
            if sa[0] not in v6:
                v6.append(sa[0])
        for ip in v6:
            ok(f"IPv6: {ip}")
    except socket.gaierror:
        info("No IPv6 records")
    rev = []
    for ip in v4[:3]:
        try:
            rev.append({ip: socket.gethostbyaddr(ip)[0]})
            info(f"Reverse {ip} → {rev[-1][ip]}")
        except (socket.herror, socket.gaierror):
            info(f"Reverse {ip} → (none)")
    record("dns", host, {"canonical": name, "aliases": aliases, "ipv4": v4,
                         "ipv6": v6, "reverse": rev})


# -------------------------------------------------------- 4. port checker

TOP_PORTS = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 465, 587,
             993, 995, 1433, 1723, 3306, 3389, 5432, 5900, 6379, 8000, 8080,
             8443, 8888, 9200, 27017]
RISKY = {21: "FTP (cleartext)", 23: "Telnet (cleartext)", 445: "SMB exposed",
         3389: "RDP exposed", 6379: "Redis exposed", 27017: "MongoDB exposed",
         9200: "Elasticsearch exposed", 3306: "MySQL exposed", 5900: "VNC exposed"}


def probe(host, port, timeout):
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return port, True
    except OSError:
        return port, False


def port_check():
    box("AUTHORIZED PORT CHECKER")
    print(yellow("  Probing hosts you do not own or administer may be illegal."))
    print(yellow("  This module only checks a short list of common ports.\n"))
    host = get_target()
    if not host:
        return
    try:
        ip = socket.gethostbyname(host)
    except socket.gaierror as e:
        bad(f"Cannot resolve: {e}")
        return
    pre = ipaddress.ip_address(ip)
    scope = "private/local" if (pre.is_private or pre.is_loopback) else "PUBLIC"
    info(f"Resolved {host} → {ip} ({scope})")
    if ask(f"Type {bold('I AUTHORIZE')} to confirm you have permission: ") != "I AUTHORIZE":
        warn("Authorization not confirmed. Aborted.")
        return

    ports = TOP_PORTS
    custom = ask("Custom ports (e.g. 22,80,8080) or Enter for defaults: ")
    if custom:
        try:
            ports = sorted({int(p) for p in custom.replace(" ", "").split(",") if p})
            if not ports or len(ports) > 100 or any(not 1 <= p <= 65535 for p in ports):
                raise ValueError
        except ValueError:
            bad("Provide up to 100 valid ports (1-65535).")
            return

    info(f"Checking {len(ports)} ports (10 threads, 1.5s timeout)...")
    open_ports = []
    with ThreadPoolExecutor(max_workers=10) as ex:
        futs = [ex.submit(probe, ip, p, 1.5) for p in ports]
        for f in as_completed(futs):
            p, is_open = f.result()
            if is_open:
                open_ports.append(p)
    open_ports.sort()
    risky = []
    for p in open_ports:
        try:
            svc = socket.getservbyport(p)
        except OSError:
            svc = "unknown"
        note = RISKY.get(p)
        if note:
            risky.append(p)
            print(f"  {red('OPEN')}  {p:<6}{svc:<12}{yellow(note)}")
        else:
            print(f"  {green('OPEN')}  {p:<6}{svc}")
    if not open_ports:
        ok("No open ports among those checked.")
    record("port_check", host, {"ip": ip, "checked": len(ports),
                                "open": open_ports, "risky": risky})


# ----------------------------------------------------------- 5. net info


def local_ip():
    """Find the primary local IP. UDP connect sends no packets."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("192.0.2.1", 9))  # TEST-NET-1, never routed
        return s.getsockname()[0]
    except OSError:
        return None
    finally:
        s.close()


def net_info():
    box("DEVICE NETWORK INFO")
    ip = local_ip()
    data = {"hostname": socket.gethostname(), "local_ip": ip,
            "termux": "com.termux" in os.environ.get("PREFIX", ""),
            "python": sys.version.split()[0]}
    ok(f"Hostname : {data['hostname']}")
    if ip:
        kind = "private" if ipaddress.ip_address(ip).is_private else "public"
        ok(f"Local IP : {ip} ({kind})")
        data["subnet_guess"] = str(ipaddress.ip_network(ip + "/24", strict=False))
        info(f"Likely /24 subnet: {data['subnet_guess']}")
    else:
        warn("No active network interface detected (offline?)")
    info(f"Termux   : {'yes' if data['termux'] else 'no'}")
    info(f"Python   : {data['python']}")
    record("net_info", "localhost", data)


# ------------------------------------------------------------- 6. report


def save_report():
    box("SAVE SESSION REPORT")
    if not SESSION["results"]:
        warn("Nothing to save yet. Run a module first.")
        return
    os.makedirs(REPORT_DIR, exist_ok=True)
    stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    path = os.path.join(REPORT_DIR, f"sentinel_{stamp}.json")
    SESSION["saved"] = datetime.datetime.now().isoformat(timespec="seconds")
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(SESSION, fh, indent=2)
    ok(f"Saved {len(SESSION['results'])} result(s) → {path}")


# ---------------------------------------------------------------- menu

MENU = [
    ("1", "HTTP Security Header Audit", audit_headers),
    ("2", "TLS Certificate Inspector", inspect_tls),
    ("3", "DNS Resolver", dns_lookup),
    ("4", "Authorized Port Checker", port_check),
    ("5", "Device Network Info", net_info),
    ("6", "Save Session Report (JSON)", save_report),
]


def show_menu():
    banner()
    print(cyan("  ╔══════════════ MAIN MENU ══════════════╗"))
    for key, label, _ in MENU:
        print(f"  {cyan('║')} {magenta('['+key+']')} {label:<34}{cyan('║')}")
    print(f"  {cyan('║')} {red('[0]')} {'Exit':<34}{cyan('║')}")
    print(cyan("  ╚═══════════════════════════════════════╝"))


def require_consent():
    """First-run acknowledgement of the disclaimer."""
    banner()
    print(yellow("  LEGAL NOTICE"))
    print("  This tool is for education and AUTHORIZED security auditing only.")
    print("  You are solely responsible for how you use it. See DISCLAIMER.md.\n")
    return ask("Type 'yes' to accept and continue: ").lower() == "yes"


def main():
    ap = argparse.ArgumentParser(description=f"{APP} - defensive Termux toolkit")
    ap.add_argument("--no-color", action="store_true", help="disable ANSI colors")
    ap.add_argument("--version", action="version", version=f"{APP} {__version__}")
    args = ap.parse_args()
    if args.no_color:
        C.disable()

    SESSION["started"] = datetime.datetime.now().isoformat(timespec="seconds")
    if sys.version_info < (3, 7):
        sys.exit("Python 3.7+ required.")
    if not require_consent():
        print("Consent not given. Exiting.")
        return 1

    actions = {k: fn for k, _, fn in MENU}
    while True:
        show_menu()
        choice = ask("Select an option: ")
        if choice == "0":
            if SESSION["results"] and ask("Save report before exit? [y/N]: ").lower() == "y":
                save_report()
            print(green("\n  Stay safe. Goodbye!\n"))
            return 0
        fn = actions.get(choice)
        if not fn:
            bad("Invalid option.")
            pause()
            continue
        try:
            fn()
        except KeyboardInterrupt:
            warn("Cancelled.")
        except Exception as e:  # last-resort guard: never crash the menu
            bad(f"Unexpected error: {type(e).__name__}: {e}")
        pause()


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print(red("\n\n  Interrupted. Bye!"))
        sys.exit(130)
