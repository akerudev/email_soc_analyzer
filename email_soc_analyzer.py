#!/usr/bin/env python3
"""
email_soc_analyzer.py
=====================
Tool SOC per analisi email via IMAP.
Analizza: header (SPF/DKIM/DMARC), phishing, IOC, allegati sospetti.

Autore: Munimen - Alessandro
"""

import imaplib
import email
import re
import hashlib
import socket
import ssl
import os
import sys
import json
import ipaddress
from email import policy
from email.header import decode_header
from datetime import datetime
from urllib.parse import urlparse
import textwrap

# ──────────────────────────────────────────────
#  CONFIGURAZIONE
# ──────────────────────────────────────────────

IMAP_CONFIGS = {
    "gmail":   {"host": "imap.gmail.com",   "port": 993},
    "outlook": {"host": "outlook.office365.com", "port": 993},
    "custom":  {"host": None,               "port": 993},
}

# Estensioni allegati considerate ad alto rischio
SUSPICIOUS_EXTENSIONS = {
    ".exe", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jar",
    ".scr", ".pif", ".com", ".msi", ".dll", ".iso", ".img",
    ".doc", ".docm", ".xlsm", ".xls", ".ppt", ".pptm",
    ".hta", ".wsf", ".lnk", ".reg",
}

# Parole chiave phishing comuni (italiano + inglese)
PHISHING_KEYWORDS = [
    "verifica il tuo account", "accedi subito", "clicca qui", "sospeso",
    "bloccato", "conferma le tue credenziali", "urgente", "scaduto",
    "aggiorna i dati", "hai vinto", "trasferimento", "eredità",
    "verify your account", "suspended", "click here", "confirm your password",
    "update your information", "you have won", "bank transfer", "login attempt",
    "unusual activity", "reset your password",
]

# Domini noti per URL shortener / redirezione (spesso usati nel phishing)
SUSPICIOUS_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
    "rebrand.ly", "cutt.ly", "is.gd", "tiny.cc",
}

# ──────────────────────────────────────────────
#  HELPERS VISUALI
# ──────────────────────────────────────────────

RED    = "\033[91m"
YELLOW = "\033[93m"
GREEN  = "\033[92m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

def banner():
    print(f"""{CYAN}{BOLD}
╔══════════════════════════════════════════════════════╗
║          MUNIMEN - Email SOC Analyzer v1.0           ║
║        Analisi IMAP  |  IOC  |  Phishing  |  Header  ║
╚══════════════════════════════════════════════════════╝
{RESET}""")

def section(title):
    width = 56
    print(f"\n{BOLD}{CYAN}{'─' * width}{RESET}")
    print(f"{BOLD}  {title}{RESET}")
    print(f"{CYAN}{'─' * width}{RESET}")

def flag(level, msg):
    """Stampa un flag con livello: OK / WARN / ALERT"""
    icons = {"OK": f"{GREEN}[✔ OK   ]{RESET}", "WARN": f"{YELLOW}[⚠ WARN ]{RESET}", "ALERT": f"{RED}[✘ ALERT]{RESET}"}
    print(f"  {icons.get(level, '')} {msg}")

def info(msg):
    print(f"  {CYAN}[i]{RESET} {msg}")

# ──────────────────────────────────────────────
#  CONNESSIONE IMAP
# ──────────────────────────────────────────────

def connect_imap(provider: str, username: str, password: str, custom_host: str = None):
    cfg = IMAP_CONFIGS.get(provider, IMAP_CONFIGS["custom"])
    host = custom_host if provider == "custom" else cfg["host"]
    port = cfg["port"]
    info(f"Connessione a {host}:{port} ...")
    ctx = ssl.create_default_context()
    conn = imaplib.IMAP4_SSL(host, port, ssl_context=ctx)
    conn.login(username, password)
    info(f"Login OK come {username}")
    return conn

def fetch_emails(conn, folder="INBOX", limit=10, unread_only=False):
    conn.select(folder, readonly=True)
    criteria = "(UNSEEN)" if unread_only else "ALL"
    _, data = conn.search(None, criteria)
    ids = data[0].split()
    ids = ids[-limit:]  # ultime N email
    messages = []
    for uid in ids:
        _, msg_data = conn.fetch(uid, "(RFC822)")
        raw = msg_data[0][1]
        msg = email.message_from_bytes(raw, policy=policy.default)
        messages.append((uid.decode(), msg))
    info(f"Scaricate {len(messages)} email da {folder}")
    return messages

# ──────────────────────────────────────────────
#  DECODIFICA HEADER
# ──────────────────────────────────────────────

def decode_mime_words(s: str) -> str:
    if not s:
        return ""
    decoded_parts = decode_header(s)
    result = []
    for part, enc in decoded_parts:
        if isinstance(part, bytes):
            result.append(part.decode(enc or "utf-8", errors="replace"))
        else:
            result.append(part)
    return " ".join(result)

def extract_ip_from_received(received_headers: list) -> list:
    ip_pattern = re.compile(
        r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    )
    ips = []
    for hdr in received_headers:
        found = ip_pattern.findall(hdr)
        for ip in found:
            try:
                obj = ipaddress.ip_address(ip)
                if not obj.is_private and not obj.is_loopback:
                    ips.append(ip)
            except ValueError:
                pass
    return list(dict.fromkeys(ips))  # deduplicati, ordine preservato

def analyze_headers(msg):
    section("ANALISI HEADER")

    # Mittente
    sender = decode_mime_words(msg.get("From", ""))
    reply_to = decode_mime_words(msg.get("Reply-To", ""))
    info(f"From:      {sender}")
    info(f"Reply-To:  {reply_to if reply_to else '(assente)'}")

    # Mismatch From / Reply-To
    if reply_to and reply_to.strip() != sender.strip():
        flag("WARN", f"Reply-To diverso da From → possibile spoofing")

    # Subject
    subject = decode_mime_words(msg.get("Subject", "(no subject)"))
    info(f"Subject:   {subject}")

    # Date
    date = msg.get("Date", "(no date)")
    info(f"Date:      {date}")

    # SPF / DKIM / DMARC (letti dagli header Authentication-Results)
    auth_results = msg.get("Authentication-Results", "") or msg.get("ARC-Authentication-Results", "")
    section("SPF / DKIM / DMARC")
    if auth_results:
        for check in ["spf", "dkim", "dmarc"]:
            match = re.search(rf'{check}=(\S+)', auth_results, re.IGNORECASE)
            if match:
                result = match.group(1).rstrip(";,")
                level = "OK" if result.lower() in ("pass", "pass;") else "ALERT"
                flag(level, f"{check.upper()}: {result}")
            else:
                flag("WARN", f"{check.upper()}: non trovato negli header")
    else:
        flag("WARN", "Authentication-Results assente (header non fornito dal server)")

    # Received hop chain → IP pubblici
    received = msg.get_all("Received") or []
    ips = extract_ip_from_received(received)
    section("IP PUBBLICI NEL PERCORSO")
    if ips:
        for ip in ips:
            flag("WARN", f"IP rilevato: {ip}  ← verifica su VirusTotal / AbuseIPDB")
    else:
        info("Nessun IP pubblico trovato nella catena Received")

    return {
        "sender": sender,
        "reply_to": reply_to,
        "subject": subject,
        "ips": ips,
        "auth_results": auth_results,
    }

# ──────────────────────────────────────────────
#  ESTRAZIONE CORPO + IOC
# ──────────────────────────────────────────────

def get_body(msg) -> tuple[str, str]:
    """Restituisce (text_plain, text_html)"""
    plain, html = "", ""
    if msg.is_multipart():
        for part in msg.walk():
            ct = part.get_content_type()
            cd = str(part.get("Content-Disposition", ""))
            if "attachment" in cd:
                continue
            if ct == "text/plain":
                plain += part.get_payload(decode=True).decode(
                    part.get_content_charset() or "utf-8", errors="replace"
                )
            elif ct == "text/html":
                html += part.get_payload(decode=True).decode(
                    part.get_content_charset() or "utf-8", errors="replace"
                )
    else:
        ct = msg.get_content_type()
        payload = msg.get_payload(decode=True)
        if payload:
            decoded = payload.decode(msg.get_content_charset() or "utf-8", errors="replace")
            if ct == "text/html":
                html = decoded
            else:
                plain = decoded
    return plain, html

def extract_urls(text: str) -> list:
    pattern = re.compile(
        r'https?://[^\s\'"<>]+'
        r'|www\.[^\s\'"<>]+'
        r'|(?:href|src)=["\']([^"\']+)["\']',
        re.IGNORECASE
    )
    matches = pattern.findall(text)
    urls = []
    for m in matches:
        url = m if isinstance(m, str) else m
        url = url.strip().rstrip(".,;)")
        if url:
            urls.append(url)
    return list(dict.fromkeys(urls))

def extract_domains(urls: list) -> list:
    domains = []
    for url in urls:
        if not url.startswith("http"):
            url = "http://" + url
        try:
            parsed = urlparse(url)
            if parsed.hostname:
                domains.append(parsed.hostname.lower())
        except Exception:
            pass
    return list(dict.fromkeys(domains))

def extract_ips_from_body(text: str) -> list:
    pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
    found = pattern.findall(text)
    ips = []
    for ip in found:
        try:
            obj = ipaddress.ip_address(ip)
            if not obj.is_private and not obj.is_loopback:
                ips.append(ip)
        except ValueError:
            pass
    return list(dict.fromkeys(ips))

def analyze_ioc(plain: str, html: str):
    section("ESTRAZIONE IOC")
    combined = plain + html

    urls = extract_urls(combined)
    domains = extract_domains(urls)
    ips = extract_ips_from_body(combined)

    # URL
    if urls:
        info(f"URL trovati: {len(urls)}")
        for url in urls[:15]:  # max 15 in console
            short = url[:80] + "…" if len(url) > 80 else url
            dom = urlparse(url if url.startswith("http") else "http://" + url).hostname or ""
            if any(s in dom for s in SUSPICIOUS_DOMAINS):
                flag("ALERT", f"URL shortener sospetto: {short}")
            else:
                flag("WARN", f"URL: {short}")
    else:
        flag("OK", "Nessun URL trovato nel corpo")

    # Domini
    if domains:
        info(f"Domini unici: {', '.join(domains[:10])}")

    # IP nel corpo
    if ips:
        for ip in ips:
            flag("ALERT", f"IP raw nel corpo email: {ip}")

    return {"urls": urls, "domains": domains, "ips_in_body": ips}

# ──────────────────────────────────────────────
#  RILEVAMENTO PHISHING
# ──────────────────────────────────────────────

def analyze_phishing(plain: str, html: str, header_data: dict):
    section("RILEVAMENTO PHISHING / SOCIAL ENGINEERING")
    combined = (plain + html).lower()
    hits = []

    for kw in PHISHING_KEYWORDS:
        if kw.lower() in combined:
            hits.append(kw)

    if hits:
        flag("ALERT", f"Keyword phishing rilevate ({len(hits)}): {', '.join(hits[:5])}")
    else:
        flag("OK", "Nessuna keyword phishing rilevata")

    # Reply-To mismatch già segnalato negli header, qui calcolo score
    score = 0
    score += len(hits) * 2
    if header_data.get("reply_to") and header_data["reply_to"] != header_data["sender"]:
        score += 10
    if header_data.get("ips"):
        score += 5

    risk = "BASSO"
    color = GREEN
    if score >= 10:
        risk = "MEDIO"
        color = YELLOW
    if score >= 20:
        risk = "ALTO"
        color = RED

    print(f"\n  {BOLD}Phishing Risk Score: {color}{score}{RESET}  →  Livello: {color}{BOLD}{risk}{RESET}")
    return score

# ──────────────────────────────────────────────
#  ANALISI ALLEGATI
# ──────────────────────────────────────────────

def analyze_attachments(msg):
    section("ANALISI ALLEGATI")
    found_any = False

    for part in msg.walk():
        cd = str(part.get("Content-Disposition", ""))
        if "attachment" not in cd:
            continue

        filename_raw = part.get_filename() or "unknown"
        filename = decode_mime_words(filename_raw)
        ext = os.path.splitext(filename)[1].lower()

        payload = part.get_payload(decode=True)
        if not payload:
            continue

        found_any = True
        size = len(payload)
        md5  = hashlib.md5(payload).hexdigest()
        sha1 = hashlib.sha1(payload).hexdigest()
        sha256 = hashlib.sha256(payload).hexdigest()

        level = "ALERT" if ext in SUSPICIOUS_EXTENSIONS else "WARN"
        flag(level, f"Allegato: {filename}  ({size} bytes)")
        info(f"  Estensione: {ext or '(nessuna)'}")
        info(f"  MD5:    {md5}")
        info(f"  SHA1:   {sha1}")
        info(f"  SHA256: {sha256}")
        info(f"  → Controlla su: https://www.virustotal.com/gui/file/{sha256}")

        if ext in SUSPICIOUS_EXTENSIONS:
            flag("ALERT", f"Estensione AD ALTO RISCHIO: {ext}")

    if not found_any:
        flag("OK", "Nessun allegato trovato")

# ──────────────────────────────────────────────
#  REPORT FINALE SINGOLA EMAIL
# ──────────────────────────────────────────────

def analyze_email(uid: str, msg):
    print(f"\n\n{'═' * 58}")
    print(f"{BOLD}{CYAN}  EMAIL UID: {uid}{RESET}")
    print(f"{'═' * 58}")

    header_data = analyze_headers(msg)
    plain, html = get_body(msg)
    ioc_data = analyze_ioc(plain, html)
    score = analyze_phishing(plain, html, header_data)
    analyze_attachments(msg)

    section("RIEPILOGO")
    info(f"Mittente:    {header_data['sender']}")
    info(f"Oggetto:     {header_data['subject']}")
    info(f"IP pubblici: {len(header_data['ips'])} rilevati")
    info(f"URL trovati: {len(ioc_data['urls'])}")
    info(f"Risk Score:  {score}")

    return {
        "uid": uid,
        "subject": header_data["subject"],
        "sender": header_data["sender"],
        "phishing_score": score,
        "ioc_urls": ioc_data["urls"],
        "ioc_domains": ioc_data["domains"],
    }

# ──────────────────────────────────────────────
#  MAIN
# ──────────────────────────────────────────────

def main():
    banner()

    # ── Selezione provider ──
    print(f"{BOLD}Provider IMAP:{RESET}")
    print("  1) Gmail")
    print("  2) Outlook / Office 365")
    print("  3) Custom (inserisci host)")
    choice = input("\nScelta [1-3]: ").strip()
    provider_map = {"1": "gmail", "2": "outlook", "3": "custom"}
    provider = provider_map.get(choice, "gmail")

    custom_host = None
    if provider == "custom":
        custom_host = input("Host IMAP: ").strip()

    username = input("Email/username: ").strip()
    import getpass
    password = getpass.getpass("Password (o App Password): ")

    folder = input("Cartella [default: INBOX]: ").strip() or "INBOX"
    limit_str = input("Quante email analizzare? [default: 5]: ").strip()
    limit = int(limit_str) if limit_str.isdigit() else 5
    unread_only = input("Solo non lette? [s/N]: ").strip().lower() == "s"

    # ── Connessione ──
    try:
        conn = connect_imap(provider, username, password, custom_host)
    except imaplib.IMAP4.error as e:
        print(f"\n{RED}Errore login IMAP: {e}{RESET}")
        print("  → Gmail: abilita 'App Password' nelle impostazioni Google (con 2FA attivo)")
        print("  → Outlook: usa password account o App Password")
        sys.exit(1)

    # ── Fetch & analisi ──
    messages = fetch_emails(conn, folder=folder, limit=limit, unread_only=unread_only)
    results = []
    for uid, msg in messages:
        result = analyze_email(uid, msg)
        results.append(result)

    conn.logout()

    # ── Sommario finale ──
    print(f"\n\n{'═' * 58}")
    print(f"{BOLD}{CYAN}  SOMMARIO ANALISI  ({len(results)} email){RESET}")
    print(f"{'═' * 58}")
    for r in results:
        risk_color = GREEN if r["phishing_score"] < 10 else (YELLOW if r["phishing_score"] < 20 else RED)
        print(f"  UID {r['uid']:>6}  Score: {risk_color}{r['phishing_score']:>3}{RESET}  {r['subject'][:50]}")

    # ── Salvataggio JSON opzionale ──
    save = input("\nSalvare report JSON? [s/N]: ").strip().lower()
    if save == "s":
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        fname = f"soc_report_{ts}.json"
        with open(fname, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2, ensure_ascii=False, default=str)
        print(f"{GREEN}Report salvato: {fname}{RESET}")


if __name__ == "__main__":
    main()
