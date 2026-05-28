#!/usr/bin/env python3
"""
email_soc_analyzer.py
=====================
Tool SOC per analisi email via OAuth2 + Gmail API.
Analizza: header (SPF/DKIM/DMARC), phishing, IOC, allegati sospetti.

Autore: Munimen - Alessandro

Dipendenze:
    pip install google-auth-oauthlib google-auth-httplib2 google-api-python-client

Setup iniziale:
    1. Crea un progetto su https://console.cloud.google.com
    2. Abilita Gmail API
    3. Crea credenziali OAuth2 (App Desktop) → scarica credentials.json
    4. Metti credentials.json nella stessa cartella di questo script
"""

import os
import sys
import re
import base64
import hashlib
import json
import ipaddress
import email
from email import policy
from email.header import decode_header
from datetime import datetime
from urllib.parse import urlparse

# OAuth2 — Google
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from googleapiclient.discovery import build

# ──────────────────────────────────────────────
#  CONFIGURAZIONE OAuth2
# ──────────────────────────────────────────────

SCOPES           = ["https://www.googleapis.com/auth/gmail.readonly"]
TOKEN_FILE       = "token.json"
CREDENTIALS_FILE = "credentials.json"

# ──────────────────────────────────────────────
#  CONFIGURAZIONE ANALISI
# ──────────────────────────────────────────────

SUSPICIOUS_EXTENSIONS = {
    ".exe", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jar",
    ".scr", ".pif", ".com", ".msi", ".dll", ".iso", ".img",
    ".doc", ".docm", ".xlsm", ".xls", ".ppt", ".pptm",
    ".hta", ".wsf", ".lnk", ".reg",
}

PHISHING_KEYWORDS = [
    "verifica il tuo account", "accedi subito", "clicca qui", "sospeso",
    "bloccato", "conferma le tue credenziali", "urgente", "scaduto",
    "aggiorna i dati", "hai vinto", "trasferimento", "eredità",
    "verify your account", "suspended", "click here", "confirm your password",
    "update your information", "you have won", "bank transfer", "login attempt",
    "unusual activity", "reset your password",
]

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
║          MUNIMEN - Email SOC Analyzer v2.0           ║
║   OAuth2 + Gmail API  |  IOC  |  Phishing  |  Header  ║
╚══════════════════════════════════════════════════════╝
{RESET}""")

def section(title):
    width = 56
    print(f"\n{BOLD}{CYAN}{'─' * width}{RESET}")
    print(f"{BOLD}  {title}{RESET}")
    print(f"{CYAN}{'─' * width}{RESET}")

def flag(level, msg):
    icons = {
        "OK":    f"{GREEN}[✔ OK   ]{RESET}",
        "WARN":  f"{YELLOW}[⚠ WARN ]{RESET}",
        "ALERT": f"{RED}[✘ ALERT]{RESET}",
    }
    print(f"  {icons.get(level, '')} {msg}")

def info(msg):
    print(f"  {CYAN}[i]{RESET} {msg}")

# ──────────────────────────────────────────────
#  AUTENTICAZIONE OAuth2
# ──────────────────────────────────────────────

def get_gmail_service():
    """
    Autentica via OAuth2 e restituisce il servizio Gmail API.
    - Prima volta: apre il browser per il login Google
    - Volte successive: rinnova il token in automatico, nessun browser
    - Il token viene salvato in token.json
    """
    creds = None

    if os.path.exists(TOKEN_FILE):
        creds = Credentials.from_authorized_user_file(TOKEN_FILE, SCOPES)

    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
            info("Token rinnovato automaticamente")
        else:
            if not os.path.exists(CREDENTIALS_FILE):
                print(f"\n{RED}Errore: file '{CREDENTIALS_FILE}' non trovato.{RESET}")
                print("  → Scaricalo da Google Cloud Console:")
                print("    https://console.cloud.google.com → API e servizi → Credenziali")
                sys.exit(1)

            info("Apertura browser per autenticazione Google...")
            flow = InstalledAppFlow.from_client_secrets_file(CREDENTIALS_FILE, SCOPES)
            creds = flow.run_local_server(port=0)
            info(f"{GREEN}Login OAuth2 completato{RESET}")

        with open(TOKEN_FILE, "w") as f:
            f.write(creds.to_json())
        info(f"Token salvato in {TOKEN_FILE}")

    return build("gmail", "v1", credentials=creds)


# ──────────────────────────────────────────────
#  FETCH EMAIL via Gmail API
# ──────────────────────────────────────────────

def fetch_emails_oauth(service, limit=10, unread_only=False):
    """
    Scarica le email usando Gmail API.
    Restituisce lista di (message_id, email.message) — stessa struttura
    dell'ex fetch IMAP, tutti i moduli di analisi restano invariati.
    """
    query = "is:unread" if unread_only else ""

    results = service.users().messages().list(
        userId="me",
        q=query,
        maxResults=limit,
    ).execute()

    msg_refs = results.get("messages", [])
    if not msg_refs:
        info("Nessuna email trovata con i criteri selezionati")
        return []

    messages = []
    for ref in msg_refs:
        raw_msg = service.users().messages().get(
            userId="me",
            id=ref["id"],
            format="raw",
        ).execute()

        raw_bytes = base64.urlsafe_b64decode(raw_msg["raw"].encode("utf-8"))
        parsed = email.message_from_bytes(raw_bytes, policy=policy.default)
        messages.append((ref["id"], parsed))

    info(f"Scaricate {len(messages)} email via Gmail API")
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
    ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
    ips = []
    for hdr in received_headers:
        for ip in ip_pattern.findall(hdr):
            try:
                obj = ipaddress.ip_address(ip)
                if not obj.is_private and not obj.is_loopback:
                    ips.append(ip)
            except ValueError:
                pass
    return list(dict.fromkeys(ips))

def analyze_headers(msg):
    section("ANALISI HEADER")

    sender   = decode_mime_words(msg.get("From", ""))
    reply_to = decode_mime_words(msg.get("Reply-To", ""))
    subject  = decode_mime_words(msg.get("Subject", "(no subject)"))
    date     = msg.get("Date", "(no date)")

    info(f"From:      {sender}")
    info(f"Reply-To:  {reply_to if reply_to else '(assente)'}")
    info(f"Subject:   {subject}")
    info(f"Date:      {date}")

    if reply_to and reply_to.strip() != sender.strip():
        flag("WARN", "Reply-To diverso da From → possibile spoofing")

    auth_results = msg.get("Authentication-Results", "") or msg.get("ARC-Authentication-Results", "")
    section("SPF / DKIM / DMARC")
    if auth_results:
        for check in ["spf", "dkim", "dmarc"]:
            match = re.search(rf'{check}=(\S+)', auth_results, re.IGNORECASE)
            if match:
                result = match.group(1).rstrip(";,")
                level = "OK" if result.lower().startswith("pass") else "ALERT"
                flag(level, f"{check.upper()}: {result}")
            else:
                flag("WARN", f"{check.upper()}: non trovato negli header")
    else:
        flag("WARN", "Authentication-Results assente (header non fornito dal server)")

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
    plain, html = "", ""
    if msg.is_multipart():
        for part in msg.walk():
            ct = part.get_content_type()
            cd = str(part.get("Content-Disposition", ""))
            if "attachment" in cd:
                continue
            payload = part.get_payload(decode=True)
            if not payload:
                continue
            charset = part.get_content_charset() or "utf-8"
            decoded = payload.decode(charset, errors="replace")
            if ct == "text/plain":
                plain += decoded
            elif ct == "text/html":
                html += decoded
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
        re.IGNORECASE,
    )
    urls = []
    for m in pattern.findall(text):
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
    ips = []
    for ip in pattern.findall(text):
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

    urls    = extract_urls(combined)
    domains = extract_domains(urls)
    ips     = extract_ips_from_body(combined)

    if urls:
        info(f"URL trovati: {len(urls)}")
        for url in urls[:15]:
            short = url[:80] + "…" if len(url) > 80 else url
            dom = urlparse(url if url.startswith("http") else "http://" + url).hostname or ""
            if any(s in dom for s in SUSPICIOUS_DOMAINS):
                flag("ALERT", f"URL shortener sospetto: {short}")
            else:
                flag("WARN", f"URL: {short}")
    else:
        flag("OK", "Nessun URL trovato nel corpo")

    if domains:
        info(f"Domini unici: {', '.join(domains[:10])}")

    for ip in ips:
        flag("ALERT", f"IP raw nel corpo email: {ip}")

    return {"urls": urls, "domains": domains, "ips_in_body": ips}


# ──────────────────────────────────────────────
#  RILEVAMENTO PHISHING
# ──────────────────────────────────────────────

def analyze_phishing(plain: str, html: str, header_data: dict):
    section("RILEVAMENTO PHISHING / SOCIAL ENGINEERING")
    combined = (plain + html).lower()
    hits = [kw for kw in PHISHING_KEYWORDS if kw.lower() in combined]

    if hits:
        flag("ALERT", f"Keyword phishing rilevate ({len(hits)}): {', '.join(hits[:5])}")
    else:
        flag("OK", "Nessuna keyword phishing rilevata")

    score = len(hits) * 2
    if header_data.get("reply_to") and header_data["reply_to"] != header_data["sender"]:
        score += 10
    if header_data.get("ips"):
        score += 5

    if score >= 20:
        risk, color = "ALTO",  RED
    elif score >= 10:
        risk, color = "MEDIO", YELLOW
    else:
        risk, color = "BASSO", GREEN

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

        filename = decode_mime_words(part.get_filename() or "unknown")
        ext      = os.path.splitext(filename)[1].lower()
        payload  = part.get_payload(decode=True)
        if not payload:
            continue

        found_any = True
        size   = len(payload)
        md5    = hashlib.md5(payload).hexdigest()
        sha1   = hashlib.sha1(payload).hexdigest()
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
#  ANALISI SINGOLA EMAIL
# ──────────────────────────────────────────────

def analyze_email(uid: str, msg):
    print(f"\n\n{'═' * 58}")
    print(f"{BOLD}{CYAN}  EMAIL ID: {uid}{RESET}")
    print(f"{'═' * 58}")

    header_data = analyze_headers(msg)
    plain, html = get_body(msg)
    ioc_data    = analyze_ioc(plain, html)
    score       = analyze_phishing(plain, html, header_data)
    analyze_attachments(msg)

    section("RIEPILOGO")
    info(f"Mittente:    {header_data['sender']}")
    info(f"Oggetto:     {header_data['subject']}")
    info(f"IP pubblici: {len(header_data['ips'])} rilevati")
    info(f"URL trovati: {len(ioc_data['urls'])}")
    info(f"Risk Score:  {score}")

    return {
        "uid":            uid,
        "subject":        header_data["subject"],
        "sender":         header_data["sender"],
        "phishing_score": score,
        "ioc_urls":       ioc_data["urls"],
        "ioc_domains":    ioc_data["domains"],
    }


# ──────────────────────────────────────────────
#  MAIN
# ──────────────────────────────────────────────

def main():
    banner()

    limit_str   = input("Quante email analizzare? [default: 5]: ").strip()
    limit       = int(limit_str) if limit_str.isdigit() else 5
    unread_only = input("Solo non lette? [s/N]: ").strip().lower() == "s"

    # Autenticazione OAuth2
    try:
        service = get_gmail_service()
    except Exception as e:
        print(f"\n{RED}Errore autenticazione OAuth2: {e}{RESET}")
        print("  → Verifica che credentials.json sia nella cartella corrente")
        print("  → Verifica che Gmail API sia abilitata su Google Cloud Console")
        sys.exit(1)

    # Fetch & analisi
    messages = fetch_emails_oauth(service, limit=limit, unread_only=unread_only)
    if not messages:
        print(f"\n{YELLOW}Nessuna email da analizzare.{RESET}")
        sys.exit(0)

    results = []
    for uid, msg in messages:
        result = analyze_email(uid, msg)
        results.append(result)

    # Sommario finale
    print(f"\n\n{'═' * 58}")
    print(f"{BOLD}{CYAN}  SOMMARIO ANALISI  ({len(results)} email){RESET}")
    print(f"{'═' * 58}")
    for r in results:
        risk_color = GREEN if r["phishing_score"] < 10 else (YELLOW if r["phishing_score"] < 20 else RED)
        print(f"  ID {r['uid'][:12]}…  Score: {risk_color}{r['phishing_score']:>3}{RESET}  {r['subject'][:45]}")

    # Salvataggio JSON opzionale
    save = input("\nSalvare report JSON? [s/N]: ").strip().lower()
    if save == "s":
        ts    = datetime.now().strftime("%Y%m%d_%H%M%S")
        fname = f"soc_report_{ts}.json"
        with open(fname, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2, ensure_ascii=False, default=str)
        print(f"{GREEN}Report salvato: {fname}{RESET}")


if __name__ == "__main__":
    main()
