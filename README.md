# 🛡️ Email SOC Analyzer

Sicurezza informatica per chi non può permettersi di abbassare la guardia.

Strumento da riga di comando per l'analisi automatizzata delle email aziendali alla ricerca di minacce: phishing, allegati pericolosi, spoofing e IOC (Indicators of Compromise).

Si connette a Gmail tramite **OAuth2 + Gmail API** — nessuna password memorizzata, accesso in sola lettura.

---

## ✨ Funzionalità

| Modulo | Cosa analizza |
|---|---|
| **Header Analysis** | SPF / DKIM / DMARC, Reply-To spoofing, IP pubblici nella catena Received |
| **Phishing Detection** | 30+ keyword in italiano e inglese, Risk Score BASSO / MEDIO / ALTO |
| **IOC Extraction** | URL, domini, IP raw nel corpo, URL shortener sospetti |
| **Analisi Allegati** | Hash MD5 / SHA1 / SHA256, estensioni ad alto rischio, link VirusTotal |

---

## 📋 Requisiti

- Python **3.10** o superiore
- Account **Gmail**
- Progetto su **Google Cloud Console** con Gmail API abilitata (vedi setup)

---

## ⚙️ Setup Google Cloud Console

Questo passaggio va fatto **una volta sola** su qualsiasi piattaforma.

### 1. Crea il progetto

1. Vai su [console.cloud.google.com]
2. **Seleziona progetto** → **Nuovo progetto** → nome: `munimen-soc` → **Crea**

### 2. Abilita Gmail API

1. Menu laterale → **API e servizi** → **Libreria**
2. Cerca **Gmail API** → **Abilita**

### 3. Crea credenziali OAuth2

1. Menu laterale → **API e servizi** → **Credenziali**
2. **Crea credenziali** → **ID client OAuth 2.0**
3. Tipo applicazione: **App desktop**
4. Nome: `email-soc-analyzer` → **Crea**
5. Scarica il file JSON → rinominalo **`credentials.json`**

### 4. Configura la schermata di consenso

1. Menu laterale → **Schermata consenso OAuth** → Tipo: **Esterno** → **Crea**
2. Inserisci nome app e email → **Salva e continua**
3. Sezione **Utenti di test** → **Aggiungi utenti** → inserisci la tua email Gmail

### 5. Posiziona il file

Copia `credentials.json` nella stessa cartella dello script:

```
email-soc-analyzer/
├── email_soc_analyzer.py
└── credentials.json        ← qui
```

---

## 🚀 Installazione

### 🍎 macOS (M1 / M2 / M4 e Intel)

```bash
# Verifica Python
python3 --version

# Clona il repository
git clone https://github.com/munimen/email-soc-analyzer.git
cd email-soc-analyzer

# (Consigliato) Crea un ambiente virtuale
python3 -m venv venv
source venv/bin/activate

# Installa le dipendenze
pip install google-auth-oauthlib google-auth-httplib2 google-api-python-client

# Copia credentials.json nella cartella
# Avvia
python3 email_soc_analyzer.py
```

> **Nota Mac:** Se usi Homebrew e hai più versioni di Python, usa esplicitamente `python3.11` o `python3.12` per evitare conflitti.

---

### 🐧 Linux (Kali, Ubuntu, Debian)

```bash
# Verifica Python
python3 --version

# Installa pip se mancante
sudo apt update && sudo apt install python3-pip -y

# Clona il repository
git clone https://github.com/munimen/email-soc-analyzer.git
cd email-soc-analyzer

# (Consigliato) Crea un ambiente virtuale
python3 -m venv venv
source venv/bin/activate

# Installa le dipendenze
pip install google-auth-oauthlib google-auth-httplib2 google-api-python-client

# Kali Linux — se usi pip globale aggiungi il flag
# pip install google-auth-oauthlib google-auth-httplib2 google-api-python-client --break-system-packages

# Copia credentials.json nella cartella
# Avvia
python3 email_soc_analyzer.py
```

> **Nota Kali:** Il primo avvio apre il browser per il login Google. Se usi Kali senza GUI (headless), il flusso OAuth2 richiede un browser — usa la versione desktop o configura un browser remoto.

---

### 🪟 Windows 11

```powershell
# Verifica Python (PowerShell o Terminale)
python --version

# Se non è installato: https://python.org
# Durante l'installazione spunta "Add Python to PATH"

# Clona il repository
git clone https://github.com/munimen/email-soc-analyzer.git
cd email-soc-analyzer

# (Consigliato) Crea un ambiente virtuale
python -m venv venv
venv\Scripts\activate

# Installa le dipendenze
pip install google-auth-oauthlib google-auth-httplib2 google-api-python-client

# Copia credentials.json nella cartella
# Avvia
python email_soc_analyzer.py
```

> **Nota Windows:** Al primo avvio si apre automaticamente Edge o Chrome con la pagina di login Google. Se vedi "app non verificata", clicca **Avanzate** → **Vai a email-soc-analyzer** → **Consenti**.

---

## ▶️ Utilizzo

```bash
python3 email_soc_analyzer.py
```

Lo script chiede due parametri:

```
Quante email analizzare? [default: 5]: 5
Solo non lette? [s/N]: N
```

**Primo avvio** — si apre il browser per l'autenticazione Google. Dopo aver cliccato "Consenti", torna al terminale. Il token viene salvato in `token.json` e rinnovato automaticamente negli avvii successivi.

---

## 📊 Esempio di output

```
╔══════════════════════════════════════════════════════╗
║          MUNIMEN - Email SOC Analyzer v2.0           ║
║   OAuth2 + Gmail API  |  IOC  |  Phishing  |  Header  ║
╚══════════════════════════════════════════════════════╝

══════════════════════════════════════════════════════════
  EMAIL ID: 18f4a2c91b3d
══════════════════════════════════════════════════════════

── ANALISI HEADER ──────────────────────────────────────
  [i] From:      noreply@banca-example.com
  [i] Reply-To:  attacker@gmail.com
  [⚠ WARN ] Reply-To diverso da From → possibile spoofing

── SPF / DKIM / DMARC ──────────────────────────────────
  [✔ OK   ] SPF: pass
  [✘ ALERT] DKIM: fail
  [⚠ WARN ] DMARC: non trovato

── ESTRAZIONE IOC ───────────────────────────────────────
  [✘ ALERT] URL shortener sospetto: http://bit.ly/xy93k
  [⚠ WARN ] URL: http://login-banca.support/accedi

── RILEVAMENTO PHISHING ─────────────────────────────────
  [✘ ALERT] Keyword: "conferma le tue credenziali", "urgente"

  Phishing Risk Score: 24  →  Livello: ALTO

── ANALISI ALLEGATI ─────────────────────────────────────
  [✘ ALERT] Allegato: documento.docm  (48392 bytes)
  [i]   SHA256: 3a7f9c2b1e4d...
  [i]   → https://www.virustotal.com/gui/file/3a7f9c2b1e4d...
  [✘ ALERT] Estensione AD ALTO RISCHIO: .docm
```

---

## 📁 Struttura del progetto

```
email-soc-analyzer/
├── email_soc_analyzer.py   # Script principale
├── credentials.json        # Credenziali OAuth2 Google (NON committare)
├── token.json              # Token generato automaticamente (NON committare)
├── README.md
└── .gitignore
```

---

## 🔒 Sicurezza

> ⚠️ **Non committare mai** `credentials.json` e `token.json` su Git.

Aggiungi questo `.gitignore` al progetto:

```gitignore
credentials.json
token.json
soc_report_*.json
venv/
__pycache__/
*.pyc
```

Lo scope OAuth2 usato è **`gmail.readonly`** — il tool può solo leggere, mai modificare, cancellare o inviare email.

---

## 🗺️ Roadmap

- [ ] Integrazione API VirusTotal per enrichment automatico degli IOC
- [ ] Integrazione API AbuseIPDB per reputazione IP
- [ ] Export report HTML / PDF professionale
- [ ] Integrazione Wazuh via syslog
- [ ] Dashboard web locale con Flask
- [ ] Supporto Microsoft Graph API per Outlook

---

## 📄 Licenza

MIT License — libero per uso personale e commerciale.

---

## 👤 Autore

**Alessandro Passero** — 
Sicurezza informatica per le PMI italiane.

> *munimen [ lat. ] — difesa, protezione, baluardo*
