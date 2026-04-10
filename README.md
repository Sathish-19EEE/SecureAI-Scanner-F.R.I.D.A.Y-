# 🛡️ SecureAI — Intelligent Web Vulnerability Detection Platform

> A web-based security platform that combines traditional CVE scanning, NLP-based context analysis, AI behavioral detection, and a live web crawler linked to an LLM analyzer — to detect every possible vulnerability in modern web applications without fail.

![License](https://img.shields.io/badge/license-MIT-blue)
![Stack](https://img.shields.io/badge/stack-Flask%20%7C%20HTML%2FJS-green)
![Status](https://img.shields.io/badge/status-Active-brightgreen)

---

## 📌 Problem Statement

Modern web applications built on SPAs, REST APIs, and microservices face security threats that existing tools like Burp Suite, OWASP ZAP, and Nikto cannot fully address. These tools rely on static checklists and only detect known vulnerability patterns — they cannot understand application behavior, detect business logic flaws, or analyze what happens inside forms, cookies, and HTTP headers at the application level. There is no step-by-step remediation guidance for developers, and false positives waste significant time. SecureAI fills this gap by combining traditional scanning with a live crawler, an LLM analyzer, NLP semantic understanding, and AI behavioral pattern detection — producing honest risk scores and actionable mitigation guides for every vulnerability found.

---

## 🚀 Features

| Feature | Description |
|---|---|
| 🕷️ Live Web Crawler | Visits every page of the target website and maps all pages, forms, inputs, cookies, and API endpoints |
| 🤖 LLM Vulnerability Analyzer | Analyzes crawled data intelligently — detects CSRF missing in forms, insecure cookies, server version disclosure, file upload risks |
| 🧠 NLP Semantic Engine | Tokenizes and classifies the target URL to understand application context (financial, auth, admin) and amplifies risk accordingly |
| 👁️ AI Behavioral Engine | Detects hidden hacker patterns (reconnaissance, credential attack, privilege escalation, data exfiltration) using MITRE ATT&CK techniques |
| 💀 Attack Chain Reconstructor | Rebuilds the exact step-by-step attack path a hacker would follow — with time estimates and tools used per phase |
| 📊 Honest Risk Scoring | Calculates real risk score based on actual findings — HTTPS sites score low, vulnerable sites score high. No bias |
| 🗺️ MITRE ATT&CK Mapping | Every vulnerability mapped to its MITRE ATT&CK technique code (T1190, T1110, T1040 etc.) |
| ✅ OWASP Top 10 Coverage | Covers A01 through A07 — Broken Access Control, Cryptographic Failures, Injection, Insecure Design, Misconfiguration, Identification Failures |
| 🔢 CVSS Scoring | Industry-standard Common Vulnerability Scoring System score (0–10) for every vulnerability |
| 🧭 Step-by-Step Mitigation | Each vulnerability comes with a numbered fix guide developers can follow immediately |
| 📄 Report Download | One-click downloadable security report with all findings, CVSS scores, MITRE codes, and fix steps |
| 📡 Real-Time Dashboard | Live scan progress showing each protocol running — NLP, Crawler, LLM, MITRE, Attack Chain |

---

## 🏗️ Tech Stack

### Frontend
- 🌐 HTML5 — Page structure
- 🎨 CSS3 (Custom Dark Theme) — Professional security tool aesthetic with severity color coding
- ⚡ Vanilla JavaScript — Real-time scan animation, API calls, dynamic result rendering
- 🅱️ Bootstrap 5 — Responsive layout and UI components
- 🔣 Font Awesome 6 — Security-relevant iconography

### Backend
- 🐍 Python 3 — Core language
- 🌶️ Flask — Lightweight REST API server
- 🔗 Flask-CORS — Cross-origin request handling between frontend and backend
- 🕷️ Requests + BeautifulSoup4 — Web crawler (HTTP requests + HTML parsing)
- 🔍 Custom NLP Engine — URL tokenizer and semantic context classifier (built from scratch)
- 🤖 Custom LLM Analyzer — Rule-reasoning engine that analyzes crawl data for deep vulnerability detection
- 🧠 Custom AI Behavioral Engine — Pattern-matching engine using MITRE ATT&CK behavioral indicators
- 📐 Hashlib + Datetime — Scan ID generation and timestamping

---

## 📂 Project Structure

```
security-platform/
│
├── backend/
│   ├── app.py                  # Flask server — main entry point, all scan routes, NLP + AI engines
│   ├── crawler.py              # Web crawler — visits pages, extracts forms, inputs, cookies, headers
│   └── llm_analyzer.py         # LLM analyzer — analyzes crawl data and detects deep vulnerabilities
│
├── frontend/
│   └── index.html              # Complete dashboard UI — scan input, protocol progress, results, report
│
└── README.md
```

---

## ⚙️ Installation & Setup

### Prerequisites
- Python 3.9+
- pip

### 1. Download the Project

Download all files and place them in this structure:
```
security-platform/
├── backend/   → app.py, crawler.py, llm_analyzer.py
└── frontend/  → index.html
```

### 2. Install Dependencies

Open terminal in the `backend` folder and run:

```bash
pip install flask flask-cors requests beautifulsoup4
```

### 3. Start the Backend Server

```bash
cd backend
python app.py
```

You should see:
```
✅ Crawler Engine          : LOADED
✅ LLM Analyzer Engine     : LOADED
✅ NLP Semantic Analyzer   : LOADED
✅ AI Behavioral Engine    : LOADED
📡 Running → http://localhost:5000
```

### 4. Open the Frontend

Open `frontend/index.html` directly in any browser (Chrome/Edge).

### 5. Run a Scan

Enter a target URL and click **SCAN NOW**. Example:
```
http://testphp.vulnweb.com/login.php
```

---

## 🧠 How It Works

### Full Scan Flow

1. User enters a target URL in the dashboard and clicks Scan
2. Frontend sends a POST request to `http://localhost:5000/scan` with the URL
3. **Protocol 1 — NLP Engine** (`app.py`): Tokenizes the URL, classifies tokens as FINANCIAL, AUTH_SURFACE, or PRIVILEGED, sets a risk amplifier (1.0–1.8x), and generates a semantic context string
4. **Protocol 2 — URL Scanner** (`app.py`): Checks URL properties — HTTP vs HTTPS, SQL parameters, sensitive path keywords, IDOR patterns, CSRF surfaces — and maps findings to OWASP categories and MITRE ATT&CK codes
5. **Protocol 3 — Crawler** (`crawler.py`): Visits the actual website, follows all internal links (up to 15 pages), extracts every form with its inputs and method, collects all cookies with their security flags, reads HTTP response headers, detects server technology stack
6. **Protocol 4 — LLM Analyzer** (`llm_analyzer.py`): Receives the full crawl data and reasons about it — flags POST forms missing CSRF tokens, password fields transmitted over HTTP, cookies missing HttpOnly/Secure/SameSite flags, missing security headers (CSP, HSTS, X-Frame-Options), server version disclosure, file upload endpoints, admin panels exposed
7. **Protocol 5 — AI Behavioral Engine** (`app.py`): Checks URL and page patterns against MITRE ATT&CK behavioral indicators to detect reconnaissance, credential attacks, data exfiltration, and privilege escalation patterns
8. **Protocol 6 — Risk Calculator** (`app.py`): Aggregates all findings, applies HTTPS reduction factor (×0.6 for HTTPS sites), applies NLP risk amplifier, caps at 100 — producing an honest, unbiased risk score
9. **Protocol 7 — Attack Chain Reconstructor** (`app.py`): Builds a step-by-step hacker attack timeline based on detected vulnerabilities — phases include Reconnaissance, Credential Attack, SQL Injection, XSS Hijacking, and Data Exfiltration
10. Final JSON result sent back to frontend, rendered in real-time dashboard with all vulnerability cards, CVSS scores, MITRE codes, mitigation steps, and attack chain

---

## 📈 Scalability

- **Concurrent scans**: Flask can be replaced with `gunicorn` + multiple workers to handle parallel scan requests. Each scan is stateless and identified by a unique hash ID
- **Crawler throughput**: Crawler uses configurable `max_pages` limit. Can be parallelized using Python `asyncio` or `concurrent.futures` for faster large-site scanning
- **Storage**: Currently in-memory dictionary. Can be migrated to PostgreSQL or MongoDB with minimal changes — scan result structure is already JSON-serializable
- **Deployment**: Backend can be containerized with Docker and deployed on AWS EC2, Azure, or GCP. Frontend is a static file servable via any CDN (Netlify, Cloudflare Pages)
- **LLM scaling**: The LLM analyzer currently uses rule-reasoning. Can be upgraded to call OpenAI API or a local LLaMA model for deeper contextual analysis without changing the interface

---

## 💡 Feasibility

SecureAI is built entirely on stable, widely-used open source libraries — Flask, Requests, and BeautifulSoup4 — all of which are production-grade and actively maintained. No specialized infrastructure is required: the backend runs on any machine with Python 3.9+, and the frontend is a single HTML file. The crawler and LLM analyzer are custom-built Python modules with no external API dependencies, meaning the tool works fully offline. Taking this to production requires adding a database, authentication layer, and deploying the Flask server behind Nginx — all standard steps with existing tooling.

---

## 🌟 Novelty

Most existing scanners (Burp Suite, OWASP ZAP, Nikto) operate on URL patterns and known CVE signatures — they never visit the actual website or look inside its HTML. SecureAI's core novelty is the **Crawler-LLM pipeline**: the crawler visits every page and extracts raw application data (forms, cookies, headers), and the LLM analyzer reasons about that data to find vulnerabilities that are invisible to URL-based tools — such as a POST form missing a CSRF token, a session cookie lacking HttpOnly, or a server revealing its exact version. Combined with NLP-based risk amplification and MITRE ATT&CK behavioral detection, SecureAI operates more like a human security expert than a pattern-matching rule engine.

---

## 🔧 Feature Depth

- **Crawler** handles timeouts gracefully, skips binary files (images, CSS, JS), detects technology stack from headers and script sources, and collects cookie security attributes per cookie individually
- **LLM Analyzer** checks each form independently — a page with three forms gets three separate CSRF checks. Cookie analysis is per-cookie, not per-page
- **Risk scoring** applies a 0.6 reduction multiplier for HTTPS sites, preventing safe sites from receiving unfairly high scores — a problem common in existing tools
- **Attack Chain** is dynamically generated based on what was actually found — if no SQL injection is detected, that phase does not appear in the chain
- **MITRE ATT&CK mapping** covers T1040, T1059.007, T1078, T1110, T1185, T1190, T1539, T1592, T1595 — nine distinct techniques across reconnaissance, initial access, credential access, and exfiltration tactics
- **Report** includes scan ID, timestamp, all vulnerability details with CVSS scores, full mitigation steps, MITRE codes, and framework coverage — ready to share with development teams

---

## ⚠️ Ethical Use & Disclaimer

SecureAI is strictly for **educational, research, and authorized security testing only**.

Do **NOT** use this tool to scan any website, server, or application without **explicit written permission** from the owner. Unauthorized scanning may violate cybersecurity laws including the Information Technology Act (India), Computer Fraud and Abuse Act (USA), and equivalent legislation in your jurisdiction.

All demo scans in this project use intentionally vulnerable test sites (testphp.vulnweb.com, demo.testfire.net) that are publicly provided for security research purposes.

Use responsibly, ethically, and legally.

---

## 📜 License

Licensed under the [MIT License](LICENSE).

---

## 🤝 Author

**Team — Flarenet Company**
Built at OreHack Hackathon 2026
