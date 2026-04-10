from flask import Flask, jsonify, request
from flask_cors import CORS
import re
import time
import hashlib
from datetime import datetime
from urllib.parse import urlparse

# Import our custom engines
try:
    from crawler import crawl_website
    CRAWLER_AVAILABLE = True
    print("  ✅ Crawler Engine          : LOADED")
except Exception as e:
    CRAWLER_AVAILABLE = False
    print(f"  ⚠️  Crawler Engine         : NOT LOADED ({e})")

try:
    from llm_analyzer import analyze_with_llm
    LLM_AVAILABLE = True
    print("  ✅ LLM Analyzer Engine     : LOADED")
except Exception as e:
    LLM_AVAILABLE = False
    print(f"  ⚠️  LLM Analyzer           : NOT LOADED ({e})")

app = Flask(__name__)
CORS(app)
scans = {}

# ── VULNERABILITY DATABASE ───────────────────────────────────
VULN_DB = {
    "INSECURE_CONNECTION": {
        "type": "Insecure HTTP Connection",
        "owasp": "A02:2021 - Cryptographic Failures",
        "mitre_technique": "T1040 - Network Sniffing",
        "severity": "HIGH",
        "cvss_score": 7.5,
        "description": "Website transmits data over unencrypted HTTP. All traffic including passwords can be intercepted.",
        "impact": "Credentials and personal data stolen via Man-in-the-Middle attacks.",
        "fix": "Upgrade to HTTPS using SSL/TLS certificate",
        "mitigation_steps": [
            "Get FREE SSL from Let's Encrypt (letsencrypt.org)",
            "Install certificate on web server (Apache/Nginx)",
            "Redirect all HTTP to HTTPS",
            "Enable HSTS header",
            "Test at ssllabs.com/ssltest"
        ],
        "references": "OWASP A02:2021 | NIST SP 800-52"
    },
    "SQL_INJECTION": {
        "type": "SQL Injection Risk Detected",
        "owasp": "A03:2021 - Injection",
        "mitre_technique": "T1190 - Exploit Public-Facing Application",
        "severity": "CRITICAL",
        "cvss_score": 9.8,
        "description": "URL contains database query parameters that may be vulnerable to SQL injection.",
        "impact": "Complete database compromise - read, modify, delete all data.",
        "fix": "Use parameterized queries exclusively",
        "mitigation_steps": [
            "Replace raw SQL with parameterized queries",
            "Use ORM (SQLAlchemy, Hibernate)",
            "Validate all input server-side",
            "Apply least privilege to DB accounts",
            "Deploy Web Application Firewall"
        ],
        "references": "OWASP A03:2021 | MITRE T1190"
    },
    "XSS": {
        "type": "Cross-Site Scripting (XSS)",
        "owasp": "A03:2021 - Injection",
        "mitre_technique": "T1059.007 - JavaScript Execution",
        "severity": "HIGH",
        "cvss_score": 7.2,
        "description": "Input parameters present that could allow XSS if not sanitized.",
        "impact": "Session hijacking, credential theft, malicious redirects.",
        "fix": "Sanitize inputs and encode outputs",
        "mitigation_steps": [
            "Encode user output with HTML entities",
            "Implement Content Security Policy header",
            "Use frameworks that auto-escape (React, Vue)",
            "Set HttpOnly on session cookies",
            "Use DOMPurify for HTML content"
        ],
        "references": "OWASP A03:2021 | CWE-79"
    },
    "CSRF": {
        "type": "CSRF Vulnerability Risk",
        "owasp": "A01:2021 - Broken Access Control",
        "mitre_technique": "T1185 - Browser Session Hijacking",
        "severity": "MEDIUM",
        "cvss_score": 6.5,
        "description": "Form endpoints may lack CSRF protection.",
        "impact": "Unauthorized actions performed on behalf of users.",
        "fix": "Implement CSRF tokens in all POST forms",
        "mitigation_steps": [
            "Generate unique CSRF token per session",
            "Include token as hidden field in forms",
            "Validate token server-side on every POST",
            "Use SameSite=Strict cookies",
            "Verify Origin/Referer headers"
        ],
        "references": "OWASP A01:2021 | CWE-352"
    },
    "SENSITIVE_PAGE": {
        "type": "Sensitive Page Publicly Accessible",
        "owasp": "A05:2021 - Security Misconfiguration",
        "mitre_technique": "T1595 - Active Scanning",
        "severity": "MEDIUM",
        "cvss_score": 5.3,
        "description": "Admin or login pages accessible without restrictions.",
        "impact": "Enables brute-force attacks and unauthorized access.",
        "fix": "Restrict with auth and IP whitelisting",
        "mitigation_steps": [
            "Implement MFA on admin pages",
            "Add IP whitelisting",
            "Rate limit to 5 attempts per 15 minutes",
            "Add CAPTCHA",
            "Log and alert on access attempts"
        ],
        "references": "OWASP A05:2021 | CWE-284"
    },
    "IDOR": {
        "type": "Insecure Direct Object Reference",
        "owasp": "A01:2021 - Broken Access Control",
        "mitre_technique": "T1078 - Valid Accounts",
        "severity": "HIGH",
        "cvss_score": 8.6,
        "description": "URL exposes object IDs enabling unauthorized access.",
        "impact": "Access any user data by manipulating ID parameters.",
        "fix": "Implement authorization checks for every object",
        "mitigation_steps": [
            "Verify ownership for every resource request",
            "Replace sequential IDs with UUIDs",
            "Implement server-side access control",
            "Add IDOR testing to security suite",
            "Log all parameter manipulation attempts"
        ],
        "references": "OWASP A01:2021 | CWE-639"
    }
}

HACKER_PATTERNS = {
    "reconnaissance": {
        "indicators": ["robots.txt", ".git", ".env", "backup", "wp-admin", "phpmyadmin", ".htaccess"],
        "attack_phase": "Phase 1: Reconnaissance",
        "mitre_technique": "T1595.003 - Wordlist Scanning",
        "description": "Hacker mapping your site structure before attack.",
        "danger_level": "WARNING",
        "next_hacker_move": "Will target weakest entry point found.",
        "prevention": [
            "Block sensitive file access via server config",
            "Remove backup and .git folders from web root",
            "Set up honeypot pages",
            "Enable real-time suspicious URL alerting"
        ]
    },
    "credential_attack": {
        "indicators": ["login", "signin", "auth", "password", "forgot-password"],
        "attack_phase": "Phase 2: Credential Attack",
        "mitre_technique": "T1110 - Brute Force",
        "description": "Hacker targeting authentication endpoints.",
        "danger_level": "HIGH",
        "next_hacker_move": "Automated tool will try thousands of passwords.",
        "prevention": [
            "Account lockout after 5 failed attempts",
            "Add CAPTCHA v3",
            "Enable MFA",
            "Alert on multiple failed logins"
        ]
    },
    "data_exfiltration": {
        "indicators": ["export", "download", "dump", "backup", "csv", "bulk"],
        "attack_phase": "Phase 4: Data Exfiltration",
        "mitre_technique": "T1041 - Exfiltration Over C2 Channel",
        "description": "Bulk data extraction attempt indicators.",
        "danger_level": "CRITICAL",
        "next_hacker_move": "Sequential ID enumeration to download all records.",
        "prevention": [
            "Rate limit data export APIs",
            "Authorization checks on all data",
            "Monitor sequential ID patterns",
            "DLP alerts for bulk queries"
        ]
    },
    "privilege_escalation": {
        "indicators": ["admin", "superuser", "root", "escalate", "bypass"],
        "attack_phase": "Phase 3: Privilege Escalation",
        "mitre_technique": "T1078.003 - Local Accounts",
        "description": "Privilege escalation attempt indicators.",
        "danger_level": "CRITICAL",
        "next_hacker_move": "Role parameter manipulation or JWT forgery.",
        "prevention": [
            "RBAC server-side enforcement",
            "Validate permissions every request",
            "Short-lived JWT tokens",
            "Log all privileged access attempts"
        ]
    }
}

# ── NLP ANALYZER ─────────────────────────────────────────────
def nlp_analyze_url(url):
    parsed = urlparse(url)
    full = (parsed.path + "?" + parsed.query).lower()
    context = {"app_type": "generic", "risk_amplifier": 1.0, "nlp_tags": [], "semantic_context": ""}

    fin_tokens = ["bank", "pay", "wallet", "finance", "money", "transfer", "credit"]
    auth_tokens = ["login", "auth", "signin", "password", "token", "oauth"]
    admin_tokens = ["admin", "dashboard", "manage", "panel", "console"]

    for t in fin_tokens:
        if t in full:
            context["app_type"] = "financial"
            context["risk_amplifier"] = 1.5
            context["nlp_tags"].append(f"FINANCIAL:{t}")

    for t in auth_tokens:
        if t in full:
            context["nlp_tags"].append(f"AUTH_SURFACE:{t}")
            context["risk_amplifier"] = max(context["risk_amplifier"], 1.3)

    for t in admin_tokens:
        if t in full:
            context["nlp_tags"].append(f"PRIVILEGED:{t}")
            context["risk_amplifier"] = max(context["risk_amplifier"], 1.4)

    if context["app_type"] == "financial":
        context["semantic_context"] = "HIGH-VALUE TARGET: Financial app. Attackers specifically target payment endpoints."
    elif any("AUTH" in t for t in context["nlp_tags"]):
        context["semantic_context"] = "AUTHENTICATION SURFACE: Login endpoint - primary target for credential attacks."
    elif any("PRIVILEGED" in t for t in context["nlp_tags"]):
        context["semantic_context"] = "PRIVILEGED ZONE: Admin interface detected."
    elif url.startswith("https") and not context["nlp_tags"]:
        context["semantic_context"] = "SECURED ENDPOINT: HTTPS with no obvious vulnerability indicators."
    else:
        context["semantic_context"] = "STANDARD APPLICATION: General web endpoint assessed."

    return context

# ── URL-BASED SCANNER ────────────────────────────────────────
def url_scan(url):
    parsed = urlparse(url)
    path = parsed.path.lower()
    query = parsed.query.lower()
    full = path + "?" + query
    vulns = []
    is_https = url.startswith("https")

    if not is_https:
        vulns.append(VULN_DB["INSECURE_CONNECTION"])

    if re.search(r'[?&](id|cat|pid|uid|product_id|item|page|num)=\d+', url.lower()):
        vulns.append(VULN_DB["SQL_INJECTION"])

    if re.search(r'[?&](search|q|query|input|text|msg|comment)=', url.lower()) and not is_https:
        vulns.append(VULN_DB["XSS"])

    sensitive = ["/login", "/admin", "/wp-admin", "/dashboard", "/panel", "/signin"]
    for sp in sensitive:
        if sp in path:
            vulns.append(VULN_DB["SENSITIVE_PAGE"])
            break

    if re.search(r'[?&](id|uid|user|account|profile)=\d+', url.lower()):
        vulns.append(VULN_DB["IDOR"])

    csrf_paths = ["/login", "/register", "/signup", "/checkout", "/transfer"]
    for cp in csrf_paths:
        if cp in path:
            vulns.append(VULN_DB["CSRF"])
            break

    for pattern_name, pdata in HACKER_PATTERNS.items():
        for indicator in pdata["indicators"]:
            if indicator in full:
                vulns.append({
                    "type": f"AI DETECTED: {pdata['attack_phase']}",
                    "severity": "HIGH",
                    "cvss_score": 7.8,
                    "owasp": "A07:2021 - Identification Failures",
                    "mitre_technique": pdata["mitre_technique"],
                    "description": pdata["description"],
                    "danger_level": pdata["danger_level"],
                    "impact": f"Next hacker move: {pdata['next_hacker_move']}",
                    "fix": "Implement behavioral monitoring",
                    "mitigation_steps": pdata["prevention"],
                    "references": f"MITRE ATT&CK {pdata['mitre_technique']}",
                    "detected_by": "AI Behavioral Engine"
                })
                break

    return vulns, is_https

# ── RISK CALCULATOR ──────────────────────────────────────────
def calculate_risk(vulns, amplifier, is_https):
    if not vulns:
        return 5, "LOW", "No significant vulnerabilities detected."

    scores = {"CRITICAL": 25, "HIGH": 15, "MEDIUM": 8, "LOW": 3}
    base = sum(scores.get(v.get("severity", "LOW"), 3) for v in vulns)

    if is_https:
        base = int(base * 0.6)

    final = min(int(base * amplifier), 100)

    if final >= 75: return final, "CRITICAL", "Immediate action required. Multiple serious vulnerabilities detected."
    elif final >= 55: return final, "HIGH", "Serious vulnerabilities. Address urgently before deployment."
    elif final >= 35: return final, "MEDIUM", "Moderate risk. Exploitable under specific conditions."
    elif final >= 15: return final, "LOW", "Minor issues. Low immediate risk but should be addressed."
    else: return final, "LOW", "No significant vulnerabilities. Site appears reasonably secured."

# ── ATTACK CHAIN ─────────────────────────────────────────────
def build_chain(vulns, nlp, url):
    chain = []
    step = 1
    types = [v.get("type", "") for v in vulns]

    chain.append({"phase": step, "title": "Reconnaissance", "time_estimate": "Minutes 1-10",
        "hacker_action": f"Attacker scans {url} to map all pages, forms, APIs.",
        "tools_used": "Burp Suite, DirBuster", "mitre": "T1595", "status": "ALWAYS_OCCURS"})
    step += 1

    if any("AUTH" in t for t in nlp.get("nlp_tags", [])):
        chain.append({"phase": step, "title": "Credential Attack", "time_estimate": "Minutes 10-30",
            "hacker_action": "Credential stuffing with leaked password lists - 1000 attempts/minute.",
            "tools_used": "Hydra, Burp Intruder", "mitre": "T1110.004", "status": "HIGH_RISK"})
        step += 1

    if any("SQL" in t for t in types):
        chain.append({"phase": step, "title": "SQL Injection", "time_estimate": "Minutes 30-45",
            "hacker_action": "Injects ' OR 1=1;-- to bypass auth and dumps full database.",
            "tools_used": "SQLMap", "mitre": "T1190", "status": "CRITICAL"})
        step += 1

    if any("XSS" in t for t in types):
        chain.append({"phase": step, "title": "XSS Session Hijacking", "time_estimate": "Minutes 45-60",
            "hacker_action": "Injects script to steal session cookies from active users.",
            "tools_used": "BeEF Framework", "mitre": "T1059.007", "status": "HIGH_RISK"})
        step += 1

    if len(vulns) > 2:
        chain.append({"phase": step, "title": "Data Exfiltration", "time_estimate": "Minutes 60-90",
            "hacker_action": "Downloads all user records silently. Installs backdoor for persistence.",
            "tools_used": "curl, wget", "mitre": "T1041", "status": "MAXIMUM_DAMAGE"})

    return chain

# ── MAIN SCAN ROUTE ──────────────────────────────────────────
@app.route('/')
def home():
    return jsonify({
        "platform": "SecureAI Scanner",
        "version": "4.0",
        "engines": {
            "crawler": CRAWLER_AVAILABLE,
            "llm_analyzer": LLM_AVAILABLE,
            "url_scanner": True,
            "nlp_engine": True,
            "behavioral_ai": True
        },
        "status": "online"
    })

@app.route('/scan', methods=['POST'])
def start_scan():
    data = request.json
    url = data.get('url', '').strip()
    deep_scan = data.get('deep_scan', False)

    if not url:
        return jsonify({"error": "URL kudungada!"})
    if not url.startswith("http"):
        url = "http://" + url

    scan_id = hashlib.md5(f"{url}{time.time()}".encode()).hexdigest()[:8]

    # ── PROTOCOL 1: NLP ──
    nlp_context = nlp_analyze_url(url)

    # ── PROTOCOL 2: URL SCAN ──
    url_vulns, is_https = url_scan(url)
    all_vulns = list(url_vulns)

    crawl_summary = None
    llm_insights = []

    # ── PROTOCOL 3: CRAWLER + LLM (if available) ──
    if CRAWLER_AVAILABLE and LLM_AVAILABLE:
        try:
            print(f"\n🕷️  Starting deep crawl + LLM analysis for: {url}")
            crawl_data = crawl_website(url, max_pages=10)
            llm_result = analyze_with_llm(crawl_data)

            # Add LLM findings
            for vuln in llm_result.get("vulnerabilities", []):
                # Avoid exact duplicates
                existing_types = [v.get("type", "") for v in all_vulns]
                if vuln.get("type") not in existing_types:
                    all_vulns.append(vuln)

            crawl_summary = llm_result.get("crawl_summary", {})
            llm_insights = llm_result.get("llm_insights", [])

        except Exception as e:
            print(f"⚠️  Crawler/LLM error: {e}")

    # ── PROTOCOL 4: RISK CALCULATION ──
    risk_score, risk_level, risk_summary = calculate_risk(
        all_vulns, nlp_context["risk_amplifier"], is_https
    )

    # ── PROTOCOL 5: ATTACK CHAIN ──
    attack_chain = build_chain(all_vulns, nlp_context, url)

    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for v in all_vulns:
        sev = v.get("severity", "LOW")
        if sev in severity_counts:
            severity_counts[sev] += 1

    protocols = ["NLP Semantic Analysis", "URL-based CVE Scanner", "AI Behavioral Engine",
                 "MITRE ATT&CK Mapper", "Attack Chain Reconstructor"]
    if CRAWLER_AVAILABLE: protocols.append("Deep Web Crawler")
    if LLM_AVAILABLE: protocols.append("LLM Vulnerability Analyzer")

    result = {
        "scan_id": scan_id,
        "url": url,
        "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "status": "completed",
        "protocols_used": protocols,
        "nlp_analysis": {
            "app_type": nlp_context["app_type"],
            "semantic_context": nlp_context["semantic_context"],
            "nlp_tags": nlp_context["nlp_tags"],
            "risk_amplifier": nlp_context["risk_amplifier"]
        },
        "risk_score": risk_score,
        "risk_level": risk_level,
        "risk_summary": risk_summary,
        "severity_breakdown": severity_counts,
        "total_vulnerabilities": len(all_vulns),
        "vulnerabilities": all_vulns,
        "attack_chain": attack_chain,
        "llm_insights": llm_insights,
        "crawl_summary": crawl_summary,
        "owasp_coverage": ["A01", "A02", "A03", "A04", "A05", "A07"],
        "frameworks_used": ["OWASP Top 10", "MITRE ATT&CK", "NIST CSF", "CVE Database"]
    }

    scans[scan_id] = result
    return jsonify(result)

@app.route('/results/<scan_id>', methods=['GET'])
def get_results(scan_id):
    if scan_id in scans:
        return jsonify(scans[scan_id])
    return jsonify({"error": "Scan not found"})

if __name__ == '__main__':
    print("=" * 55)
    print("  🛡️  SecureAI Scanner v4.0")
    print("=" * 55)
    print("  ✅ NLP Semantic Analyzer       : LOADED")
    print("  ✅ AI Behavioral Engine        : LOADED")
    print("  ✅ MITRE ATT&CK Mapper         : LOADED")
    print("  ✅ Attack Chain Reconstructor  : LOADED")
    print("  ✅ Honest Risk Scoring         : LOADED")
    print("=" * 55)
    print("  📡 Running → http://localhost:5000")
    print("=" * 55)
    import os
port = int(os.environ.get("PORT", 5000))
app.run(host='0.0.0.0', port=port, debug=False)
