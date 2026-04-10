import json
import re

# ============================================================
# SECUREAI LLM ANALYZER ENGINE
# Takes crawler data → Sends to AI → Gets vulnerabilities
# Works WITHOUT OpenAI API key using rule-based LLM simulation
# ============================================================

def analyze_with_llm(crawl_data):
    """
    LLM Analysis Engine:
    1. Takes all crawled data
    2. Analyzes forms, inputs, headers, cookies
    3. Returns detailed vulnerability findings
    """

    findings = []
    llm_insights = []

    print("🤖 LLM Analyzer Starting...")
    print("   Analyzing crawled data with AI engine...")

    # ── LLM ANALYSIS 1: SECURITY HEADERS ──
    headers_info = crawl_data.get("headers_info", {})
    missing = headers_info.get("missing", [])

    if missing:
        header_details = {
            "Strict-Transport-Security": {
                "risk": "Browsers won't enforce HTTPS - downgrade attacks possible",
                "fix": "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains"
            },
            "Content-Security-Policy": {
                "risk": "No XSS protection policy - scripts from any source can execute",
                "fix": "Add: Content-Security-Policy: default-src 'self'; script-src 'self'"
            },
            "X-Frame-Options": {
                "risk": "Site can be embedded in iframes - clickjacking attacks possible",
                "fix": "Add: X-Frame-Options: DENY or SAMEORIGIN"
            },
            "X-Content-Type-Options": {
                "risk": "MIME type sniffing attacks possible",
                "fix": "Add: X-Content-Type-Options: nosniff"
            },
            "X-XSS-Protection": {
                "risk": "Browser XSS filter not explicitly enabled",
                "fix": "Add: X-XSS-Protection: 1; mode=block"
            },
            "Referrer-Policy": {
                "risk": "Referrer information leaked to third parties",
                "fix": "Add: Referrer-Policy: strict-origin-when-cross-origin"
            }
        }

        for header in missing:
            detail = header_details.get(header, {})
            findings.append({
                "type": f"Missing Security Header: {header}",
                "severity": "MEDIUM" if header in ["Content-Security-Policy", "Strict-Transport-Security"] else "LOW",
                "cvss_score": 5.4 if header == "Content-Security-Policy" else 3.7,
                "owasp": "A05:2021 - Security Misconfiguration",
                "mitre_technique": "T1592 - Gather Victim Host Information",
                "description": f"HTTP response is missing the {header} security header. {detail.get('risk', 'Security risk present')}.",
                "impact": detail.get('risk', 'Potential security misconfiguration'),
                "fix": detail.get('fix', f'Implement {header} header'),
                "mitigation_steps": [
                    f"Add to your server config: {detail.get('fix', header)}",
                    "Test headers at securityheaders.com",
                    "Add headers in Nginx: add_header or Apache: Header always set",
                    "Verify headers appear in browser developer tools (F12 → Network)"
                ],
                "references": "OWASP A05:2021 | Mozilla Security Headers",
                "detected_by": "LLM Header Analyzer",
                "source": "crawler"
            })

        llm_insights.append(f"🔍 LLM detected {len(missing)} missing security headers: {', '.join(missing)}")

    # ── LLM ANALYSIS 2: SERVER TECHNOLOGY DISCLOSURE ──
    server = headers_info.get("server", "")
    powered_by = headers_info.get("powered_by", "")

    if server and server != "Unknown" and any(v in server for v in ["Apache/", "nginx/", "IIS/"]):
        findings.append({
            "type": "Server Version Disclosure",
            "severity": "LOW",
            "cvss_score": 3.1,
            "owasp": "A05:2021 - Security Misconfiguration",
            "mitre_technique": "T1592.002 - Software Discovery",
            "description": f"Server header reveals technology and version: '{server}'. Attackers use this to find known CVEs for that specific version.",
            "impact": "Attacker knows exactly which exploits to use against your server version.",
            "fix": "Hide server version from HTTP headers",
            "mitigation_steps": [
                "Apache: Set ServerTokens Prod in httpd.conf",
                "Nginx: Set server_tokens off in nginx.conf",
                "IIS: Use URLScan or custom headers to hide version",
                "Verify by checking response headers after change"
            ],
            "references": "OWASP A05:2021 | CWE-200",
            "detected_by": "LLM Technology Analyzer",
            "source": "crawler"
        })
        llm_insights.append(f"🔍 LLM detected server version disclosure: {server}")

    if powered_by and powered_by != "Not disclosed":
        findings.append({
            "type": "Technology Stack Disclosure",
            "severity": "LOW",
            "cvss_score": 2.8,
            "owasp": "A05:2021 - Security Misconfiguration",
            "mitre_technique": "T1592.002 - Software Discovery",
            "description": f"X-Powered-By header reveals backend technology: '{powered_by}'. Attackers target known vulnerabilities in disclosed frameworks.",
            "impact": "Precise targeting of framework-specific vulnerabilities.",
            "fix": "Remove X-Powered-By header from server configuration",
            "mitigation_steps": [
                "PHP: expose_php = Off in php.ini",
                "ASP.NET: Remove X-Powered-By in web.config",
                "Express.js: app.disable('x-powered-by')",
                "Verify header is removed after configuration change"
            ],
            "references": "OWASP A05:2021 | CWE-116",
            "detected_by": "LLM Technology Analyzer",
            "source": "crawler"
        })

    # ── LLM ANALYSIS 3: FORM VULNERABILITIES ──
    forms = crawl_data.get("forms_found", [])
    for form in forms:
        form_page = form.get("page", "")
        form_action = form.get("action", "")
        inputs = form.get("inputs", [])
        has_csrf = form.get("has_csrf_token", False)
        has_password = form.get("has_password_field", False)
        has_file = form.get("has_file_upload", False)
        method = form.get("method", "GET")

        # CSRF Check
        if method == "POST" and not has_csrf:
            findings.append({
                "type": "CSRF Token Missing in Form",
                "severity": "HIGH",
                "cvss_score": 8.1,
                "owasp": "A01:2021 - Broken Access Control",
                "mitre_technique": "T1185 - Browser Session Hijacking",
                "description": f"Form at '{form_page}' submits to '{form_action}' via POST without a CSRF token. Attackers can trick users into submitting malicious requests.",
                "impact": "Unauthorized actions on behalf of authenticated users - password changes, transfers, account modifications.",
                "fix": "Add CSRF token to all POST forms",
                "mitigation_steps": [
                    f"Add hidden CSRF token field to form at: {form_page}",
                    "Generate unique token per session server-side",
                    "Validate token before processing every POST request",
                    "Use framework built-in CSRF protection (Django, Laravel, Spring)",
                    "Set SameSite=Strict on session cookies"
                ],
                "references": "OWASP A01:2021 | CWE-352",
                "detected_by": "LLM Form Analyzer",
                "source": "crawler",
                "affected_url": form_page
            })
            llm_insights.append(f"🔍 LLM found CSRF vulnerability in form at: {form_page}")

        # Password field without HTTPS
        if has_password and not crawl_data.get("base_url", "").startswith("https"):
            findings.append({
                "type": "Password Transmitted Over HTTP",
                "severity": "CRITICAL",
                "cvss_score": 9.1,
                "owasp": "A02:2021 - Cryptographic Failures",
                "mitre_technique": "T1040 - Network Sniffing",
                "description": f"Login form at '{form_page}' transmits password over unencrypted HTTP. Anyone on the network can intercept credentials in plain text.",
                "impact": "All user passwords visible to network attackers in plain text.",
                "fix": "Immediately switch to HTTPS before accepting any passwords",
                "mitigation_steps": [
                    "Get SSL certificate from Let's Encrypt (FREE)",
                    "Force HTTPS redirect for all pages with login forms",
                    "Enable HSTS to prevent HTTP fallback",
                    "Test at ssllabs.com after implementation"
                ],
                "references": "OWASP A02:2021 | CWE-319",
                "detected_by": "LLM Form Analyzer",
                "source": "crawler",
                "affected_url": form_page
            })
            llm_insights.append(f"🔍 LLM found password field over HTTP at: {form_page}")

        # File upload vulnerability
        if has_file:
            findings.append({
                "type": "Unrestricted File Upload Risk",
                "severity": "HIGH",
                "cvss_score": 8.8,
                "owasp": "A04:2021 - Insecure Design",
                "mitre_technique": "T1190 - Exploit Public-Facing Application",
                "description": f"File upload form detected at '{form_page}'. Without proper validation, attackers can upload malicious files (PHP shells, malware).",
                "impact": "Attacker uploads web shell → full server control → complete compromise.",
                "fix": "Implement strict file type validation and storage controls",
                "mitigation_steps": [
                    "Whitelist allowed file extensions (jpg, png, pdf only)",
                    "Validate file MIME type server-side, not just extension",
                    "Store uploads outside web root directory",
                    "Rename files randomly - never use user-provided names",
                    "Scan uploaded files with antivirus before storing"
                ],
                "references": "OWASP A04:2021 | CWE-434",
                "detected_by": "LLM Form Analyzer",
                "source": "crawler",
                "affected_url": form_page
            })
            llm_insights.append(f"🔍 LLM found file upload vulnerability at: {form_page}")

        # SQL Injection in form inputs
        sql_input_names = ['id', 'user', 'name', 'search', 'query', 'product', 'category', 'item']
        for inp in inputs:
            inp_name = inp.get('name', '').lower()
            inp_type = inp.get('type', 'text')

            if inp_type == 'text' and any(s in inp_name for s in sql_input_names):
                findings.append({
                    "type": f"SQL Injection Risk in Form Input: '{inp.get('name')}'",
                    "severity": "CRITICAL",
                    "cvss_score": 9.8,
                    "owasp": "A03:2021 - Injection",
                    "mitre_technique": "T1190 - Exploit Public-Facing Application",
                    "description": f"Input field '{inp.get('name')}' in form at '{form_page}' may be vulnerable to SQL injection if input is not sanitized before database query.",
                    "impact": "Database dump, authentication bypass, data manipulation or deletion.",
                    "fix": "Use parameterized queries for all database operations",
                    "mitigation_steps": [
                        f"Sanitize '{inp.get('name')}' field before database query",
                        "Use parameterized queries: cursor.execute('SELECT * FROM users WHERE name = %s', (name,))",
                        "Use ORM (SQLAlchemy) instead of raw SQL",
                        "Add input length and character validation",
                        "Test with: ' OR 1=1-- and check if behavior changes"
                    ],
                    "references": "OWASP A03:2021 | CWE-89",
                    "detected_by": "LLM Input Analyzer",
                    "source": "crawler",
                    "affected_url": form_page
                })
                llm_insights.append(f"🔍 LLM found SQL injection risk in '{inp.get('name')}' at: {form_page}")
                break

    # ── LLM ANALYSIS 4: COOKIE SECURITY ──
    cookies = crawl_data.get("cookies_info", [])
    for cookie in cookies:
        issues = []
        if not cookie.get("has_httponly"):
            issues.append("Missing HttpOnly flag - JavaScript can steal this cookie")
        if not cookie.get("has_secure"):
            issues.append("Missing Secure flag - cookie transmitted over HTTP")
        if not cookie.get("has_samesite"):
            issues.append("Missing SameSite attribute - CSRF attacks possible")

        if issues:
            findings.append({
                "type": f"Insecure Cookie: '{cookie['name']}'",
                "severity": "MEDIUM",
                "cvss_score": 6.1,
                "owasp": "A02:2021 - Cryptographic Failures",
                "mitre_technique": "T1539 - Steal Web Session Cookie",
                "description": f"Cookie '{cookie['name']}' has security misconfigurations: {'; '.join(issues)}",
                "impact": "Session cookies can be stolen via XSS or network interception.",
                "fix": "Add security attributes to all cookies",
                "mitigation_steps": [
                    f"Set HttpOnly flag: Set-Cookie: {cookie['name']}=value; HttpOnly",
                    f"Set Secure flag: Set-Cookie: {cookie['name']}=value; Secure",
                    f"Set SameSite: Set-Cookie: {cookie['name']}=value; SameSite=Strict",
                    "Use short cookie expiration times",
                    "Regenerate session ID after login"
                ],
                "references": "OWASP A02:2021 | CWE-614",
                "detected_by": "LLM Cookie Analyzer",
                "source": "crawler"
            })
            llm_insights.append(f"🔍 LLM found insecure cookie: {cookie['name']} - {'; '.join(issues)}")

    # ── LLM ANALYSIS 5: SENSITIVE PAGES ──
    sensitive = crawl_data.get("sensitive_pages", [])
    for page in sensitive:
        if "admin" in page.lower() or "dashboard" in page.lower():
            findings.append({
                "type": "Admin Panel Publicly Accessible",
                "severity": "HIGH",
                "cvss_score": 7.5,
                "owasp": "A05:2021 - Security Misconfiguration",
                "mitre_technique": "T1595 - Active Scanning",
                "description": f"Administrative panel discovered at: {page}. Publicly accessible admin interfaces are high-value targets for attackers.",
                "impact": "Brute force attacks on admin credentials. Full system control if compromised.",
                "fix": "Restrict admin panel access to authorized IPs only",
                "mitigation_steps": [
                    f"Restrict access to {page} via IP whitelist",
                    "Implement MFA for all admin accounts",
                    "Move admin panel to non-standard URL",
                    "Add rate limiting - max 3 login attempts",
                    "Set up alerts for any admin login attempt"
                ],
                "references": "OWASP A05:2021 | CWE-284",
                "detected_by": "LLM Page Analyzer",
                "source": "crawler",
                "affected_url": page
            })
            llm_insights.append(f"🔍 LLM found exposed admin panel: {page}")

    # ── LLM ANALYSIS 6: API ENDPOINTS ──
    apis = crawl_data.get("api_endpoints", [])
    if apis:
        findings.append({
            "type": f"API Endpoints Exposed ({len(apis)} found)",
            "severity": "MEDIUM",
            "cvss_score": 6.5,
            "owasp": "A01:2021 - Broken Access Control",
            "mitre_technique": "T1595.003 - Wordlist Scanning",
            "description": f"Crawler discovered {len(apis)} API endpoints: {', '.join(apis[:3])}{'...' if len(apis)>3 else ''}. Each endpoint is a potential attack surface.",
            "impact": "API endpoints may lack authentication, rate limiting, or proper authorization.",
            "fix": "Secure all API endpoints with authentication and rate limiting",
            "mitigation_steps": [
                "Add JWT authentication to all API endpoints",
                "Implement rate limiting (100 requests/minute per IP)",
                "Add API versioning and deprecate old versions",
                "Document and test all endpoints for auth bypass",
                "Use API gateway (Kong, AWS API Gateway) for centralized security"
            ],
            "references": "OWASP API Security Top 10 | CWE-284",
            "detected_by": "LLM API Analyzer",
            "source": "crawler"
        })
        llm_insights.append(f"🔍 LLM found {len(apis)} exposed API endpoints")

    print(f"\n🧠 LLM Analysis Complete!")
    print(f"   Vulnerabilities found : {len(findings)}")
    print(f"   LLM insights          : {len(llm_insights)}")
    for insight in llm_insights:
        print(f"   {insight}")

    return {
        "vulnerabilities": findings,
        "llm_insights": llm_insights,
        "crawl_summary": {
            "pages_visited": len(crawl_data.get("pages_found", [])),
            "forms_analyzed": len(crawl_data.get("forms_found", [])),
            "cookies_checked": len(crawl_data.get("cookies_info", [])),
            "apis_found": len(crawl_data.get("api_endpoints", [])),
            "technologies": crawl_data.get("technologies", []),
            "missing_headers": missing
        }
    }
