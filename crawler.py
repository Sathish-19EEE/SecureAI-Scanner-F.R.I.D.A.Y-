import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import re
import warnings
warnings.filterwarnings('ignore')

def crawl_website(start_url, max_pages=15):
    """
    SECUREAI CRAWLER ENGINE
    Visits website → Maps all pages, forms, inputs, APIs
    Passes everything to LLM for deep analysis
    """

    visited = set()
    to_visit = [start_url]
    base_domain = urlparse(start_url).netloc

    crawl_data = {
        "base_url": start_url,
        "pages_found": [],
        "forms_found": [],
        "inputs_found": [],
        "api_endpoints": [],
        "sensitive_pages": [],
        "external_links": [],
        "technologies": [],
        "headers_info": {},
        "cookies_info": [],
        "raw_html_samples": []
    }

    sensitive_keywords = [
        "login", "admin", "dashboard", "register",
        "password", "token", "api", "upload",
        "config", "backup", "payment", "checkout"
    ]

    api_patterns = [
        r'/api/', r'/v1/', r'/v2/', r'/v3/',
        r'/graphql', r'/rest/', r'\.json',
        r'/data/', r'/service/'
    ]

    print(f"\n🕷️  SecureAI Crawler Starting...")
    print(f"🎯  Target: {start_url}")
    print(f"{'='*50}")

    # ── FIRST PAGE: Get headers and cookies ──
    try:
        first_response = requests.get(
            start_url,
            timeout=8,
            verify=False,
            headers={"User-Agent": "Mozilla/5.0 SecureAI-Scanner/4.0"}
        )

        # Security headers check
        security_headers = [
            "Strict-Transport-Security",
            "Content-Security-Policy",
            "X-Frame-Options",
            "X-Content-Type-Options",
            "X-XSS-Protection",
            "Referrer-Policy"
        ]

        found_headers = {}
        missing_headers = []

        for header in security_headers:
            if header in first_response.headers:
                found_headers[header] = first_response.headers[header]
            else:
                missing_headers.append(header)

        crawl_data["headers_info"] = {
            "found": found_headers,
            "missing": missing_headers,
            "server": first_response.headers.get("Server", "Unknown"),
            "powered_by": first_response.headers.get("X-Powered-By", "Not disclosed")
        }

        # Cookies check
        for cookie in first_response.cookies:
            crawl_data["cookies_info"].append({
                "name": cookie.name,
                "has_httponly": cookie.has_nonstandard_attr("HttpOnly") or "httponly" in str(cookie).lower(),
                "has_secure": cookie.secure,
                "has_samesite": "samesite" in str(cookie).lower()
            })

        # Technology detection
        server = first_response.headers.get("Server", "")
        powered_by = first_response.headers.get("X-Powered-By", "")
        content_type = first_response.headers.get("Content-Type", "")

        if "Apache" in server: crawl_data["technologies"].append("Apache Web Server")
        if "nginx" in server.lower(): crawl_data["technologies"].append("Nginx Web Server")
        if "PHP" in powered_by: crawl_data["technologies"].append("PHP Backend")
        if "ASP.NET" in powered_by: crawl_data["technologies"].append("ASP.NET Backend")
        if "WordPress" in first_response.text: crawl_data["technologies"].append("WordPress CMS")
        if "jQuery" in first_response.text: crawl_data["technologies"].append("jQuery")
        if "react" in first_response.text.lower(): crawl_data["technologies"].append("React.js")
        if "angular" in first_response.text.lower(): crawl_data["technologies"].append("Angular.js")

    except Exception as e:
        print(f"⚠️  First page error: {e}")

    # ── CRAWL ALL PAGES ──
    while to_visit and len(visited) < max_pages:
        current_url = to_visit.pop(0)

        if current_url in visited:
            continue

        # Skip non-web resources
        skip_extensions = ['.jpg', '.jpeg', '.png', '.gif', '.css', '.js', '.ico', '.pdf', '.zip']
        if any(current_url.lower().endswith(ext) for ext in skip_extensions):
            continue

        try:
            response = requests.get(
                current_url,
                timeout=6,
                verify=False,
                headers={"User-Agent": "Mozilla/5.0 SecureAI-Scanner/4.0"},
                allow_redirects=True
            )

            visited.add(current_url)

            # Page info
            page_info = {
                "url": current_url,
                "status_code": response.status_code,
                "content_length": len(response.text),
                "has_forms": False,
                "has_inputs": False,
                "is_sensitive": False
            }

            # Check sensitive
            for keyword in sensitive_keywords:
                if keyword in current_url.lower():
                    page_info["is_sensitive"] = True
                    crawl_data["sensitive_pages"].append(current_url)
                    break

            # Check API
            for pattern in api_patterns:
                if re.search(pattern, current_url.lower()):
                    crawl_data["api_endpoints"].append(current_url)
                    break

            # Parse HTML
            soup = BeautifulSoup(response.text, 'html.parser')

            # ── FORMS ──
            forms = soup.find_all('form')
            if forms:
                page_info["has_forms"] = True
                for form in forms:
                    inputs = form.find_all(['input', 'textarea', 'select'])
                    input_list = []
                    has_csrf = False

                    for inp in inputs:
                        inp_name = inp.get('name', '')
                        inp_type = inp.get('type', 'text')
                        inp_value = inp.get('value', '')

                        # Check for CSRF token
                        if any(csrf in inp_name.lower() for csrf in ['csrf', 'token', '_token', 'nonce']):
                            has_csrf = True

                        input_list.append({
                            "name": inp_name,
                            "type": inp_type,
                            "value": inp_value[:50] if inp_value else ""
                        })

                    form_data = {
                        "page": current_url,
                        "action": urljoin(current_url, form.get('action', current_url)),
                        "method": form.get('method', 'GET').upper(),
                        "inputs": input_list,
                        "input_count": len(input_list),
                        "has_csrf_token": has_csrf,
                        "has_password_field": any(i.get('type') == 'password' for i in input_list),
                        "has_file_upload": any(i.get('type') == 'file' for i in input_list)
                    }
                    crawl_data["forms_found"].append(form_data)

            # ── STANDALONE INPUTS ──
            all_inputs = soup.find_all(['input', 'textarea'])
            for inp in all_inputs:
                inp_type = inp.get('type', 'text')
                if inp_type not in ['hidden', 'submit', 'button', 'image']:
                    crawl_data["inputs_found"].append({
                        "page": current_url,
                        "name": inp.get('name', 'unnamed'),
                        "type": inp_type,
                        "placeholder": inp.get('placeholder', '')
                    })
                    page_info["has_inputs"] = True

            # HTML sample for LLM
            if len(crawl_data["raw_html_samples"]) < 3:
                crawl_data["raw_html_samples"].append({
                    "url": current_url,
                    "html_snippet": response.text[:2000]
                })

            crawl_data["pages_found"].append(page_info)
            print(f"  ✅ [{response.status_code}] {current_url}")
            if forms: print(f"     📋 {len(forms)} form(s) found")
            if page_info["is_sensitive"]: print(f"     ⚠️  Sensitive page!")

            # ── DISCOVER MORE LINKS ──
            for tag in soup.find_all(['a', 'link'], href=True):
                href = tag.get('href', '')
                full_url = urljoin(current_url, href)
                link_domain = urlparse(full_url).netloc

                if link_domain == base_domain and full_url not in visited:
                    if full_url not in to_visit:
                        to_visit.append(full_url)
                elif link_domain != base_domain and href.startswith('http'):
                    crawl_data["external_links"].append(full_url)

            # Script src - detect JS libraries
            for script in soup.find_all('script', src=True):
                src = script.get('src', '').lower()
                if 'jquery' in src: crawl_data["technologies"].append("jQuery (CDN)")
                if 'bootstrap' in src: crawl_data["technologies"].append("Bootstrap")
                if 'react' in src: crawl_data["technologies"].append("React.js")
                if 'angular' in src: crawl_data["technologies"].append("Angular.js")
                if 'vue' in src: crawl_data["technologies"].append("Vue.js")

        except requests.exceptions.Timeout:
            print(f"  ⏱️  Timeout: {current_url}")
        except requests.exceptions.ConnectionError:
            print(f"  ❌ Cannot connect: {current_url}")
        except Exception as e:
            print(f"  ⚠️  Error {current_url}: {str(e)[:50]}")

    # Remove duplicates
    crawl_data["technologies"] = list(set(crawl_data["technologies"]))
    crawl_data["external_links"] = list(set(crawl_data["external_links"]))[:10]

    print(f"\n{'='*50}")
    print(f"🗺️  Crawl Complete!")
    print(f"   Pages visited  : {len(crawl_data['pages_found'])}")
    print(f"   Forms found    : {len(crawl_data['forms_found'])}")
    print(f"   Inputs found   : {len(crawl_data['inputs_found'])}")
    print(f"   API endpoints  : {len(crawl_data['api_endpoints'])}")
    print(f"   Sensitive pages: {len(crawl_data['sensitive_pages'])}")
    print(f"   Technologies   : {', '.join(crawl_data['technologies'])}")
    print(f"{'='*50}\n")

    return crawl_data
