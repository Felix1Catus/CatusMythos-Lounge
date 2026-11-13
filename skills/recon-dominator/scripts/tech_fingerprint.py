#!/usr/bin/env python3
"""
Technology Fingerprinting Module - recon-dominator
Detects web technologies, frameworks, CMS, WAF/CDN, analytics, and security headers.
Author: orizon.one

WAF/CDN/analytics detection merged in from Masriyan/Claude-Code-CyberSecurity-Skill's
skills/01-recon-osint/scripts/tech_fingerprint.py (MIT, see NOTICE-MASRIYAN.md), reimplemented
against stdlib urllib instead of `requests` so this skill keeps its zero-pip-dependency design.
"""

import argparse
import json
import re
import ssl
import urllib.request
from pathlib import Path
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed


from _common import log, success, warn
# Technology signatures: pattern -> technology name
HEADER_SIGNATURES = {
    "server": {
        "apache": "Apache",
        "nginx": "Nginx",
        "microsoft-iis": "IIS",
        "litespeed": "LiteSpeed",
        "openresty": "OpenResty",
        "gunicorn": "Gunicorn",
        "uvicorn": "Uvicorn",
        "caddy": "Caddy",
        "envoy": "Envoy",
        "traefik": "Traefik",
    },
    "x-powered-by": {
        "php": "PHP",
        "asp.net": "ASP.NET",
        "express": "Express.js",
        "next.js": "Next.js",
        "nuxt": "Nuxt.js",
        "django": "Django",
        "flask": "Flask",
        "ruby": "Ruby",
        "java": "Java",
        "servlet": "Java Servlet",
    }
}

BODY_SIGNATURES = [
    (r"wp-content|wp-includes|wordpress", "WordPress"),
    (r"/sites/default/files|drupal", "Drupal"),
    (r"joomla", "Joomla"),
    (r"shopify\.com|cdn\.shopify", "Shopify"),
    (r"squarespace\.com", "Squarespace"),
    (r"wix\.com|wixstatic", "Wix"),
    (r"__next|_next/static", "Next.js"),
    (r"__nuxt|_nuxt/", "Nuxt.js"),
    (r"ng-version|angular", "Angular"),
    (r"__vue|vue\.js|vue\.min\.js", "Vue.js"),
    (r"react|reactDOM|_reactRoot", "React"),
    (r"svelte", "Svelte"),
    (r"ember", "Ember.js"),
    (r"jquery|jQuery", "jQuery"),
    (r"bootstrap\.min\.(css|js)", "Bootstrap"),
    (r"tailwindcss|tailwind", "Tailwind CSS"),
    (r"laravel|csrf.*token", "Laravel"),
    (r"rails|ruby on rails|turbolinks", "Ruby on Rails"),
    (r"django|csrfmiddlewaretoken", "Django"),
    (r"flask", "Flask"),
    (r"spring|java\.lang", "Spring"),
    (r"graphql|__schema|graphiql", "GraphQL"),
    (r"swagger|openapi|api-docs", "Swagger/OpenAPI"),
    (r"cloudflare", "Cloudflare"),
    (r"google-analytics|gtag|ga\.js", "Google Analytics"),
    (r"googletagmanager", "Google Tag Manager"),
    (r"hotjar", "Hotjar"),
    (r"sentry", "Sentry"),
    (r"recaptcha", "reCAPTCHA"),
    (r"stripe\.com|stripe\.js", "Stripe"),
    (r"intercom", "Intercom"),
    (r"hubspot", "HubSpot"),
    (r"salesforce|pardot", "Salesforce"),
    (r"firebase", "Firebase"),
    (r"aws-sdk|amazonaws", "AWS SDK"),
    (r"phpmyadmin", "phpMyAdmin"),
    (r"grafana", "Grafana"),
    (r"kibana", "Kibana"),
    (r"jenkins", "Jenkins"),
    (r"gitlab", "GitLab"),
    (r"minio", "MinIO"),
    (r"connect\.facebook\.net|fbq\(", "Facebook Pixel"),
]

# WAF signatures: header/cookie substring -> WAF name (merged from Masriyan's collection)
WAF_SIGNATURES = {
    "cf-ray": "Cloudflare WAF",
    "__cfduid": "Cloudflare WAF",
    "x-amzn-requestid": "AWS WAF",
    "x-akamai": "Akamai",
    "akamaighost": "Akamai",
    "x-sucuri-id": "Sucuri",
    "x-sucuri-cache": "Sucuri",
    "mod_security": "ModSecurity",
    "noyb": "ModSecurity",
}

# CDN signatures: specific header name -> CDN name (checked via exact header presence)
CDN_HEADER_SIGNATURES = {
    "cf-cache-status": "Cloudflare",
    "x-amz-cf-id": "AWS CloudFront",
    "x-fastly-request-id": "Fastly",
    "x-cdn": None,  # value itself names the CDN
    "x-akamai-transformed": "Akamai",
}

COOKIE_SIGNATURES = {
    "PHPSESSID": "PHP",
    "JSESSIONID": "Java",
    "ASP.NET": "ASP.NET",
    "csrftoken": "Django",
    "laravel_session": "Laravel",
    "_rails": "Ruby on Rails",
    "connect.sid": "Express.js",
    "AWSALB": "AWS ALB",
    "AWSELB": "AWS ELB",
    "__cfduid": "Cloudflare",
    "cf_clearance": "Cloudflare",
    "incap_ses": "Imperva/Incapsula",
}


def fetch_page(url, timeout=10):
    """Fetch a page and return headers + body."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    req = urllib.request.Request(url, headers={
        "User-Agent": "Mozilla/5.0 (compatible; orizon-recon/1.0)"
    })
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            body = resp.read(32768).decode("utf-8", errors="replace")
            headers = dict(resp.headers)
            return headers, body
    except Exception:
        return None, None


# WordPress (and WP-plugin-shaped sites generally) enqueue scripts/styles with
# a `?ver=X.Y.Z` cache-busting query string that is also the real plugin/
# theme/core version -- e.g. `/wp-content/plugins/elementor-pro/assets/css/
# modules/sticky.min.css?ver=4.0.4` names both the plugin ("elementor-pro")
# and its exact version in one URL, with no authentication needed to read it.
_WP_PLUGIN_VER_RE = re.compile(
    r"wp-content/plugins/([a-zA-Z0-9_.-]+)/[^\"'\s]*\?ver=([0-9][0-9a-zA-Z.+_-]*)"
)
_WP_THEME_VER_RE = re.compile(
    r"wp-content/themes/([a-zA-Z0-9_.-]+)/[^\"'\s]*\?ver=([0-9][0-9a-zA-Z.+_-]*)"
)
_WP_CORE_VER_RE = re.compile(
    r"wp-includes/[^\"'\s]*\?ver=([0-9][0-9a-zA-Z.+_-]*)"
)


def extract_versioned_components(body):
    """Pull {name, version, kind} tuples out of a page's enqueued-asset
    query strings. One entry per unique (name, version) pair -- a plugin's
    own assets are usually all pinned to the same version, so this
    naturally de-dupes without losing anything."""
    seen = set()
    components = []

    for name, version in _WP_PLUGIN_VER_RE.findall(body):
        key = ("wp-plugin", name, version)
        if key not in seen:
            seen.add(key)
            components.append({"kind": "wordpress-plugin", "name": name, "version": version})

    for name, version in _WP_THEME_VER_RE.findall(body):
        key = ("wp-theme", name, version)
        if key not in seen:
            seen.add(key)
            components.append({"kind": "wordpress-theme", "name": name, "version": version})

    core_matches = _WP_CORE_VER_RE.findall(body)
    # wp-includes assets occasionally carry a bundled library's own version
    # rather than core's -- only trust this as "WordPress core" when there
    # are at least 2 matches AND they all agree on one version (one
    # mismatched asset among several is a stronger signal than a single
    # match that could be the one exception).
    if len(core_matches) >= 2 and len(set(core_matches)) == 1:
        components.append({"kind": "wordpress-core", "name": "wordpress", "version": core_matches[0]})

    return components


def fingerprint_host(host):
    """Fingerprint a single host."""
    technologies = set()
    details = {}

    # Try HTTPS first, then HTTP
    for scheme in ["https", "http"]:
        url = f"{scheme}://{host}/"
        headers, body = fetch_page(url)
        if headers:
            details["url"] = url
            details["headers"] = headers

            # Header-based detection
            for header_name, sigs in HEADER_SIGNATURES.items():
                header_val = (headers.get(header_name, "") or "").lower()
                for pattern, tech in sigs.items():
                    if pattern in header_val:
                        technologies.add(tech)

            # Cookie-based detection
            cookies = headers.get("Set-Cookie", "") or ""
            for cookie_name, tech in COOKIE_SIGNATURES.items():
                if cookie_name.lower() in cookies.lower():
                    technologies.add(tech)

            # WAF detection (header + cookie substring match)
            combined_lower = (" ".join(f"{k}:{v}" for k, v in headers.items()) + " " + cookies).lower()
            wafs = set()
            for sig, waf_name in WAF_SIGNATURES.items():
                if sig in combined_lower:
                    wafs.add(waf_name)
            if wafs:
                details["waf"] = sorted(wafs)

            # CDN detection (specific header presence)
            headers_lower = {k.lower(): v for k, v in headers.items()}
            cdns = set()
            for hdr, cdn_name in CDN_HEADER_SIGNATURES.items():
                if hdr in headers_lower:
                    cdns.add(cdn_name or headers_lower[hdr])
            if cdns:
                details["cdn"] = sorted(cdns)

            # Security headers analysis
            security = {}
            sec_headers = {
                "Strict-Transport-Security": "HSTS",
                "Content-Security-Policy": "CSP",
                "X-Frame-Options": "X-Frame-Options",
                "X-Content-Type-Options": "X-Content-Type-Options",
                "X-XSS-Protection": "X-XSS-Protection",
                "Permissions-Policy": "Permissions-Policy",
                "Referrer-Policy": "Referrer-Policy",
                "Cross-Origin-Opener-Policy": "COOP",
                "Cross-Origin-Embedder-Policy": "COEP",
                "Cross-Origin-Resource-Policy": "CORP",
            }
            for header, name in sec_headers.items():
                val = headers.get(header, "")
                security[name] = {"present": bool(val), "value": val or "MISSING"}

            details["security_headers"] = security
            missing = [n for n, v in security.items() if not v["present"]]
            if missing:
                details["missing_security_headers"] = missing

            # Body-based detection
            if body:
                for pattern, tech in BODY_SIGNATURES:
                    if re.search(pattern, body, re.IGNORECASE):
                        technologies.add(tech)

                # Extract meta generator
                gen_match = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)', body, re.I)
                if gen_match:
                    technologies.add(gen_match.group(1))

                # Versioned components: WordPress (and similar CMS) enqueue
                # scripts/styles with a `?ver=X.Y.Z` cache-busting query
                # string that happens to also be the plugin/theme/core
                # version -- the same technique that manually found Elementor
                # 4.3.5 / Elementor Pro 4.0.4 on a real engagement. Feeds
                # cve_lookup.py, which needs an actual version number per
                # component, not just "this technology is present".
                versioned = extract_versioned_components(body)
                if versioned:
                    details["versioned_components"] = versioned

            break  # Got response, no need to try other scheme

    return {
        "host": host,
        "technologies": sorted(technologies),
        "details": details
    }


def main():
    parser = argparse.ArgumentParser(description="Technology Fingerprinting - orizon.one")
    parser.add_argument("--input", "-i", required=True, help="File with hosts or JSON from port scan")
    parser.add_argument("--output", "-o", help="Output JSON file")
    parser.add_argument("--threads", "-t", type=int, default=20, help="Concurrent threads")
    args = parser.parse_args()

    log("Starting technology fingerprinting...")
    log(f"Timestamp: {datetime.utcnow().isoformat()}Z")

    # Load hosts
    input_path = Path(args.input)
    hosts = []
    if input_path.suffix == ".json":
        with open(input_path) as f:
            data = json.load(f)
        if "results" in data:
            hosts = [r["host"] for r in data["results"]]
        elif "subdomains" in data:
            hosts = [s["host"] for s in data["subdomains"]]
    else:
        hosts = [h.strip() for h in input_path.read_text().strip().split("\n") if h.strip()]

    log(f"Fingerprinting {len(hosts)} hosts...")

    results = []
    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = {executor.submit(fingerprint_host, host): host for host in hosts}
        for future in as_completed(futures):
            result = future.result()
            extra_bits = []
            if result["details"].get("waf"):
                extra_bits.append(f"WAF: {', '.join(result['details']['waf'])}")
            if result["details"].get("cdn"):
                extra_bits.append(f"CDN: {', '.join(result['details']['cdn'])}")
            extra = f" [{' | '.join(extra_bits)}]" if extra_bits else ""
            if result["technologies"]:
                success(f"{result['host']}: {', '.join(result['technologies'])}{extra}")
            else:
                log(f"{result['host']}: no technologies detected{extra}")
            results.append(result)

    # Build tech matrix
    all_techs = set()
    for r in results:
        all_techs.update(r["technologies"])

    output = {
        "meta": {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "type": "tech_fingerprint",
            "tool": "recon-dominator by orizon.one",
            "hosts_analyzed": len(hosts),
            "unique_technologies": len(all_techs)
        },
        "technology_summary": sorted(all_techs),
        "results": results
    }

    output_path = args.output or "tech_fingerprint_results.json"
    with open(output_path, "w") as f:
        json.dump(output, f, indent=2)
    success(f"Results saved to: {output_path}")

    # Summary
    print(f"\n{'='*60}")
    print(f"  TECHNOLOGY FINGERPRINT SUMMARY")
    print(f"{'='*60}")
    print(f"  Hosts analyzed      : {len(hosts)}")
    print(f"  Unique technologies : {len(all_techs)}")
    for tech in sorted(all_techs):
        count = sum(1 for r in results if tech in r["technologies"])
        print(f"    {tech:30s} : {count} hosts")
    print(f"{'='*60}\n")


if __name__ == "__main__":
    main()
