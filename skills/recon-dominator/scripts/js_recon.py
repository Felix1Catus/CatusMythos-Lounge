#!/usr/bin/env python3
"""
JS Bundle & Source-Map Recon - recon-dominator
Mines a target's own client-side JavaScript for hidden API routes, parameter
names, and unlinked chunks/routes -- a well-documented 2024-2026 bug-bounty
technique (research_notes/Recon-dominator depth techniques/js_bundle_mining.md)
not covered by tech_fingerprint.py's own technology-signature detection.

Everything here is stdlib-only (re, json, urllib) by design, matching the
rest of this skill. Where a real JS AST/parser would be needed for full
correctness (variable-concatenated URLs, computed call targets like
window["fetch"], multi-statement URL building), that limitation is stated
explicitly rather than silently producing a wrong answer -- these cases are
skipped, not guessed at.
Author: CatusMythos-Lounge contributors
"""

import argparse
import json
import re
import urllib.parse
import urllib.request
from datetime import datetime, timezone

from _common import http_get, log, success, warn


# --- Endpoint/path extraction -----------------------------------------------
# LinkFinder's original 5-alternative regex (Gerben Javado), reused verbatim
# or near-verbatim by JSFinder and GoLinkFinder -- there is essentially one
# "classic" endpoint-extraction regex in the open-source ecosystem, not many
# competing ones. Kept as the strict superset (GoLinkFinder's version, which
# JSFinder trims two ways) rather than reinventing a pattern.
ENDPOINT_REGEX = re.compile(r"""
    (?:"|')
    (
      ((?:[a-zA-Z]{1,10}://|//)[^"'/]{1,}\.[a-zA-Z]{2,}[^"']{0,})
      |
      ((?:/|\.\./|\./)[^"'><,;|*()(%$^/\\\[\]][^"'><,;|()]{1,})
      |
      ([a-zA-Z0-9_\-/]{1,}/[a-zA-Z0-9_\-/.]{1,}\.(?:[a-zA-Z]{1,4}|action)(?:[?#][^"|']{0,}|))
      |
      ([a-zA-Z0-9_\-/]{1,}/[a-zA-Z0-9_\-/]{3,}(?:[?#][^"|']{0,}|))
      |
      ([a-zA-Z0-9_\-]{1,}\.(?:php|asp|aspx|jsp|json|action|html|js|txt|xml)(?:[?#][^"|']{0,}|))
    )
    (?:"|')
""", re.VERBOSE)

FILE_EXTENSIONS = {
    "js", "css", "html", "htm", "xhtml", "xlsx", "xls", "docx", "doc", "pdf",
    "rss", "xml", "php", "phtml", "asp", "aspx", "asmx", "ashx", "cgi", "pl",
    "rb", "py", "do", "jsp", "jspa", "json", "jsonp", "txt",
}


def maybe_url(s):
    """jsluice's (BishopFox) last-resort string-heuristic filter, ported
    verbatim from its Go source -- the precision filter that closes the gap
    between a broad regex sweep and an actual URL, without needing a real
    parser. Reduces noise from ENDPOINT_REGEX's own false matches."""
    if not any(c in s for c in "/?."):
        return False
    if any(c in s for c in " ()!<>'\"`{}^$,"):
        return False
    if s.startswith("/"):
        return True
    parsed = urllib.parse.urlparse(s)
    if parsed.scheme and parsed.scheme.lower() not in ("http", "https"):
        return False
    host = parsed.hostname or ""
    if len(host.split(".")) > 1:
        return True
    if parsed.query:
        return True
    if "." not in parsed.path:
        return False
    ext = parsed.path.rsplit(".", 1)[-1]
    return ext in FILE_EXTENSIONS


def extract_endpoints(js_text):
    """Sweep raw (even minified) JS text for quoted path-like strings.
    Beautification isn't required -- LinkFinder's own "|' delimiter
    anchoring works directly on minified text."""
    found = set()
    for m in ENDPOINT_REGEX.finditer(js_text):
        val = m.group(1)
        if val and maybe_url(val):
            found.add(val)
    return sorted(found)


# --- fetch/axios/jQuery/XHR call-site extraction ----------------------------
# Each regex mirrors a specific, documented matcher branch from jsluice's own
# ground-truth logic (BishopFox) -- not a generic string sweep -- so each one
# captures a real HTTP call shape rather than guessing. Explicit limitation,
# same as jsluice's own: a base URL built from a variable, concatenation
# (`BASE + "/x"`), or a computed call target (`window["fetch"]`) cannot be
# resolved by regex and is not attempted here -- that needs real AST parsing.
FETCH_RE = re.compile(r"""\bfetch\s*\(\s*(['"`])((?:\\.|(?!\1).)*?)\1""", re.DOTALL)
AXIOS_METHOD_RE = re.compile(
    r"""\baxios\.(get|post|put|patch|delete|head|options)\s*\(\s*(['"`])((?:\\.|(?!\2).)*?)\2""",
    re.IGNORECASE | re.DOTALL,
)
AJAX_OBJECT_RE = re.compile(
    # `\b` only in front of the word-starting alternatives (axios, jQuery) --
    # `$` isn't a word character, so a shared leading `\b` fails to match
    # `$.ajax` whenever it's preceded by another non-word character (e.g. a
    # newline or space, i.e. almost always), silently dropping every jQuery
    # `$.ajax({...})` object-literal call. Caught by testing against a
    # realistic sample, not assumed from the research notes' own synthesis.
    r"""(?:\baxios|\$\.ajax|\bjQuery\.ajax)\s*\(\s*\{.{0,500}?\burl\s*:\s*(['"`])((?:\\.|(?!\1).)*?)\1""",
    re.DOTALL,
)
JQUERY_RE = re.compile(
    r"""\$\.(get|post|ajax)\s*\(\s*(['"`])((?:\\.|(?!\2).)*?)\2""",
    re.DOTALL,
)
XHR_OPEN_RE = re.compile(
    r"""\.open\s*\(\s*(['"`])(GET|HEAD|OPTIONS|POST|PUT|PATCH|DELETE)\1\s*,\s*(['"`])((?:\\.|(?!\3).)*?)\3""",
    re.IGNORECASE | re.DOTALL,
)


def normalize_template(raw_url):
    """Collapse template-literal placeholders (`${id}`) into a stable
    path-shape marker, mirroring jsluice's ExpressionPlaceholder concept."""
    return re.sub(r"\$\{[^}]*\}", "{param}", raw_url)


def extract_api_calls(js_text):
    """Extract fetch/axios/$.ajax/$.get/$.post/XHR.open call sites and the
    URL argument each one targets. Returns a list of {method, url, raw}."""
    calls = []
    for m in FETCH_RE.finditer(js_text):
        calls.append({"method": "GET", "url": normalize_template(m.group(2)), "via": "fetch"})
    for m in AXIOS_METHOD_RE.finditer(js_text):
        calls.append({"method": m.group(1).upper(), "url": normalize_template(m.group(3)), "via": "axios"})
    for m in AJAX_OBJECT_RE.finditer(js_text):
        calls.append({"method": "?", "url": normalize_template(m.group(2)), "via": "ajax-object"})
    for m in JQUERY_RE.finditer(js_text):
        calls.append({"method": m.group(1).upper(), "url": normalize_template(m.group(3)), "via": "jquery"})
    for m in XHR_OPEN_RE.finditer(js_text):
        calls.append({"method": m.group(2).upper(), "url": normalize_template(m.group(4)), "via": "xhr"})

    # De-dupe, dropping calls that normalized to pure placeholder (no literal
    # structure left at all) -- jsluice discards these too, since a URL of
    # just "{param}" carries no actual recon value.
    seen, unique = set(), []
    for c in calls:
        if not re.search(r"[A-Za-z0-9/._-]", c["url"].replace("{param}", "")):
            continue
        key = (c["method"], c["url"], c["via"])
        if key not in seen:
            seen.add(key)
            unique.append(c)
    return unique


# --- Source-map mining ------------------------------------------------------
SOURCEMAP_COMMENT_RE = re.compile(r"//[#@]\s*sourceMappingURL=([^\s'\"]+)")


def find_sourcemap_url(js_text, js_url):
    m = SOURCEMAP_COMMENT_RE.search(js_text)
    if m:
        return urllib.parse.urljoin(js_url, m.group(1))
    return js_url + ".map"  # standard fallback convention


def recover_sourcemap(map_url, timeout=15):
    """Recovering original file paths/source needs zero VLQ decoding of the
    `mappings` field -- sources/sourcesContent are read directly. Even when
    sourcesContent is absent, the sources array alone discloses the entire
    original module/directory tree (component names, internal paths),
    itself real recon value with zero text recovered."""
    body = http_get(map_url, timeout=timeout)
    if not body:
        return None
    try:
        data = json.loads(body)
    except (json.JSONDecodeError, ValueError):
        return None

    sources = data.get("sources", [])
    contents = data.get("sourcesContent", [])
    root = data.get("sourceRoot", "")

    recovered = {}
    for i, src_path in enumerate(sources):
        full_path = (root.rstrip("/") + "/" + src_path) if root else src_path
        text = contents[i] if i < len(contents) else None
        recovered[full_path] = text
    return recovered


# --- Next.js / Vite chunk-manifest enumeration ------------------------------
def get_next_build_id(html):
    m = re.search(r'/_next/static/([^/"\']+)/_buildManifest\.js', html)
    if m:
        return m.group(1)
    m = re.search(r'"buildId"\s*:\s*"([^"]+)"', html)
    return m.group(1) if m else None


def fetch_next_build_manifest(base_url, build_id, timeout=15):
    """Every key of the returned dict is a client-side route the app knows
    about, independent of whether anything on the rendered page links to
    it -- hidden/unlinked/admin/feature-flagged routes still show up here
    as long as they're part of the current build."""
    url = f"{base_url.rstrip('/')}/_next/static/{build_id}/_buildManifest.js"
    text = http_get(url, timeout=timeout)
    if not text:
        return {}
    m = re.search(r"__BUILD_MANIFEST\s*=\s*(\{.*?\})\s*[;,]", text, re.DOTALL)
    if not m:
        return {}
    try:
        return json.loads(m.group(1))
    except (json.JSONDecodeError, ValueError):
        return {}


VITE_MANIFEST_PATHS = ["/.vite/manifest.json", "/assets/manifest.json", "/manifest.json"]


def fetch_vite_manifest(base_url, timeout=15):
    """.vite/manifest.json is already strict JSON -- no stripping needed.
    dynamicImports is the high-value field: in an SPA it's overwhelmingly
    how route-level code-splitting is implemented, so it's close to a
    direct route list."""
    for path in VITE_MANIFEST_PATHS:
        text = http_get(base_url.rstrip("/") + path, timeout=timeout)
        if not text:
            continue
        try:
            manifest = json.loads(text)
        except (json.JSONDecodeError, ValueError):
            continue
        if not isinstance(manifest, dict):
            continue
        all_files, dynamic_entry_points = set(), set()
        for key, chunk in manifest.items():
            if isinstance(chunk, dict):
                if chunk.get("file"):
                    all_files.add(chunk["file"])
                for dyn_key in chunk.get("dynamicImports", []):
                    dynamic_entry_points.add(dyn_key)
        return {"manifest_path": path, "all_files": sorted(all_files),
                "dynamic_entry_points": sorted(dynamic_entry_points)}
    return {}


# Catches chunks referenced only from within other JS (dynamic import()
# targets) that never appear as a top-level HTML <script> tag, regardless
# of which bundler produced them -- the one bundler-agnostic baseline.
CHUNK_HINT_RE = re.compile(r"""["'](/[\w./-]*chunks?/[\w.-]+\.js)["']""")
HASHED_ASSET_RE = re.compile(r"""["']([\w./-]+?\.[0-9a-f]{8,20}\.(?:js|css))["']""")


def find_referenced_chunks(js_text):
    found = set(CHUNK_HINT_RE.findall(js_text)) | set(HASHED_ASSET_RE.findall(js_text))
    return sorted(found)


# --- Orchestration -----------------------------------------------------------
def extract_script_urls(html, base_url):
    urls = set()
    for m in re.finditer(r'<script[^>]+src=["\']([^"\']+)["\']', html, re.IGNORECASE):
        urls.add(urllib.parse.urljoin(base_url, m.group(1)))
    return sorted(urls)


def mine_target(base_url, max_chunks=30, fetch_sourcemaps=True, timeout=15):
    result = {
        "target": base_url,
        "endpoints": set(),
        "api_calls": [],
        "sourcemap_hits": {},  # map_url -> {path: content_or_None}
        "next_routes": {},
        "vite": {},
        "scripts_analyzed": [],
        "errors": [],
    }

    html = http_get(base_url, timeout=timeout) or ""
    if not html:
        warn(f"Could not fetch {base_url}")
        return result

    script_urls = extract_script_urls(html, base_url)

    build_id = get_next_build_id(html)
    if build_id:
        log(f"Next.js build detected (buildId={build_id}), fetching build manifest")
        result["next_routes"] = fetch_next_build_manifest(base_url, build_id, timeout)
        if result["next_routes"]:
            success(f"Next.js build manifest: {len(result['next_routes'])} known routes")

    vite_manifest = fetch_vite_manifest(base_url, timeout)
    if vite_manifest:
        result["vite"] = vite_manifest
        success(f"Vite manifest found at {vite_manifest['manifest_path']}: "
                 f"{len(vite_manifest['all_files'])} files, "
                 f"{len(vite_manifest['dynamic_entry_points'])} dynamic entry points")

    seen_chunks = set(script_urls)
    queue = list(script_urls)[:max_chunks]
    analyzed = 0

    while queue and analyzed < max_chunks:
        js_url = queue.pop(0)
        if js_url in result["scripts_analyzed"]:
            continue
        js_text = http_get(js_url, timeout=timeout)
        analyzed += 1
        result["scripts_analyzed"].append(js_url)
        if not js_text:
            result["errors"].append(f"fetch failed: {js_url}")
            continue

        result["endpoints"].update(extract_endpoints(js_text))
        result["api_calls"].extend(extract_api_calls(js_text))

        for chunk_path in find_referenced_chunks(js_text):
            chunk_url = urllib.parse.urljoin(js_url, chunk_path)
            if chunk_url not in seen_chunks and len(queue) + analyzed < max_chunks:
                seen_chunks.add(chunk_url)
                queue.append(chunk_url)

        if fetch_sourcemaps:
            map_url = find_sourcemap_url(js_text, js_url)
            recovered = recover_sourcemap(map_url, timeout)
            if recovered:
                result["sourcemap_hits"][map_url] = recovered
                success(f"Source map recovered: {map_url} ({len(recovered)} original source files disclosed)")

    result["endpoints"] = sorted(result["endpoints"])
    # De-dupe api_calls again post-merge (per-chunk dedup already ran, but
    # the same endpoint can appear across multiple chunks).
    seen, unique_calls = set(), []
    for c in result["api_calls"]:
        key = (c["method"], c["url"], c["via"])
        if key not in seen:
            seen.add(key)
            unique_calls.append(c)
    result["api_calls"] = unique_calls

    return result


def main():
    parser = argparse.ArgumentParser(description="JS Bundle & Source-Map Recon - CatusMythos-Lounge")
    parser.add_argument("--target", "-t", required=True, help="Base URL to mine (e.g. https://app.example.com)")
    parser.add_argument("--max-chunks", type=int, default=30, help="Max JS files to fetch/analyze")
    parser.add_argument("--no-sourcemaps", action="store_true", help="Skip source-map fetch/recovery")
    parser.add_argument("--timeout", type=int, default=15)
    parser.add_argument("--output", "-o", help="Output JSON file")
    args = parser.parse_args()

    log(f"Mining JS bundles for: {args.target}")
    result = mine_target(args.target, max_chunks=args.max_chunks,
                          fetch_sourcemaps=not args.no_sourcemaps, timeout=args.timeout)

    output = {
        "meta": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "type": "js_bundle_recon",
            "tool": "js_recon.py by CatusMythos-Lounge contributors",
            "target": args.target,
        },
        **result,
    }

    output_path = args.output or "js_recon_results.json"
    with open(output_path, "w") as f:
        json.dump(output, f, indent=2)
    success(f"Results saved to: {output_path}")

    print(f"\n{'='*60}")
    print(f"  JS BUNDLE RECON SUMMARY - {args.target}")
    print(f"{'='*60}")
    print(f"  Scripts analyzed    : {len(result['scripts_analyzed'])}")
    print(f"  Endpoints found     : {len(result['endpoints'])}")
    print(f"  API call sites      : {len(result['api_calls'])}")
    print(f"  Source maps hit     : {len(result['sourcemap_hits'])}")
    if result["next_routes"]:
        print(f"  Next.js routes      : {len(result['next_routes'])}")
    if result["vite"]:
        print(f"  Vite dynamic routes : {len(result['vite'].get('dynamic_entry_points', []))}")
    if result["endpoints"]:
        print(f"\n  Sample endpoints:")
        for e in result["endpoints"][:15]:
            print(f"    {e}")
    if result["sourcemap_hits"]:
        print(f"\n  SOURCE MAPS DISCLOSED (review for secrets/hidden routes):")
        for map_url, files in result["sourcemap_hits"].items():
            print(f"    {map_url} -> {len(files)} original source files")
    print(f"{'='*60}\n")


if __name__ == "__main__":
    main()
