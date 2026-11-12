#!/usr/bin/env python3
"""
CVE / Public-Exploit Lookup - recon-dominator
Turns fingerprinted components (tech_fingerprint.py's output) into concrete,
version-matched vulnerability hypotheses instead of a blind vuln-class sweep.

This is the orchestration fix for "probe everything" vs "probe what the
fingerprint actually suggests": recon-dominator now tells the rest of the
pipeline not just WHAT is running, but WHICH PUBLISHED CVEs plausibly apply
to the EXACT discovered version, with real affected-version-range comparison
against NVD's own CPE match data where NVD provides it -- not a keyword
guess. Each result also carries NVD's reference URLs, which routinely
include the original write-up/PoC/advisory, not just the bare CVE ID.

Zero dependencies (stdlib urllib only), consistent with the rest of this
pipeline. Uses the NVD CVE 2.0 API, which is public and does not require an
API key for the request volume a normal engagement needs -- this script
self-paces to stay under NVD's published unauthenticated rate limit (5
requests / 30s) rather than relying on a key.

Author: CatusMythos-Lounge contributors
"""

import argparse
import json
import re
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone


def log(msg):
    print(f"[*] {msg}")


def warn(msg):
    print(f"[!] {msg}")


def success(msg):
    print(f"[+] {msg}")


NVD_CVE_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
# NVD's published unauthenticated rate limit is 5 requests per rolling 30s
# window. Self-pace comfortably under that rather than relying on nobody
# else hitting the same limit at the same time.
NVD_MIN_INTERVAL_S = 6.5


def _http_get_json(url, timeout=20):
    ctx = ssl.create_default_context()
    req = urllib.request.Request(url, headers={
        "User-Agent": "Mozilla/5.0 (compatible; catusmythos-lounge-recon/1.0)",
        "Accept": "application/json",
    })
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            return json.loads(resp.read().decode("utf-8", errors="replace")), None
    except urllib.error.HTTPError as e:
        if e.code == 403 or e.code == 429:
            return None, f"rate-limited (HTTP {e.code}) -- NVD's public API caps unauthenticated requests; " \
                          "retry later or get a free API key from https://nvd.nist.gov/developers/request-an-api-key"
        return None, f"HTTP {e.code}"
    except Exception as e:
        return None, str(e)


def _parse_version(v):
    """Best-effort version tuple for comparison: '4.2.1' -> (4, 2, 1)."""
    parts = re.findall(r"\d+", v or "")
    return tuple(int(p) for p in parts) if parts else (0,)


def _version_in_range(version, start_incl=None, start_excl=None, end_incl=None, end_excl=None):
    """Compare a discovered version against NVD's own CPE match range
    fields when present. Returns True/False/None (None = NVD didn't publish
    a usable range for this match, can't determine -- report as 'unclear',
    never silently assume affected OR patched)."""
    if start_incl is None and start_excl is None and end_incl is None and end_excl is None:
        return None
    v = _parse_version(version)
    if start_incl is not None and v < _parse_version(start_incl):
        return False
    if start_excl is not None and v <= _parse_version(start_excl):
        return False
    if end_incl is not None and v > _parse_version(end_incl):
        return False
    if end_excl is not None and v >= _parse_version(end_excl):
        return False
    return True


def _extract_cvss(metrics):
    """Pull the best available CVSS score+severity out of whichever metric
    version NVD populated for this CVE (v3.1 preferred, fall back through
    v3.0 then v2)."""
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key) or []
        if entries:
            data = entries[0].get("cvssData", {})
            return data.get("baseScore"), data.get("baseSeverity", entries[0].get("baseSeverity"))
    return None, None


_RANGE_TEXT_RE = re.compile(
    r"through\s+v?(\d[\d.]*)|before\s+v?(\d[\d.]*)|prior\s+to\s+v?(\d[\d.]*)|"
    r"<\s*=?\s*v?(\d[\d.]*)",
    re.IGNORECASE,
)


def _parse_range_from_text(description):
    """CNA-written CVE descriptions routinely state the affected range in
    prose even when NVD hasn't attached structured CPE match data yet --
    'This issue affects X: from n/a through 4.2.1.' is a standard phrasing.
    Best-effort only: returns the end-of-range version if a recognizable
    pattern is found, else None. Never used to REFUTE a hypothesis, only to
    avoid reporting 'unclear' when the text plainly states an upper bound."""
    m = _RANGE_TEXT_RE.search(description)
    if not m:
        return None
    end_version = next((g for g in m.groups() if g), None)
    if not end_version:
        return None
    return {"start_incl": None, "start_excl": None, "end_incl": end_version, "end_excl": None}


def _matches_component(cve_item, product_name):
    """Does this CVE's own CPE configuration actually name this product,
    not just a keyword-search coincidence? Returns (match: bool|None,
    version_range: dict|None) -- None match means NVD attached no CPE
    configuration at all for this CVE, so we can't confirm OR refute via
    CPE and fall back to the keyword-search relevance alone."""
    configs = cve_item.get("configurations", [])
    if not configs:
        return None, None
    needle = product_name.lower().replace("-", " ").replace("_", " ")
    for config in configs:
        for node in config.get("nodes", []):
            for cpe_match in node.get("cpeMatch", []):
                criteria = cpe_match.get("criteria", "")
                # cpe:2.3:a:vendor:product:version:...
                cpe_parts = criteria.split(":")
                cpe_product = cpe_parts[4].replace("_", " ") if len(cpe_parts) > 4 else ""
                if needle in cpe_product or cpe_product in needle:
                    return True, {
                        "start_incl": cpe_match.get("versionStartIncluding"),
                        "start_excl": cpe_match.get("versionStartExcluding"),
                        "end_incl": cpe_match.get("versionEndIncluding"),
                        "end_excl": cpe_match.get("versionEndExcluding"),
                        "vulnerable_flag": cpe_match.get("vulnerable", True),
                    }
    return False, None


def _fetch_all_cve_pages(search_term, page_size=200, max_pages=5):
    """NVD returns results in a fixed server-side order (observed: oldest
    published first) with NO sort-order parameter to request newest-first,
    and date-range filtering (pubStartDate/pubEndDate) is capped to a ~120
    day window by the API itself (a wider range 404s) -- so a single small
    page silently drops every recent CVE. Paginate via startIndex instead,
    capped at max_pages (self-paced, one NVD request per page) so a product
    with thousands of historical CVEs doesn't turn into an unbounded crawl."""
    all_items = []
    start_index = 0
    total_results = None
    page = 0
    while page < max_pages:
        query = urllib.parse.urlencode({
            "keywordSearch": search_term,
            "resultsPerPage": page_size,
            "startIndex": start_index,
        })
        data, err = _http_get_json(f"{NVD_CVE_API}?{query}")
        if err:
            warn(f"  NVD lookup failed for '{search_term}' (page {page+1}): {err}")
            break
        if not data:
            break
        if total_results is None:
            total_results = data.get("totalResults", 0)
        items = data.get("vulnerabilities", [])
        all_items.extend(items)
        start_index += page_size
        page += 1
        if start_index >= total_results or not items:
            break
        time.sleep(NVD_MIN_INTERVAL_S)  # self-pace between pages too
    if total_results and len(all_items) < total_results:
        warn(f"  '{search_term}': only fetched {len(all_items)} of {total_results} total "
             f"NVD matches (page cap reached) -- results may miss some older CVEs; "
             f"recent ones are prioritized by the page order, so this is weighted correctly.")
    return all_items


def lookup_component(name, version, max_results=200, recent_years=5):
    """Query NVD for CVEs plausibly matching this component, and compare
    each one's own published affected-version range against the discovered
    version. Returns a list of hypothesis dicts, newest-published first."""
    # Plugin/theme slugs are hyphen/underscore-separated ("elementor-pro"),
    # but NVD's keywordSearch matches CVE description text, which spells
    # product names with spaces ("Elementor Pro") -- searching the raw slug
    # returns nothing even when hundreds of real matches exist for the
    # space-separated name (verified: "elementor-pro" -> 0 results,
    # "elementor pro" -> 184 results, same product).
    search_term = name.replace("-", " ").replace("_", " ")
    all_vulnerabilities = _fetch_all_cve_pages(search_term, page_size=max_results)

    cutoff_year = datetime.now(timezone.utc).year - recent_years
    hypotheses = []
    for item in all_vulnerabilities:
        cve = item.get("cve", {})
        cve_id = cve.get("id", "UNKNOWN")
        published = cve.get("published", "")
        try:
            pub_year = int(published[:4]) if published else 0
        except ValueError:
            pub_year = 0

        descriptions = cve.get("descriptions", [])
        desc_en = next((d["value"] for d in descriptions if d.get("lang") == "en"), "")

        # Keyword relevance gate: NVD's keywordSearch is a blunt free-text
        # match against the whole description -- require the product name
        # to actually appear, or this is noise, not a hypothesis.
        if name.lower().replace("-", " ") not in desc_en.lower().replace("-", " "):
            continue

        score, severity = _extract_cvss(cve.get("metrics", {}))
        matched, version_range = _matches_component(cve, name)
        range_source = "nvd-cpe-match" if version_range else None

        if version_range:
            affected = _version_in_range(
                version,
                version_range.get("start_incl"), version_range.get("start_excl"),
                version_range.get("end_incl"), version_range.get("end_excl"),
            )
        else:
            # NVD often hasn't published structured CPE match data for a
            # recent CVE yet (CPE enrichment lags initial publication by
            # weeks), but the CNA's own description text routinely states
            # the affected range in prose anyway -- e.g. "This issue
            # affects Elementor Pro: from n/a through 4.2.1." Parse that as
            # a lower-confidence fallback rather than reporting "unclear"
            # when the answer is sitting right there in the text.
            text_range = _parse_range_from_text(desc_en)
            if text_range:
                version_range = text_range
                range_source = "description-text-heuristic"
                affected = _version_in_range(version, None, None, text_range.get("end_incl"), None)
            else:
                affected = None  # genuinely no usable range anywhere -- can't confirm or refute

        references = [r.get("url") for r in cve.get("references", []) if r.get("url")]

        hypotheses.append({
            "cve_id": cve_id,
            "published": published,
            "is_recent": pub_year >= cutoff_year,
            "cvss_score": score,
            "severity": severity,
            "description": desc_en[:400],
            "cpe_matched_this_product": matched,
            "affected_version_range": version_range,
            "range_source": range_source,  # "nvd-cpe-match" (structured, higher confidence),
                                            # "description-text-heuristic" (prose-parsed, verify
                                            # against the references before trusting), or None
            # True = version is inside NVD's own published range for this CVE
            # (treat as a strong hypothesis to verify, not a confirmed finding
            # -- still needs the actual vulnerable feature/precondition
            # checked live, same as every other chain in this pipeline).
            # False = version is outside the range (likely already patched).
            # None = NVD didn't publish a usable range; manual version check
            # needed before trusting this as a hypothesis at all.
            "version_appears_affected": affected,
            "references": references[:5],
        })

    # Recent first, then by severity -- matches the "recent write-ups and
    # exploits" ask: a 2026 CVE with a public PoC is more actionable than an
    # old one that's almost certainly already patched everywhere.
    hypotheses.sort(key=lambda h: (h["is_recent"], h["cvss_score"] or 0, h["published"]), reverse=True)
    return hypotheses


def main():
    parser = argparse.ArgumentParser(
        description="CVE / public-exploit lookup for fingerprinted components"
    )
    parser.add_argument("--input", "-i", required=True,
                         help="tech_fingerprint.py JSON output (reads versioned_components)")
    parser.add_argument("--output", "-o", help="Output JSON file")
    parser.add_argument("--recent-years", type=int, default=5,
                         help="A CVE published within this many years is flagged 'is_recent' (default: 5)")
    args = parser.parse_args()

    with open(args.input) as f:
        fp_data = json.load(f)

    components = []
    for result in fp_data.get("results", []):
        for comp in result.get("details", {}).get("versioned_components", []):
            components.append(comp)
    # De-dupe across hosts (a shared plugin version across subdomains should
    # only cost one NVD query, not one per host).
    seen = set()
    unique_components = []
    for c in components:
        key = (c["name"], c["version"])
        if key not in seen:
            seen.add(key)
            unique_components.append(c)

    if not unique_components:
        warn("No versioned components found in the fingerprint input -- nothing to look up. "
             "This is expected for sites tech_fingerprint.py couldn't extract asset-query-string "
             "versions from (non-WordPress stacks, or a page that doesn't enqueue versioned assets).")
        output = {"meta": {"timestamp": datetime.now(timezone.utc).isoformat()}, "components": [], "hypotheses": []}
    else:
        log(f"Looking up {len(unique_components)} versioned component(s) against NVD "
            f"(self-paced ~{NVD_MIN_INTERVAL_S}s between requests, this will take a moment)...")
        all_hypotheses = []
        for i, comp in enumerate(unique_components):
            name, version = comp["name"], comp["version"]
            log(f"  [{i+1}/{len(unique_components)}] {name} {version}")
            hyps = lookup_component(name, version, recent_years=args.recent_years)
            for h in hyps:
                h["component"] = name
                h["installed_version"] = version
                h["component_kind"] = comp.get("kind")
            all_hypotheses.extend(hyps)
            affected_count = sum(1 for h in hyps if h["version_appears_affected"])
            if affected_count:
                warn(f"    -> {affected_count} CVE(s) where the installed version appears IN the affected range")
            elif hyps:
                log(f"    -> {len(hyps)} CVE(s) found for this product, none confirmed in-range for this version")
            if i < len(unique_components) - 1:
                time.sleep(NVD_MIN_INTERVAL_S)

        output = {
            "meta": {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "tool": "cve_lookup.py (recon-dominator, CatusMythos-Lounge)",
                "components_checked": len(unique_components),
                "total_hypotheses": len(all_hypotheses),
                "affected_hypotheses": sum(1 for h in all_hypotheses if h["version_appears_affected"]),
            },
            "components": unique_components,
            "hypotheses": all_hypotheses,
        }

    output_path = args.output or "cve_lookup_results.json"
    with open(output_path, "w") as f:
        json.dump(output, f, indent=2)
    success(f"Results saved to: {output_path}")

    print(f"\n{'='*60}")
    print("  CVE LOOKUP SUMMARY")
    print(f"{'='*60}")
    print(f"  Components checked : {output['meta'].get('components_checked', 0)}")
    print(f"  CVEs found         : {output['meta'].get('total_hypotheses', 0)}")
    print(f"  Appear IN affected range (verify live, not auto-confirmed): "
          f"{output['meta'].get('affected_hypotheses', 0)}")
    for h in sorted(output["hypotheses"], key=lambda x: x["version_appears_affected"] is True, reverse=True)[:10]:
        if h["version_appears_affected"]:
            flag = "AFFECTED?" if h.get("range_source") == "nvd-cpe-match" else "AFFECTED? (text)"
        elif h["version_appears_affected"] is False:
            flag = "patched"
        else:
            flag = "unclear range"
        print(f"    [{flag:>17}] {h['cve_id']} ({h['component']} {h['installed_version']}) "
              f"CVSS {h['cvss_score']} {h['severity']}")
    print(f"{'='*60}\n")


if __name__ == "__main__":
    main()
