# JavaScript-Bundle and Source-Map Mining for Hidden API/Endpoint Discovery

## What are the actual, specific regex patterns used by tools like SecretFinder, LinkFinder, JSFinder, GoLinkFinder (and the AST-based successor, jsluice/Katana) to extract URLs/endpoints/paths from raw JS text?

### Takeaway
LinkFinder's single regex (written by Gerben Javado in 2017) is reused **verbatim or near-verbatim** by JSFinder and GoLinkFinder — there is essentially one "classic" endpoint-extraction regex in the open-source ecosystem, not many competing ones. SecretFinder reuses the same tool scaffold but swaps in a completely different dict of ~30 secret/credential regexes (it does not do generic endpoint-finding itself). The newer generation (jsluice, which powers Katana's `-jsluice` mode) abandoned regex entirely in favor of real tree-sitter AST parsing specifically because regex cannot reliably identify *which* call is a `fetch`/`axios`/XHR call versus an unrelated string — its matcher logic is nonetheless directly portable to a stdlib-only heuristic.

### Cited Findings
- **LinkFinder's exact regex** (verified directly from source, `linkfinder.py`), compiled with Python's `re.VERBOSE` flag:
  ```python
  regex_str = r"""

    (?:"|')                               # Start newline delimiter

    (
      ((?:[a-zA-Z]{1,10}://|//)           # Match a scheme [a-Z]*1-10 or //
      [^"'/]{1,}\.                        # Match a domainname (any character + dot)
      [a-zA-Z]{2,}[^"']{0,})              # The domainextension and/or path

      |

      ((?:/|\.\./|\./)                    # Start with /,../,./
      [^"'><,;| *()(%%$^/\\\[\]]          # Next character can't be...
      [^"'><,;|()]{1,})                   # Rest of the characters can't be

      |

      ([a-zA-Z0-9_\-/]{1,}/               # Relative endpoint with /
      [a-zA-Z0-9_\-/.]{1,}                # Resource name
      \.(?:[a-zA-Z]{1,4}|action)          # Rest + extension (length 1-4 or action)
      (?:[\?|#][^"|']{0,}|))              # ? or # mark with parameters

      |

      ([a-zA-Z0-9_\-/]{1,}/               # REST API (no extension) with /
      [a-zA-Z0-9_\-/]{3,}                 # Proper REST endpoints usually have 3+ chars
      (?:[\?|#][^"|']{0,}|))              # ? or # mark with parameters

      |

      ([a-zA-Z0-9_\-]{1,}                 # filename
      \.(?:php|asp|aspx|jsp|json|
           action|html|js|txt|xml)        # . + extension
      (?:[\?|#][^"|']{0,}|))              # ? or # mark with parameters

    )

    (?:"|')                               # End newline delimiter

  """
  ```
  It has 5 alternatives inside one capture group: (1) absolute/scheme-relative URLs, (2) relative paths starting `/`, `../`, `./`, (3) extensioned relative endpoints like `api/v1/user.json`, (4) extension-less REST paths with 3+ char segments, (5) bare filenames with a known web extension. — [LinkFinder source](https://github.com/GerbenJavado/LinkFinder/blob/master/linkfinder.py)
- **JSFinder copies this regex almost verbatim** but with two concrete deltas confirmed by diffing the fetched source against LinkFinder's: (a) it drops LinkFinder's 4th alternative entirely (the "REST API, no extension, 3+ chars" branch), leaving only 4 alternatives; (b) in the "relative endpoint with /" branch it narrows the resource-name character class from `[a-zA-Z0-9_\-/.]{1,}` to `[a-zA-Z0-9_\-/]{1,}` (removing the literal dot) and changes the trailing `?`-or-`#` group from `[\?|#]` to `[\?|/]`. JSFinder's code even credits the source: `# Regular expression comes from https://github.com/GerbenJavado/LinkFinder`. It is compiled the same way: `pattern = re.compile(pattern_raw, re.VERBOSE)`. — [JSFinder source](https://github.com/Threezh1/JSFinder/blob/master/JSFinder.py)
- **GoLinkFinder's regex is LinkFinder's *original* 5-alternative pattern** (including the REST-no-extension branch), just flattened into one line with comments/whitespace stripped for Go's `regexp` (RE2) engine, with the comment `// regex foo from https://github.com/GerbenJavado/LinkFinder` directly above it:
  ```go
  const regexStr = `(?:"|')(((?:[a-zA-Z]{1,10}://|//)[^"'/]{1,}\.[a-zA-Z]{2,}[^"']{0,})|((?:/|\.\./|\./)[^"'><,;| *()(%%$^/\\\[\]][^"'><,;|()]{1,})|([a-zA-Z0-9_\-/]{1,}/[a-zA-Z0-9_\-/]{1,}\.(?:[a-zA-Z]{1,4}|action)(?:[\?|#][^"|']{0,}|))|([a-zA-Z0-9_\-/]{1,}/[a-zA-Z0-9_\-/]{3,}(?:[\?|#][^"|']{0,}|))|([a-zA-Z0-9_\-]{1,}\.(?:php|asp|aspx|jsp|json|action|html|js|txt|xml)(?:[\?|#][^"|']{0,}|)))(?:"|')`
  ```
  This pattern uses only basic regex constructs (char classes, alternation, quantifiers, no backreferences/lookaround), which is exactly why it ports cleanly between Python's `re` and Go's RE2 without any syntax changes — the same is true porting it into Python's stdlib `re` unmodified. — [GoLinkFinder source](https://github.com/0xsha/GoLinkFinder/blob/master/GoLinkFinder.go)
- GoLinkFinder's post-processing (`extractUrlFromJS`) strips quote characters, discards matches under 5 chars, and resolves scheme-relative (`//host/...`) and root-relative (`/path`) matches against the base URL — a cleanup pass worth replicating after the regex match, not folded into the regex itself. — [GoLinkFinder source](https://github.com/0xsha/GoLinkFinder/blob/master/GoLinkFinder.go)
- **SecretFinder does not have its own generic endpoint/URL regex.** Its `_regex` dict (verified from source) is exclusively secret/credential patterns reused as a flat Python dict, e.g.:
  ```python
  _regex = {
      'google_api'     : r'AIza[0-9A-Za-z-_]{35}',
      'firebase'  : r'AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}',
      'google_captcha' : r'6L[0-9A-Za-z-_]{38}|^6[0-9a-zA-Z_-]{39}$',
      'google_oauth'   : r'ya29\.[0-9A-Za-z\-_]+',
      'amazon_aws_access_key_id' : r'A[SK]IA[0-9A-Z]{16}',
      'amazon_aws_url' : r's3\.amazonaws.com[/]+|[a-zA-Z0-9_-]*\.s3\.amazonaws.com',
      'authorization_basic' : r'basic [a-zA-Z0-9=:_\+\/-]{5,100}',
      'authorization_bearer' : r'bearer [a-zA-Z0-9_\-\.=:_\+\/]{5,100}',
      'authorization_api' : r'api[key|_key|\s+]+[a-zA-Z0-9_\-]{5,100}',
      'twilio_api_key' : r'SK[0-9a-fA-F]{32}',
      'stripe_standard_api' : r'sk_live_[0-9a-zA-Z]{24}',
      'json_web_token' : r'ey[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*$',
      'slack_token' : r"\"api_token\":\"(xox[a-zA-Z]-[a-zA-Z0-9-]+)\"",
      'SSH_privKey' : r"([-]+BEGIN [^\s]+ PRIVATE KEY[-]+[\s]*[^-]*[-]+END [^\s]+ PRIVATE KEY[-]+)",
      'possible_Creds' : r"(?i)(password\s*[`=:\"]+\s*[^\s]+|password is\s*[`=:\"]*\s*[^\s]+|pwd\s*[`=:\"]*\s*[^\s]+|passwd\s*[`=:\"]+\s*[^\s]+)",
  }
  r = re.compile(regex[1], re.VERBOSE | re.I)
  ```
  (30 entries total in the dict, spanning Google/Firebase/AWS/Facebook/Mailgun/Twilio/PayPal/Square/Stripe/GitHub/SSH/PGP/JWT/Slack/Heroku keys plus generic `Authorization:` header and hardcoded-password patterns.) For URL discovery, SecretFinder reuses the same "crawl `<script src>` from HTML, download JS, regex the content" scaffold as LinkFinder, but applies this secrets dict instead of an endpoint regex. — [SecretFinder source](https://github.com/m4ll0k/SecretFinder/blob/master/SecretFinder.py)
- **Katana's underlying JS engine, `jsluice` (BishopFox), does not use regex at all for call matching** — it parses JS into a real syntax tree (tree-sitter) and queries it. Its default URL matchers, in priority order, are: `matchXHR()` (matches calls ending in `.open` whose first argument is a valid HTTP-method string literal, then separately scans sibling `.setRequestHeader()` calls in the same scope), `matchJQuery()` (matches `$.get`/`$.post`/`$.ajax`/`jQuery.get`/`jQuery.post`/`jQuery.ajax`, handling 3 distinct call-signature shapes), a `location`/`this.url`/`*.href`/`*.src`/`*.location` assignment matcher, a `location.replace(...)` matcher, a `window.open(...)` matcher, a `fetch(url, init)` matcher (pulls `method` and `headers` out of the second-argument object), a catch-all "other function calls with a URL-like first argument" matcher, and finally a last-resort "any string literal" matcher. — [jsluice url-matchers.go](https://github.com/BishopFox/jsluice/blob/main/url-matchers.go), [url-match-jquery.go](https://github.com/BishopFox/jsluice/blob/main/url-match-jquery.go), [url-match-xhr.go](https://github.com/BishopFox/jsluice/blob/main/url-match-xhr.go)
- jsluice's last-resort filter, `MaybeURL(string) bool`, is pure string logic (no AST needed), verified verbatim from source:
  ```go
  func MaybeURL(in string) bool {
      if !strings.ContainsAny(in, "/?.") { return false }
      if strings.ContainsAny(in, " ()!<>'\"`{}^$,") { return false }
      if strings.HasPrefix(in, "/") { return true }
      u, err := url.Parse(in)
      if err != nil { return false }
      if u.Scheme != "" {
          s := strings.ToLower(u.Scheme)
          if s != "http" && s != "https" { return false }
      }
      if len(strings.Split(u.Hostname(), ".")) > 1 { return true }
      for _, vv := range u.Query() {
          if len(vv) > 0 && len(vv[0]) > 0 { return true }
      }
      if !strings.ContainsAny(u.Path, ".") { return false }
      parts := strings.Split(u.Path, ".")
      ext := parts[len(parts)-1]
      return fileExtensions.Contains(ext) // {js,css,html,htm,xhtml,xlsx,xls,docx,doc,pdf,rss,xml,php,phtml,asp,aspx,asmx,ashx,cgi,pl,rb,py,do,jsp,jspa,json,jsonp,txt}
  }
  ```
  — [jsluice maybeurl.go](https://github.com/BishopFox/jsluice/blob/main/maybeurl.go)

### Inferences
- Because `MaybeURL` operates on an already-isolated string (not on tree structure), it ports directly to Python stdlib and is the natural **precision filter** to run after a broad LinkFinder-style regex sweep, closing the gap between "classic regex tool" and "AST tool" approaches:
  ```python
  import urllib.parse

  FILE_EXTENSIONS = {
      "js","css","html","htm","xhtml","xlsx","xls","docx","doc","pdf","rss","xml",
      "php","phtml","asp","aspx","asmx","ashx","cgi","pl","rb","py","do","jsp",
      "jspa","json","jsonp","txt",
  }

  def maybe_url(s: str) -> bool:
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
  ```
- Ready-to-paste LinkFinder/JSFinder/GoLinkFinder regex for Python stdlib (use the original 5-alternative LinkFinder/GoLinkFinder version, since it is the strict superset):
  ```python
  import re

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
  # usage: [m.group(1) for m in ENDPOINT_REGEX.finditer(js_text)]
  ```
  Note: the original tools' char class `[^"'><,;| *()(%%$^/\\\[\]]` contains a doubled `%%` that is a literal artifact of the source (not a format-string escape — there is no `%`-formatting applied to this string in any of the three codebases); when porting, a single `%` is the correct literal-percent equivalent inside a plain (non-%-formatted) raw string, so `%%` can be safely collapsed to `%` as shown above.
- Running the regex on **raw minified JS directly works** — LinkFinder's own `"|'` delimiter anchoring does not require line breaks or beautification; the tools' use of `jsbeautifier` before matching is purely to make the *context/output* readable, not a functional prerequisite for the match itself. A zero-dependency tool can skip beautification entirely and regex the minified text as-is.
- SecretFinder's `authorization_api` pattern (`r'api[key|_key|\s+]+[a-zA-Z0-9_\-]{5,100}'`) is actually a parameter-name-adjacent credential grep (matches things like `apikey=...`, `api_key: ...`) rather than a URL-path finder — useful to cite under "parameter names" discovery but it is a character-class bug in the original (the `[key|_key|\s+]` is a character class, not an alternation, so it just matches any of the characters k,e,y,_,|,\s,+ one-or-more times) — worth flagging if replicating it, since it will over-match.

### Gaps
- Could not find a GoLinkFinder-equivalent set of comments justifying *why* the REST-no-extension branch (3+ char segments) exists versus being dropped in JSFinder; JSFinder's author gives no changelog note for the deltas, so the rationale (likely false-positive reduction) is inferred, not confirmed.
- Did not locate source for "Katana" itself invoking jsluice's exact regex fallback path (Katana wraps jsluice as a library/mode rather than containing its own copy of these matchers) — the matcher code cited is jsluice's, which Katana documentation references as its JS-analysis engine, but line-level confirmation inside Katana's own repo was not fetched in this pass.

---

## How does source-map (.map file) parsing work to recover original, unminified source and file structure from a minified bundle — what is the JSON structure, and what's the simplest stdlib-only extraction method?

### Takeaway
A source map is one JSON object (`version`, `file`, `sourceRoot`, `sources`, `sourcesContent`, `names`, `mappings`, optionally `ignoreList`/`sections`); recovering the **original file paths and original source text requires zero decoding of the `mappings` field** — a plain `json.load()` plus reading the parallel `sources`/`sourcesContent` arrays is the entire extraction, which is exactly why this is a stdlib-trivial, high-value recon technique.

### Cited Findings
- The current living Source Map specification is maintained at `tc39.es/source-map`, standardized as **ECMA-426** (1st edition, published December 2024); the format's version field is now hard-coded to `3` rather than incrementing further. — [ECMA-426](https://426.ecma-international.org/1.0/index.html), [tc39.es/source-map](https://tc39.es/source-map)
- Top-level fields confirmed across the spec listing and schema: `version`, `file`, `sources`, `names`, and `mappings` are present, with `sourcesContent` and `ignoreList` as documented optional fields; key order is not enforced by the format. — [sourcemap-v3 JSON schema](https://www.schemastore.org/sourcemap-v3.json), search of tc39/ECMA-426 listings
- `sourcesContent` is an explicitly optional field that carries the **original source text** so the original files don't need to be separately hosted; combined with a data-URI reference it can make a map fully self-contained. `mappings` is a string holding the actual encoded position data. "Indexed" source maps use a `sections` array instead of top-level `mappings`, where each section has an `{offset: {line, column}, map: {...}}` structure, sorted by position with no overlap. — search synthesis of tc39.es/source-map / ECMA-426 / schemastore.org (exact verbatim spec prose was not retrievable — the fetch of `tc39.es/source-map` returned only a redirect notice to `tc39.es/ecma426/`, so these field semantics are corroborated across two independent lookups rather than quoted directly from spec text)
- `mappings` segment structure (same corroboration caveat as above): generated-lines are separated by `;`, segments within a line by `,`; each segment is a sequence of Base64-VLQ-encoded integers meaning, in order: **generated column** (relative to previous segment, same line), **source-file index** (relative, into `sources`), **original line** (relative), **original column** (relative), **name index** (relative, into `names`) — fields 2-5 are optional per segment. Base64-VLQ uses the alphabet `A-Za-z0-9+/`, 5 low bits per character carry value, the 6th (high) bit is a continuation flag, and the lowest bit of the *first* chunk of a value is a sign bit (1 = negative).
- Real-world convention (implicit in how browsers/DevTools locate a map, consistent with the spec's purpose): a JS file opts into source-map loading via a trailing comment `//# sourceMappingURL=<path-or-data-uri>`, and when no such comment is found, appending `.map` to the bundle's own URL (`app.min.js` → `app.min.js.map`) is the standard fallback convention tooling relies on.

### Inferences
- Because the attacker/researcher goal is "recover original filenames and source text," not "map a specific minified line back to source," **the VLQ decode of `mappings` is unnecessary overhead** for this recon use case — `sources` (array of original paths — itself an attack-surface/directory-structure leak) and `sourcesContent` (parallel array of full original file text) are read directly:
  ```python
  import json
  import re
  import urllib.request

  def find_sourcemap_url(js_text: str, js_url: str) -> str:
      m = re.search(r"//[#@]\s*sourceMappingURL=([^\s'\"]+)", js_text)
      if m:
          return urllib.parse.urljoin(js_url, m.group(1))
      return js_url + ".map"  # fallback convention

  def recover_sources(map_url: str) -> dict:
      req = urllib.request.Request(map_url, headers={"User-Agent": "Mozilla/5.0"})
      with urllib.request.urlopen(req, timeout=15) as resp:
          data = json.loads(resp.read().decode("utf-8", "replace"))

      sources = data.get("sources", [])
      contents = data.get("sourcesContent", [])
      root = data.get("sourceRoot", "")

      recovered = {}
      for i, src_path in enumerate(sources):
          full_path = (root.rstrip("/") + "/" + src_path) if root else src_path
          text = contents[i] if i < len(contents) else None
          recovered[full_path] = text  # None if sourcesContent omitted for this entry
      return recovered  # dict of {original_file_path: original_source_text_or_None}
  ```
  Even when `sourcesContent` is absent (map references sources but doesn't embed them), the `sources` array alone discloses the **entire original module/directory tree** — component names, internal package paths, build-tool-specific folders (e.g. `webpack://`, `node_modules/`), which is high-value recon even with no text recovered.
- For cases that genuinely need line-accurate mapping (not required for the stated objective, but a faithful stdlib-only decoder is still possible without a sourcemap library — `mappings` is plain ASCII text):
  ```python
  B64_VLQ_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
  B64_VLQ_INDEX = {c: i for i, c in enumerate(B64_VLQ_CHARS)}

  def decode_vlq_segment(segment: str):
      values, cur, shift = [], 0, 0
      for ch in segment:
          digit = B64_VLQ_INDEX[ch]
          cont = digit & 0b100000
          digit &= 0b011111
          cur += digit << shift
          if cont:
              shift += 5
              continue
          sign = -1 if (cur & 1) else 1
          values.append(sign * (cur >> 1))
          cur, shift = 0, 0
      return values

  def decode_mappings(mappings: str):
      # returns list of lines -> list of [genCol, srcIdx, origLine, origCol, nameIdx] (cumulative)
      lines, gen_col, src_idx, orig_line, orig_col, name_idx = [], 0, 0, 0, 0, 0
      for line in mappings.split(";"):
          gen_col = 0
          segs = []
          for raw_seg in line.split(",") if line else []:
              if not raw_seg:
                  continue
              fields = decode_vlq_segment(raw_seg)
              gen_col += fields[0]
              row = [gen_col]
              if len(fields) > 1:
                  src_idx += fields[1]; orig_line += fields[2]; orig_col += fields[3]
                  row += [src_idx, orig_line, orig_col]
                  if len(fields) > 4:
                      name_idx += fields[4]
                      row.append(name_idx)
              segs.append(row)
          lines.append(segs)
      return lines
  ```
  This decoder is derived from the general, long-stable Base64-VLQ scheme shared across source-map tooling rather than copy-verified against spec prose in this research pass (see the sourcing caveat above) — treat it as "should be cross-checked against `tc39.es/source-map`/ECMA-426 before shipping," not as a verbatim-cited quote.
- A practical **hidden-chunk discovery technique** follows directly from `sources`: source maps for bundled apps often list sibling modules/routes never linked from any `<script>` tag on the page actually rendered (e.g. an admin-only React route's component file appears in `vendor.js.map`'s `sources` even if `/admin` is never linked) — enumerating every `.map`'s `sources` array across every discovered JS chunk is a broader recon net than reading the chunks' own code.

### Gaps
- Could not retrieve verbatim spec text for the exact field-by-field `mappings` segment semantics (the `tc39.es/source-map` fetch resolved only to a redirect notice); the description above is corroborated by two independent lookups (general web search plus a second fetch attempt) but is not a direct quotation — an implementer should verify against `https://tc39.es/ecma426/` directly before treating the VLQ decoder as authoritative for edge cases (e.g. the newer `ignoreList`/`sections` index-map handling).
- Did not find data on how commonly production deployments still ship `sourcesContent` populated vs. omitted (i.e., what fraction of real-world exposed `.map` files actually contain recoverable full source text versus only path lists) — flagged as a quantifiable gap a report-writer may want from other researchers' findings (e.g. the escape.tech stat below covers *map exposure* broadly, not specifically `sourcesContent` presence).

---

## How do webpack/Next.js/Vite-bundled applications structure chunk files so you can systematically enumerate all chunks rather than only what's linked from HTML `<script>` tags?

### Takeaway
Next.js and Vite both expose a **static, fetchable JSON-ish manifest** that lists every chunk (and, for Next.js, maps each page route to its required chunks) — Vite's is literally JSON and trivially stdlib-parseable; Next.js's is a JS-literal assignment that needs a short regex-strip before `json.loads` works. Plain webpack has no single standardized runtime global name for its JSONP chunk-registration array across versions/configs, so full enumeration without executing the runtime is a best-effort static approximation, not a guaranteed-complete technique.

### Cited Findings
- **Next.js build manifest:** community tools (`nextr4y`, `thankunext`, `njsdump`) all operate on the same mechanism: a file at `_next/static/<buildId>/_buildManifest.js` sets a global (`self.__BUILD_MANIFEST = {...}`) mapping each page route to the array of chunk files it needs; `thankunext` specifically works by checking whether a discovered URL ends in `buildManifest.js` and evaluating the script (in a headless browser) to read `self.__BUILD_MANIFEST`, while `njsdump` is a shell script that dumps routes/pages directly from a given manifest URL. The build manifest is described as a static client-side asset reachable by anyone who can load the page. — [thankunext](https://github.com/c3l3si4n/thankunext), [njsdump](https://awesome.ecosyste.ms/projects/github.com%2Fcosad3s%2Fnjsdump)
- **Vite build manifest** (`.vite/manifest.json`, written when `build.manifest: true` is set) has a documented `Record<name, ManifestChunk>` structure: entry and dynamic-entry chunks are keyed by their source path relative to the project root; non-entry chunks are keyed by the generated file's base name prefixed with `_`. Each chunk object carries the generated `file`, whether it `isEntry`, a `css` array of associated stylesheet files, a static `imports` array (other manifest keys this chunk depends on), and a `dynamicImports` array (manifest keys for lazily-loaded chunks). The docs' own worked example walks a chunk's `imports` recursively to collect every CSS file needed for an entry point. — [Vite backend integration guide](https://vite.dev/guide/backend-integration)
- **Plain webpack JSONP chunk loading:** webpack's runtime installs a callback (seen historically as `webpackJsonpCallback`) that receives a chunk ID, its modules, and an optional runtime function, and merges them into the module table; in older builds this callback hung off a global array commonly named `webpackJsonp`, but naming is **not stable across versions/configs** — one cited example shows different environments ending up with a differently-named or even multiple such global arrays, and newer tooling (e.g. Rspack, which mirrors webpack's own evolution) documents `output.chunkLoading: 'jsonp'` with an `'array-push'` format rather than a single fixed global name. A dedicated `chunk-manifest-webpack-plugin` exists specifically to export a chunk-id → asset-file JSON map as a separate, staticaly-readable file, implying this mapping is *not* reliably readable from the runtime chunk by default. — search synthesis citing the Rspack jsonp-template-plugin docs and `chunk-manifest-webpack-plugin` project page

### Inferences
- **Next.js, stdlib-only enumeration approach**: fetch the HTML once, recover the `buildId` from either the embedded `<script id="__NEXT_DATA__" type="application/json">{"buildId":"...",...}</script>` blob or from any observed `/_next/static/<buildId>/_buildManifest.js` script-tag path, then fetch that manifest file and strip the JS-assignment wrapper before `json.loads`:
  ```python
  import re, json, urllib.request

  def get_next_build_id(html: str) -> str | None:
      m = re.search(r'/_next/static/([^/"\']+)/_buildManifest\.js', html)
      if m:
          return m.group(1)
      m = re.search(r'"buildId"\s*:\s*"([^"]+)"', html)
      return m.group(1) if m else None

  def fetch_build_manifest(base_url: str, build_id: str) -> dict:
      url = f"{base_url.rstrip('/')}/_next/static/{build_id}/_buildManifest.js"
      req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
      with urllib.request.urlopen(req, timeout=15) as resp:
          text = resp.read().decode("utf-8", "replace")
      # text looks like: self.__BUILD_MANIFEST = {"/route":["static/chunks/x.js", ...], ...};self.__BUILD_MANIFEST_CB && ...
      m = re.search(r"__BUILD_MANIFEST\s*=\s*(\{.*?\})\s*[;,]", text, re.DOTALL)
      if not m:
          return {}
      return json.loads(m.group(1))  # {route: [chunk_paths...]}
  ```
  Every key of the resulting dict is a **client-side route the application knows about**, independent of whether that route is linked anywhere in the rendered HTML — this is the core value of the manifest for recon (hidden/unlinked pages, admin routes, feature-flagged routes still show up here as long as they're part of the current build).
- **Vite, stdlib-only enumeration**: no regex-stripping needed at all — `.vite/manifest.json` (commonly reachable under the site's asset base path, e.g. `/assets/manifest.json`, `/manifest.json`, or `/.vite/manifest.json` depending on `build.outDir`/`base` config) is already strict JSON:
  ```python
  import json, urllib.request

  def enumerate_vite_chunks(manifest_url: str) -> dict:
      req = urllib.request.Request(manifest_url, headers={"User-Agent": "Mozilla/5.0"})
      with urllib.request.urlopen(req, timeout=15) as resp:
          manifest = json.loads(resp.read().decode("utf-8", "replace"))

      all_files, dynamic_entry_points = set(), set()
      for key, chunk in manifest.items():
          all_files.add(chunk.get("file"))
          for dyn_key in chunk.get("dynamicImports", []):
              dynamic_entry_points.add(dyn_key)  # often correspond 1:1 to lazy-loaded routes/features
      return {"all_files": all_files, "dynamic_entry_points": dynamic_entry_points}
  ```
  `dynamicImports` is specifically worth flagging separately from `imports`: in an SPA, dynamic imports are overwhelmingly how route-level code-splitting is implemented, so this array is close to a direct route list, analogous to Next.js's build manifest but derived from static-dependency data instead of an explicit route-keyed object.
- **Plain webpack, best-effort stdlib approximation (no runtime execution available, so this is explicitly an approximation, not complete enumeration)**: since there is no single stable global name to read values from without executing the JS engine, the practical stdlib-only fallback is static text-mining of whichever "runtime"/entry chunk is reachable (commonly named `runtime*.js`, `webpack-runtime*.js`, or bundled into `main*.js`) for the **chunk-id-to-hash object literal** webpack embeds for its own `jsonpScriptSrc`/filename-template logic, e.g.:
  ```python
  import re, json

  # id:hash object literal webpack emits for chunk filename resolution, e.g. {53:"a1b2c3d4"}
  CHUNKMAP_RE = re.compile(r'\{\s*(?:\d+\s*:\s*"[a-f0-9]+"\s*,?\s*)+\}')

  def extract_chunk_hash_map(runtime_js: str) -> dict:
      m = CHUNKMAP_RE.search(runtime_js)
      if not m:
          return {}
      # object literal with bare numeric keys isn't valid JSON; quote the keys first
      quoted = re.sub(r'(?<=[{,])\s*(\d+)\s*:', r'"\1":', m.group(0))
      return json.loads(quoted)  # {chunk_id: hash}
  ```
  Combined with a separately regex-extracted filename template (look for a nearby template literal or string concatenation containing `.js"` / `` `.chunk.js` `` next to a `+` or `${`), this reconstructs probable chunk URLs — but this is explicitly the "real JS engine needed to be fully correct" case the task asked to flag: webpack's exact runtime chunk-loading logic (including any custom `chunkFilename` format, hashing scheme, or `publicPath` computed at runtime) can only be guaranteed correct by executing the bundle's own runtime chunk in a JS engine; the regex above is a heuristic that works on common/default configurations and will miss custom setups.
- Across all three bundlers, the one **universal, zero-assumption stdlib baseline** is still worth stating explicitly: recursively crawl every `<script src>` **and** every string in already-fetched JS that matches a chunk-looking filename pattern (e.g. `r'["\']([\w./-]+?\.[0-9a-f]{8,20}\.(?:js|css))["\']'` for content-hashed filenames, or `r'["\'](/[\w./-]*chunks?/[\w.-]+\.js)["\']'` for path-based chunk directories like Next.js's `_next/static/chunks/`), then recurse into each newly found file — this catches chunks referenced only from *within* other JS (dynamic `import()` targets, lazy-loaded route bundles) that never appear as a top-level HTML `<script>` tag, regardless of which bundler produced them.

### Gaps
- Did not confirm a single current (2025/2026) canonical global variable name for webpack's JSONP chunk array (e.g. whether `webpackChunk_N_E`-style per-project names are now the default) — search results explicitly stated naming varies by version/config and recommended checking the specific build's runtime output rather than assuming a fixed name; a report-writer should treat any single hardcoded global name as unreliable without target-specific verification.
- Did not verify the default/typical public URL path at which Vite's `.vite/manifest.json` is actually served in production (vs. only present in the build output directory pre-deployment) — this depends on server/framework integration (examples found were for backend-template integration, not a generic "is it always web-reachable" guarantee), so enumerate by trying common paths rather than assuming one fixed location.
- Did not find Next.js App Router (vs. Pages Router) specifics — the `_buildManifest.js`/`__BUILD_MANIFEST` mechanism described is documented/tooled primarily around the older Pages Router; App Router route discovery may use a different manifest (e.g. server-reference/action manifests) not covered in this pass.

---

## What are documented real bug-bounty writeups (2024-2026) where mining JS bundles revealed an API route or parameter that led to a vulnerability finding?

### Takeaway
Confirmed, well-sourced real-world cases center on **exposed source maps leaking hardcoded secrets/credentials** (the clearest, most repeatable pattern), with one platform vendor reporting this is widespread (found in 70% of scanned organizations) and one high-bounty individual case ($25,000) with full technical detail; several other candidate "writeups" turned out on inspection to be practice-lab scenarios or low-credibility content-farm posts and are excluded/flagged rather than cited as real findings.

### Cited Findings
- **$25,000 bounty via Stripe keys recovered from a source map** (platformsecurity.com, individual researcher writeup): after automated secret-scanners missed the issue, the researcher manually located a `.js.map` file for a minified production bundle, used a tool called **SourceMapper** to reconstruct the original readable source tree from the map, and manually read through the reconstructed files until finding a configuration module with hardcoded **Stripe live-mode publishable and secret keys**. They verified impact with a read-only call to Stripe's balance endpoint, which showed roughly **$1.76 million** in available funds accessible via the leaked secret key. The company paid a **$25,000** bounty. — [Little Bug, Big Impact: $25k bounty](https://platformsecurity.com/blog/little-bug-big-impact-25k-bounty)
- **Apple App Store source-map leak** (escape.tech vendor research post): independent researcher **rxliuli** opened browser DevTools against `apps.apple.com`, noticed source-map files were loading, and used a "Save All Resources" Chrome extension to pull down and reconstruct the full original front-end source — recovering complete **Svelte/TypeScript source code, state-management logic, UI components, API-integration code, and routing configuration**. The reconstructed repository was reportedly forked 8,000+ times on GitHub before takedown. Separately, Escape (an API/DAST security vendor) states its own scanning found this exposure class — a live JS file referencing a source map, with the `.map` itself fetchable unauthenticated — in **70% of the organizations** it scanned (caveat: this is Escape's own customer base, not an industry-wide sample), rating it low severity *as an info-disclosure category* but explicitly noting "in some cases, an exposed sourcemap can even lead to account takeover" depending on what's inside. — [Apple's App Store Source Map Leak](https://escape.tech/blog/apple-app-store-source-map-leak/)

### Inferences
- Both confirmed cases follow an identical three-step pattern that generalizes well as the "implementation-ready" technique to document: (1) **find** the map — either via the `//# sourceMappingURL=` comment or the `.js` → `.js.map` naming convention; (2) **reconstruct** — pull `sources`/`sourcesContent` (tool-assisted in both cited cases: "SourceMapper" and a browser "Save All Resources" extension, functionally equivalent to the stdlib `json.load()` approach in the prior section); (3) **manually or automatically grep the recovered source** for secrets/endpoints — in the Stripe case this was manual reading specifically *because* the hardcoded keys had no naming pattern that automated secret-scanners would flag, which argues for pairing source-map recovery with **both** a secrets-regex pass (SecretFinder-style) **and** human/LLM review of recovered config-like files, not regex alone.
- The escape.tech 70% figure, while from a vendor's own customer base rather than a neutral industry sample, is still a meaningful signal that exposed source maps are common enough in production that systematically checking for `//# sourceMappingURL=` + an unauthenticated-reachable `.map` across every discovered JS chunk is worth doing by default in any JS-recon pipeline, not as an edge case.

### Gaps
- A third candidate source ("how I found a source map exposure leading to an account takeover chain") turned out, on fetching, to be a content aggregator/index page with only headlines and no actual article body reachable — could not verify or cite any detail from it; excluded.
- A candidate "Copypasta: IDOR via Source Map Disclosure" writeup was identified in search but is explicitly a **training-lab scenario** (a "BugForge lab" with a flag), not a real disclosed bug-bounty report — excluded from citations per the instruction to maintain epistemic honesty about confirmed-fact vs. lab/practice content.
- Several other search hits (multiple `undercodetesting.com` posts with sensationalized titles like "The JavaScript Jackpot" / "The Invisible Goldmine", and various unauthenticated Medium "member-only story" previews) could not be verified as genuine, specific, named disclosures within this research pass — snippets read as generic/aggregator-style content without the hallmarks of a primary first-person disclosure (specific program name, date, researcher handle, or program response), so none are cited as confirmed findings; a report-writer wanting more than the two cases above should search HackerOne's Hacktivity feed directly for `"source map"` / `.js.map` rather than general web search, which this pass did not have remaining budget to do.
- Did not find a 2024-2026 case where JS-bundle mining revealed a **parameter name** (as opposed to a secret or whole endpoint) that specifically drove the vulnerability (e.g., an undocumented `role=` or `debug=` parameter found only in minified JS) — the two confirmed cases are both secret/credential-in-sourcemap stories rather than parameter-discovery stories; this sub-pattern remains undocumented by a verified primary source in this pass.

---

## Is there a reliable stdlib-only regex/string-matching approach to find `fetch(...)`, `axios.get/post(...)`, `.ajax(...)` calls in minified JS and extract the URL argument?

### Takeaway
Regex can approximate the common, literal-string-argument cases reasonably well (and this is exactly what pre-AST tools like LinkFinder/JSFinder already do implicitly, by just grabbing every quoted string that looks like a path); it reliably **breaks down** on object-literal call signatures (`axios({url: ...})`, `$.ajax({url: ...})`), computed/renamed call targets, and template-literal interpolation — which is precisely why BishopFox built a real tree-sitter-based parser (jsluice) instead of extending regex further. The jsluice source gives an exact specification of what a "correct" matcher checks, which a regex approximation can mirror argument-position-wise.

### Cited Findings
- jsluice's `fetch` matcher (ground-truth logic, from source) requires the call's function identifier to literally equal `"fetch"`, the first argument to be string-like, and if present, pulls `method` (default `"GET"`) and `headers` out of the **second argument when it is an object literal** — it does not attempt to resolve `method`/`headers` if the second argument is a variable rather than a literal object. — [jsluice url-matchers.go](https://github.com/BishopFox/jsluice/blob/main/url-matchers.go)
- jsluice's jQuery matcher explicitly documents three distinct call-signature shapes it must branch on: `jQuery.post(url[, data][, success][, dataType])`, `jQuery.ajax(url[, settings])`, and `jQuery.ajax([settings])` (URL-first-with-data, URL-first-with-settings, or settings-object-only) — confirming that a single flat regex cannot correctly cover jQuery's `.ajax`/`.get`/`.post` without first disambiguating which shape is present. — [jsluice url-match-jquery.go](https://github.com/BishopFox/jsluice/blob/main/url-match-jquery.go)
- jsluice's XHR matcher explicitly guards against false-positives from unrelated `.open(...)` calls (e.g. `window.open`) by checking that the **first argument is literally one of** `GET, HEAD, OPTIONS, POST, PUT, PATCH, DELETE` before treating a `.open(method, url)` call as an XHR call — this exact guard condition is directly portable to a regex character alternation. — [jsluice url-match-xhr.go](https://github.com/BishopFox/jsluice/blob/main/url-match-xhr.go)

### Inferences
- **`fetch(...)` — direct string-literal argument**, mirroring jsluice's "first arg is string-like" check:
  ```python
  import re
  FETCH_RE = re.compile(r"""\bfetch\s*\(\s*(['"`])((?:\\.|(?!\1).)*?)\1""", re.DOTALL)
  # match.group(2) == URL (or template-literal raw text if quote char is `)
  ```
- **`axios` — method-call form** (`axios.get(url, ...)`, `axios.post(url, data, ...)` etc.), mirroring the "callName suffix" style check jsluice uses for jQuery/XHR:
  ```python
  AXIOS_METHOD_RE = re.compile(
      r"""\baxios\.(get|post|put|patch|delete|head|options)\s*\(\s*(['"`])((?:\\.|(?!\2).)*?)\2""",
      re.IGNORECASE | re.DOTALL,
  )
  # group(1) == HTTP method, group(3) == URL
  ```
- **`axios`/jQuery `.ajax` — settings-object form** (`axios({method:"get", url:"..."})`, `$.ajax({url:"...", ...})`): true brace-balancing isn't regex-expressible in general, so the stdlib-only approximation is a **bounded-window** search for a `url:` key within N characters after the call opens, explicitly flagged as heuristic (will mismatch on deeply nested/reformatted objects, matching jsluice's own documented need to branch on call shape rather than pattern-match blindly):
  ```python
  AJAX_OBJECT_RE = re.compile(
      r"""\b(?:axios|\$\.ajax|jQuery\.ajax)\s*\(\s*\{.{0,500}?\burl\s*:\s*(['"`])((?:\\.|(?!\1).)*?)\1""",
      re.DOTALL,
  )
  # group(2) == URL; the 500-char window is a tunable false-positive/false-negative tradeoff, not a correctness guarantee
  ```
- **jQuery `.get`/`.post`/`.ajax` — URL-first form**, mirroring jsluice's `matchJQuery` "first argument is stringy" branch:
  ```python
  JQUERY_RE = re.compile(
      r"""\$\.(get|post|ajax)\s*\(\s*(['"`])((?:\\.|(?!\2).)*?)\2""",
      re.DOTALL,
  )
  ```
- **`XMLHttpRequest.open(method, url)`**, directly encoding jsluice's own method-token guard to suppress `window.open` false positives:
  ```python
  XHR_OPEN_RE = re.compile(
      r"""\.open\s*\(\s*(['"`])(GET|HEAD|OPTIONS|POST|PUT|PATCH|DELETE)\1\s*,\s*(['"`])((?:\\.|(?!\3).)*?)\3""",
      re.IGNORECASE | re.DOTALL,
  )
  # group(2) == method, group(4) == URL
  ```
- **Template-literal interpolation** (`` fetch(`${API_BASE}/users/${id}`) ``): the regexes above (with backtick in the quote-char alternation) will capture the raw template text including `${...}` placeholders verbatim. A stdlib cleanup pass can normalize these into a path-shape approximation, directly mirroring jsluice's own `ExpressionPlaceholder` concept (it substitutes a placeholder for non-literal expression parts and discards matches that are *entirely* placeholder, i.e. carry no literal structure at all):
  ```python
  def normalize_template(raw_url: str) -> str:
      return re.sub(r"\$\{[^}]*\}", "{param}", raw_url)
  # e.g. "/users/${id}/orders/${orderId}" -> "/users/{param}/orders/{param}"
  # if normalize_template(x) has no literal characters left (all placeholder), treat as a non-finding, same as jsluice does
  ```
- **Catch-all fallback**, matching jsluice's own last-resort "any string literal" matcher: run a broad quoted-string sweep (`r'''(['"`])((?:\\.|(?!\1).)*?)\1'''`) over the whole file and pipe every match through the `maybe_url()` filter given in Key Question 1's Inferences — this recovers calls through wrapped/renamed request helpers (`const f = axios; f.get(...)`, `import {request as r} from "./api"`) that a call-name-specific regex will always miss, at the cost of needing the heuristic filter to hold the false-positive rate down.
- Explicit limitation (as the task asked to flag when a real parser is genuinely required): **none of the above regexes can correctly resolve** (a) a base URL stored in a variable and concatenated (`BASE + "/users"` or `BASE.concat("/users")`), (b) a computed/bracket call target (`window["fetch"](...)`, `obj["ajax"](...)`), (c) which of several same-shaped object literals in a minified file is actually the argument to the matched call once nesting exceeds the bounded window used above, or (d) multi-statement URL construction (`let u = "/api"; u += "/v2"; fetch(u)`). All four require either real AST parsing (tree-sitter, as jsluice does) or executing the code in a real JS engine; the regexes above are explicitly best-effort approximations for the literal, single-expression call sites, which in practice is the majority of what appears in bundled/minified production JS but not all of it.

### Gaps
- Did not find a published stdlib-only (non-AST) Python tool that already implements this exact fetch/axios/ajax-URL-extraction-by-regex approach for comparison/validation — the regex designs above are this research's own synthesis from jsluice's documented matcher *logic* (cited above) rather than a cited pre-existing implementation, since no such prior art surfaced in the searches run.
- Did not measure false-positive/false-negative rates of the bounded-window object-literal heuristic (`AJAX_OBJECT_RE`) against real-world minified bundles — the 500-character window is a reasonable starting guess, not an empirically validated value, and a report-writer/implementer should tune it against sample bundles before relying on it.
