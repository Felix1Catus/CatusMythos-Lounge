#!/usr/bin/env bash
# MYTHOS context router — UserPromptSubmit hook (Claude edition).
# Reads the user's prompt, matches hunt-context keywords, and injects (stdout -> appended to
# context) a SHORT routing block: which directive to read, which skills to load, which agent
# to delegate to — so the right doctrine is in-context at the moment it's relevant, without
# the user prompting for it.
#
# Anti-spam: each category injects AT MOST ONCE per session (marker files per session_id).
# Fail-open always; silent (no output) when nothing matches.
# LOCATION: ~/.claude/mythos/context_router.sh
set -uo pipefail
INPUT=$(cat || true)
# live_talk is additive: do not exec, or the hunt router below never runs
printf '%s' "$INPUT" | python3 "$HOME/targets/_shared/lounge/live_talk.py" prompt || true
read -r SESSION PROMPT <<< "$(printf '%s' "$INPUT" | python3 -c '
import json, sys
try:
    d = json.load(sys.stdin)
except Exception:
    print(" "); sys.exit()
sid = d.get("session_id") or "nosession"
p = (d.get("prompt") or d.get("user_prompt") or d.get("text")
     or d.get("message") or d.get("content") or "")
if not isinstance(p, str):
    p = str(p)
print(sid, p.replace("\n", " "))
' 2>/dev/null || echo " ")"
PROMPT_LOWER=$(printf '%s' "${PROMPT:-}" | tr '[:upper:]' '[:lower:]')
[[ -z "${PROMPT_LOWER// /}" ]] && exit 0

SEEN_DIR="$HOME/.claude/mythos/router_seen/$SESSION"
mkdir -p "$SEEN_DIR"

emit() {  # emit <category> <block...>
    local cat="$1"; shift
    [[ -f "$SEEN_DIR/$cat" ]] && return 1
    touch "$SEEN_DIR/$cat"
    echo "$@"
    return 0
}

EMITTED=0

# 1) Active hunt work → brain, one shot, solo
if printf '%s' "$PROMPT_LOWER" | grep -qE 'hunt|recon|exploit|bypass|payload|idor|ssrf|xss|sqli|\brce\b|ssrf|takeover|bug ?bounty|vrp|hackerone|bugcrowd|attack surface|fuzzer?|brute|token forg|auth bypass|privesc|escalat'; then
    if emit hunt "◆ ROUTER[hunt]: HUNT CONTEXT — brain is ~/.grok/rules/CRITICAL_HUNTER.md. Do not read another file before the request. Loop: GROUND→PROBE→ANALYZE→PERSIST→VALIDATE. Skill driver: methos_generative_engine; barrier: zero_day_mindset; instrument: differential_oracle. Agents: scope-architect (big scope) → surface-re (client RE) → critical-hunter (strike) → chain-breaker/impact-prover (escalate). End every block: floor · ceiling · missing link. Never end the turn waiting for directives — fire the next probe."; then
        EMITTED=1
    fi
fi

# 2) Blocked / wall language → barrier doctrine
if printf '%s' "$PROMPT_LOWER" | grep -qE 'blocked|403|401|\bwaf\b|rate.?limit|captcha|forbidden|denied|can.?t get (past|through)|stuck'; then
    if emit barrier "◆ ROUTER[barrier]: A wall is a FILTER, not an exit. Load zero_day_mindset + differential_oracle. Canonical refusal, then one structural variant. A later error class means the check was skipped. A repeated class means loosen one axis. Stop only on an infra identity gate. Log the class to CHAIN_LEDGER.md. You share this target with the other lounge seats. Hand them the sibling. Validate the instrument before believing any 'blocked'."; then
        EMITTED=1
    fi
fi

# 3) Found something → chain + impact proof
if printf '%s' "$PROMPT_LOWER" | grep -qE 'found (a|an)|confirmed|it works|got (a|an)|vuln|bug (is )?(real|confirmed)|primitive|bypassed|pwned|session (minted|token)'; then
    if emit chain "◆ ROUTER[chain]: Finding confirmed ≠ done. Do NOT file yet — CHAIN: what does this give the next link? Load chain_completer + impact_proof; climb the proof ladder (R2 primitive → R3 boundary → R4 end state → R5 narrative), log rungs to CHAIN_LEDGER.md. Floor < Critical ⇒ missing link is the mandatory next work item. Report at the proven floor, opener = boundary IS crossed."; then
        EMITTED=1
    fi
fi

# 4) Report writing → report doctrine (the pinned feedback mistake)
if printf '%s' "$PROMPT_LOWER" | grep -qE 'report|write.?up|draft|submit|triag'; then
    if emit report "◆ ROUTER[report]: Load report_draft + impact_proof. PINNED FEEDBACK #1: opener leads with the trust boundary that IS crossed — ZERO concession language in the severity line; disclaimers go in a section BELOW the findings. Every claim maps to a captured response under evidence/. Only the human submits."; then
        EMITTED=1
    fi
fi

# 5) Resume / context loss → warm-boot path
if printf '%s' "$PROMPT_LOWER" | grep -qE 'resume|where (were|did) (we|i)|continue (the|from)|context (lost|died)|pick(ing)? up|warm.?boot|what.?s next|status of'; then
    if emit resume "◆ ROUTER[resume]: GROUND from disk, never memory — run: bash ~/.claude/mythos/resume.sh <prog> (bare to list). Read CHECKPOINT + tail JOURNAL + RESUME; RE-VERIFY the PROVEN line with ONE fresh probe before building on it. 'Those disagree' → trust the probes. Skill: ground. Agent: warm-boot for full reconstruction."; then
        EMITTED=1
    fi
fi

# 6) Big/new scope → pipeline entry
if printf '%s' "$PROMPT_LOWER" | grep -qE 'new (target|program)|scope|many (domains|apps|subdomains)|large target| acquisitions|where to start|start(ing)? (a|the) hunt'; then
    if emit scope "◆ ROUTER[scope]: LARGE-SCOPE PROTOCOL — never 'hunt the program'; decompose to ONE ranked lead. bash ~/.claude/mythos/newtarget.sh <prog> → recon_pipeline skill → delegate scope-architect (map+model) / surface-re (client RE) → LEADS.md ranked by Critical-shape → strike top lead. Breadth timeboxed, depth unbounded."; then
        EMITTED=1
    fi
fi

exit 0
