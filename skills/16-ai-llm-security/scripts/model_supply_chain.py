#!/usr/bin/env python3
"""model_supply_chain.py — Scan ML model artifacts for code-execution risk.

Many model formats (pickle, .pt, .bin, .ckpt, joblib) deserialize via Python
pickle, which can execute arbitrary code on load. This tool statically inspects
pickle opcodes for dangerous reduce/global imports WITHOUT unpickling, and flags
unsafe formats vs. safe ones (safetensors / ONNX / GGUF). Maps to OWASP LLM03.

The opcode walk resolves both the legacy ``GLOBAL`` opcode (protocol <= 3, which
carries ``module name`` inline) and ``STACK_GLOBAL`` (protocol >= 4, which pushes
the module and attribute as separate string opcodes first), so dangerous imports
in modern PyTorch/transformers checkpoints are not missed.

Usage:
    python model_supply_chain.py --path model.pt
    python model_supply_chain.py --path ./models --recursive --output scan.json
    python model_supply_chain.py --demo            # self-test on a synthetic pickle
"""
from __future__ import annotations

import argparse
import ast
import importlib.metadata
import json
import logging
import os
import pickle
import pickletools
import re
import struct
import sys
import zipfile

logger = logging.getLogger("model_supply_chain")

UNSAFE_EXT = {".pkl", ".pickle", ".pt", ".pth", ".bin", ".ckpt", ".joblib", ".dill", ".npy", ".npz"}
SAFE_EXT = {".safetensors", ".onnx", ".gguf", ".ggml", ".json"}

# Opcodes that push a string literal onto the stack (candidate STACK_GLOBAL operands).
_STRING_OPS = {"SHORT_BINUNICODE", "BINUNICODE", "BINUNICODE8", "UNICODE", "SHORT_BINSTRING", "BINSTRING", "STRING"}

# Modules/attributes that enable code execution or process/network side effects
# when imported inside a pickle stream.
DANGEROUS_MODULES = {
    "os", "subprocess", "sys", "builtins", "__builtin__", "posix", "nt",
    "shutil", "socket", "pty", "commands", "popen2", "platform", "importlib",
    "runpy", "operator", "functools", "codecs", "webbrowser", "ctypes",
    "multiprocessing", "asyncio", "pip", "setuptools", "requests", "urllib",
    # Added per research_notes/AI agent security depth techniques/
    # model_supply_chain_depth.md: named, documented blocklist-BYPASS
    # gadgets against picklescan-style scanners (this one included) --
    # pydoc.locate(name) imports an arbitrary dotted name as a string
    # argument (CVE-2026-22608 names this exact gap against picklescan),
    # marshal/types reconstruct a code object without ever naming a
    # "dangerous" callable directly (CVE-2025-67747-class), and uuid is
    # cited as a concrete real-world example of a stdlib module that
    # "was never blocklisted" by existing tools despite being reachable.
    # A blocklist is inherently a known-leaky strategy (new gadgets keep
    # being found) -- this closes the specific named gaps the research
    # surfaced, it doesn't claim completeness.
    "pydoc", "marshal", "types", "uuid",
}
DANGEROUS_CALLABLES = {
    "system", "exec", "eval", "compile", "__import__", "getattr", "call",
    "check_call", "check_output", "Popen", "run", "popen", "spawn", "fork",
    "methodcaller", "attrgetter", "apply", "FromImport",
    "locate",  # pydoc.locate -- see DANGEROUS_MODULES comment above
}


def scan_pickle_bytes(data: bytes) -> list[str]:
    """Return an ordered, de-duplicated list of dangerous findings from a pickle stream."""
    findings: list[str] = []
    recent_strings: list[str] = []  # trailing string literals, for STACK_GLOBAL resolution
    try:
        ops = list(pickletools.genops(data))
    except Exception as exc:  # noqa: BLE001 — malformed/truncated streams are expected input
        return [f"unparseable pickle stream ({exc})"]

    def flag_global(module: str, attr: str) -> None:
        ref = f"{module}.{attr}" if attr else module
        base = module.split(".")[0]
        if base in DANGEROUS_MODULES or attr in DANGEROUS_CALLABLES:
            findings.append(f"GLOBAL import: {ref}")

    for opcode, arg, _pos in ops:
        name = opcode.name
        if name in _STRING_OPS and arg is not None:
            recent_strings.append(str(arg))
            recent_strings = recent_strings[-2:]
        elif name == "GLOBAL" and arg:
            parts = str(arg).split(" ", 1)
            flag_global(parts[0], parts[1] if len(parts) > 1 else "")
            recent_strings.clear()
        elif name == "STACK_GLOBAL":
            if len(recent_strings) >= 2:
                flag_global(recent_strings[-2], recent_strings[-1])
            else:
                findings.append("STACK_GLOBAL with undetermined operands (manual review)")
            recent_strings.clear()
        elif name == "REDUCE":
            findings.append("REDUCE opcode (callable invocation on load)")
        elif name in ("INST", "OBJ", "NEWOBJ", "NEWOBJ_EX"):
            findings.append(f"{name} opcode (object construction on load)")
        elif name in ("GLOBAL", "STACK_GLOBAL"):
            recent_strings.clear()

    seen: set[str] = set()
    out: list[str] = []
    for item in findings:
        if item not in seen:
            seen.add(item)
            out.append(item)
    return out


def _verdict_from_findings(findings: list[str]) -> str:
    if any(f.startswith("GLOBAL import") for f in findings) or any("gadget pattern" in f for f in findings):
        return "DANGEROUS"
    if any(f.startswith("REDUCE") or "STACK_GLOBAL" in f for f in findings):
        return "review"
    return "review" if findings else "info"


def parse_npy_header(data: bytes):
    """Parse a .npy file's header per NumPy's own on-disk format spec,
    without loading array data. Returns (descr, data_offset), or None if
    this isn't a valid .npy stream. The header is a Python-dict-literal
    string parsed with ast.literal_eval (never executed) -- only an
    object-dtype array (descr == 'O'/'|O', which numpy.save only ever
    produces when the caller passes the non-default allow_pickle=True)
    stores its payload as an actual pickle stream after this header; every
    other dtype is raw binary numeric/string data that was never a pickle
    to begin with."""
    if not data.startswith(b"\x93NUMPY") or len(data) < 10:
        return None
    major = data[6]
    try:
        if major == 1:
            (hlen,) = struct.unpack_from("<H", data, 8)
            header_start = 10
        else:
            if len(data) < 12:
                return None
            (hlen,) = struct.unpack_from("<I", data, 8)
            header_start = 12
        header_end = header_start + hlen
        if len(data) < header_end:
            return None
        header = ast.literal_eval(data[header_start:header_end].decode("latin-1").strip())
    except (struct.error, ValueError, SyntaxError, UnicodeDecodeError):
        return None
    return header.get("descr"), header_end


def scan_npy_bytes(data: bytes) -> list[str]:
    """Route .npy bytes correctly instead of feeding the whole file to
    pickletools.genops() (research_notes/AI agent security depth
    techniques/model_supply_chain_depth.md): a plain-dtype .npy file was
    previously reported as a meaningless 'unparseable pickle stream' on
    every ordinary, genuinely-safe array (it was never a pickle stream to
    begin with), while a malicious object-dtype .npy -- the one case that
    DOES embed real pickle data -- was never specifically scanned as such
    either. Only descr=='O'/'|O' delegates to the real pickle scanner."""
    parsed = parse_npy_header(data)
    if parsed is None:
        return ["not a parseable .npy header (manual review)"]
    descr, offset = parsed
    if descr not in ("O", "|O"):
        return []  # plain numeric/string dtype array -- never pickle, nothing to scan
    return ["object-dtype .npy array (allow_pickle=True) -- payload scanned as pickle:"] \
        + scan_pickle_bytes(data[offset:])


_GGUF_TYPE_STRING = 8
_GGUF_TYPE_ARRAY = 9
_GGUF_SCALAR_SIZES = {0: 1, 1: 1, 2: 2, 3: 2, 4: 4, 5: 4, 6: 4, 7: 1, 10: 8, 11: 8, 12: 8}

_JINJA_RCE_GADGET_RE = re.compile(
    r"__class__|__globals__|__mro__|__subclasses__|__builtins__|__init__\s*\.\s*__",
)


def _gguf_read_string(data: bytes, offset: int):
    """A GGUF string is a uint64 byte-length prefix followed by raw UTF-8
    bytes (never NUL-terminated)."""
    if offset + 8 > len(data):
        raise ValueError("truncated GGUF string length")
    (length,) = struct.unpack_from("<Q", data, offset)
    offset += 8
    if offset + length > len(data):
        raise ValueError("truncated GGUF string data")
    return data[offset:offset + length].decode("utf-8", errors="replace"), offset + length


def _gguf_skip_value(data: bytes, offset: int, value_type: int):
    """Advance past one GGUF metadata value of the given type, returning
    (decoded_value_or_None, new_offset). Only STRING is decoded (all this
    scanner needs); every other type is skipped by its real byte size so
    the offset stays correct for whatever metadata key comes next --
    getting any one type's size wrong corrupts every subsequent read, so
    ARRAY recurses through this same function rather than assuming a
    fixed per-element size."""
    if value_type == _GGUF_TYPE_STRING:
        return _gguf_read_string(data, offset)
    if value_type == _GGUF_TYPE_ARRAY:
        if offset + 12 > len(data):
            raise ValueError("truncated GGUF array header")
        elem_type, count = struct.unpack_from("<IQ", data, offset)
        offset += 12
        for _ in range(count):
            _, offset = _gguf_skip_value(data, offset, elem_type)
        return None, offset
    size = _GGUF_SCALAR_SIZES.get(value_type)
    if size is None:
        raise ValueError(f"unknown GGUF value type {value_type}")
    return None, offset + size


def scan_gguf_metadata(data: bytes) -> list[str]:
    """Extract GGUF key-value metadata with stdlib struct parsing (no
    gguf/llama.cpp dependency), looking specifically at *.chat_template
    string values. GGUF's chat-template field is literal, unsandboxed
    Jinja2 evaluated by the inference server at load/first-use time --
    CVE-2024-34359 ("Llama Drama", llama-cpp-python <0.2.72) and
    CVE-2026-5760 (SGLang, CVSS 9.8) both got RCE purely from this
    metadata field, no tensor/weight data involved at all. That's why
    GGUF cannot be treated as safe-by-design on the strength of tensor/
    header inspection alone (research_notes/AI agent security depth
    techniques/model_supply_chain_depth.md)."""
    findings: list[str] = []
    if len(data) < 4 or data[:4] != b"GGUF":
        return findings
    try:
        (version,) = struct.unpack_from("<I", data, 4)
        offset = 8
        if version == 1:
            fmt, size = "<I", 4
        else:
            fmt, size = "<Q", 8
        (_tensor_count,) = struct.unpack_from(fmt, data, offset)
        offset += size
        (kv_count,) = struct.unpack_from(fmt, data, offset)
        offset += size
        for _ in range(kv_count):
            key, offset = _gguf_read_string(data, offset)
            (value_type,) = struct.unpack_from("<I", data, offset)
            offset += 4
            value, offset = _gguf_skip_value(data, offset, value_type)
            if value_type == _GGUF_TYPE_STRING and key.endswith("chat_template") and value:
                if _JINJA_RCE_GADGET_RE.search(value):
                    findings.append(
                        f"GGUF metadata key '{key}' contains a Jinja2 sandbox-escape gadget "
                        f"pattern (CVE-2024-34359/CVE-2026-5760-class chat-template RCE)"
                    )
                else:
                    # Worded to NOT contain the substring "gadget pattern" --
                    # _verdict_from_findings() checks for exactly that
                    # substring to flag DANGEROUS, and an earlier version of
                    # this message ("no known-gadget pattern matched")
                    # accidentally contained it, which would have
                    # misclassified every GGUF file with ANY chat_template,
                    # benign or not, as DANGEROUS. Caught by testing a
                    # present-but-benign template end-to-end, not just
                    # "no template" and "malicious template".
                    findings.append(
                        f"GGUF metadata key '{key}' is a Jinja2 chat template (present and "
                        f"unsandboxed by design -- review manually; template text did not match "
                        f"any known RCE-gadget signature)"
                    )
    except (struct.error, ValueError, UnicodeDecodeError) as exc:
        findings.append(f"GGUF metadata parse stopped early ({exc}) -- partial scan only")
    return findings


# (library, fixed_version, CVE, note) -- a known case where the standard
# documented mitigation against pickle RCE was ITSELF exploitable. Answers
# "is the thing that will load this file safe here", a different question
# from per-file scanning, and one this tool had no way to ask before.
_KNOWN_VULNERABLE_LOADERS = [
    ("torch", (2, 6, 0), "CVE-2025-32434",
     "torch.load(weights_only=True) -- the documented mitigation against pickle RCE -- "
     "was itself bypassable before this version"),
]


def check_loader_environment() -> list[str]:
    """One-time per-run advisory, not a per-file finding: only reports a
    library that's actually installed here and below its known-fixed
    version via stdlib importlib.metadata -- says nothing about a library
    that isn't installed."""
    advisories = []
    for lib, fixed, cve, note in _KNOWN_VULNERABLE_LOADERS:
        try:
            installed = importlib.metadata.version(lib)
        except importlib.metadata.PackageNotFoundError:
            continue
        parts = tuple(int(p) for p in re.findall(r"\d+", installed)) or (0,)
        if parts < fixed:
            advisories.append(
                f"{lib} {installed} is below the fixed version for {cve}: {note} "
                f"(upgrade to >= {'.'.join(map(str, fixed))})"
            )
    return advisories


def scan_file(path: str) -> dict:
    ext = os.path.splitext(path)[1].lower()
    result: dict = {"path": path, "ext": ext, "verdict": "info", "findings": []}

    if ext in SAFE_EXT:
        if ext in (".gguf", ".ggml"):
            # Not actually blanket-safe: CVE-2024-34359 ("Llama Drama")
            # and CVE-2026-5760 got RCE purely from the unsandboxed-Jinja2
            # chat_template metadata field -- no tensor/weight data
            # involved at all. See scan_gguf_metadata().
            try:
                with open(path, "rb") as fh:
                    result["findings"] = scan_gguf_metadata(fh.read())
            except Exception as exc:  # noqa: BLE001
                result["findings"] = [f"error reading GGUF metadata: {exc}"]
            result["verdict"] = _verdict_from_findings(result["findings"]) if result["findings"] else "safe"
            if not result["findings"]:
                result["findings"].append("safe-by-design tensor format; no chat_template metadata found")
            return result
        result["verdict"] = "safe"
        result["findings"].append("safe-by-design format (no arbitrary code execution on load)")
        return result

    if ext not in UNSAFE_EXT:
        result["findings"].append("unknown format — review manually")
        result["verdict"] = "review"
        return result

    try:
        if ext == ".npy":
            with open(path, "rb") as fh:
                result["findings"] += scan_npy_bytes(fh.read())
        elif zipfile.is_zipfile(path):
            # PyTorch .pt/.pth and many .ckpt are zip archives containing
            # pickle(s); .npz is a zip of .npy arrays (each member needs the
            # SAME header-aware routing as a standalone .npy file above --
            # matching only "pickle" in the member name, as before, missed
            # every .npz member entirely, since numpy names them "<name>.npy").
            with zipfile.ZipFile(path) as zf:
                for nm in zf.namelist():
                    if nm.endswith((".pkl", ".pickle")) or nm.endswith("data.pkl") or "pickle" in nm.lower():
                        result["findings"] += [f"[{nm}] {x}" for x in scan_pickle_bytes(zf.read(nm))]
                    elif nm.endswith(".npy"):
                        result["findings"] += [f"[{nm}] {x}" for x in scan_npy_bytes(zf.read(nm))]
            if not result["findings"]:
                result["findings"].append("zip archive, no embedded pickle entries detected")
        else:
            with open(path, "rb") as fh:
                result["findings"] += scan_pickle_bytes(fh.read())
    except Exception as exc:  # noqa: BLE001 — report I/O/zip errors as findings, never crash a batch scan
        logger.warning("error scanning %s: %s", path, exc)
        result["findings"].append(f"error: {exc}")
        result["verdict"] = "review"
        return result

    result["verdict"] = _verdict_from_findings([f.split("] ", 1)[-1] for f in result["findings"]])
    return result


def iter_paths(root: str, recursive: bool):
    if os.path.isfile(root):
        yield root
        return
    for dirpath, _dirs, files in os.walk(root):
        for name in sorted(files):
            yield os.path.join(dirpath, name)
        if not recursive:
            break


def export_findings(results: list[dict]) -> list[dict]:
    """Shape DANGEROUS verdicts into vuln-chain-composer's expected raw-
    finding format (import_findings.py's normalize_finding() reads
    type/url/evidence/payload/severity directly off this dict -- "url" is
    repurposed as the artifact path here, same as other non-web pipeline
    scripts in this repo do for a non-HTTP target). Only DANGEROUS is
    exported, never "review" (ambiguous) or "safe" -- same confirmed-only
    discipline as prompt_injection_tester.py's export_findings(). The
    "type" field is the single word "modelsupplychain" (no separator),
    matching import_findings.py's substring-containment convention for its
    other one-word type tags."""
    findings = []
    for r in results:
        if r["verdict"] != "DANGEROUS":
            continue
        findings.append({
            "type": "modelsupplychain",
            "url": r["path"],
            "evidence": f"Static pickle-opcode scan found a load-time code-execution risk in "
                        f"{r['path']}: " + "; ".join(r["findings"][:5]),
            "payload": "; ".join(r["findings"]),
            "severity": "HIGH",
            "note": "model_supply_chain.py static scan (no unpickling performed)",
        })
    return findings


def _run_demo() -> int:
    """Self-test: confirm detection on synthetic pickles at legacy and modern protocols."""

    class _Probe:
        def __reduce__(self):
            return (os.system, ("echo demo",))

    for proto in (2, pickle.DEFAULT_PROTOCOL):
        findings = scan_pickle_bytes(pickle.dumps(_Probe(), protocol=proto))
        named = [f for f in findings if f.startswith("GLOBAL import")]
        status = "OK" if named else "FAIL"
        print(f"  [proto {proto}] {status}: {findings}")
        if not named:
            print("  [!] demo FAILED: dangerous global not resolved", file=sys.stderr)
            return 1
    print("[+] demo passed — GLOBAL/STACK_GLOBAL imports resolved at both protocols")
    return 0


def main() -> None:
    ap = argparse.ArgumentParser(description="Scan ML model files for load-time code execution risk")
    ap.add_argument("--path", help="Model file or directory")
    ap.add_argument("--recursive", action="store_true", help="Recurse into subdirectories")
    ap.add_argument("--output", help="Write JSON report")
    ap.add_argument("--export-findings", help="Write DANGEROUS verdicts as vuln-chain-composer-ready "
                                                "findings JSON (feed straight to import_findings.py --input)")
    ap.add_argument("--strict", action="store_true", help="Exit non-zero (3) if any DANGEROUS artifact is found")
    ap.add_argument("--demo", action="store_true", help="Run a built-in self-test and exit")
    ap.add_argument("-v", "--verbose", action="store_true", help="Enable debug logging")
    args = ap.parse_args()

    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.WARNING,
                        format="%(levelname)s %(name)s: %(message)s")

    if args.demo:
        sys.exit(_run_demo())

    if not args.path:
        ap.error("--path is required (or use --demo)")
    if not os.path.exists(args.path):
        print(f"[!] No such path: {args.path}", file=sys.stderr)
        sys.exit(1)

    loader_advisories = check_loader_environment()
    if loader_advisories:
        print("[!] Loader-environment advisory (independent of any single file's content):")
        for a in loader_advisories:
            print(f"    - {a}")
        print()

    print(f"[*] Scanning model artifacts: {args.path}\n")
    results, danger = [], 0
    base = args.path if os.path.isdir(args.path) else os.path.dirname(args.path) or "."
    for p in iter_paths(args.path, args.recursive):
        ext = os.path.splitext(p)[1].lower()
        if ext not in UNSAFE_EXT and ext not in SAFE_EXT:
            continue
        r = scan_file(p)
        results.append(r)
        tag = {"DANGEROUS": "[DANGER]", "review": "[review]",
               "safe": "[ safe ]", "info": "[ info ]"}.get(r["verdict"], "[      ]")
        print(f"  {tag} {os.path.relpath(p, base)}")
        for f in r["findings"][:8]:
            print(f"            - {f}")
        if r["verdict"] == "DANGEROUS":
            danger += 1

    print(f"\n=== {len(results)} artifact(s) scanned | {danger} DANGEROUS ===")
    if danger:
        print("[!] Prefer safetensors. Verify provenance/signature before loading (OWASP LLM03).")

    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            json.dump(results, fh, indent=2)
        print(f"[+] Wrote {args.output}")

    if args.export_findings:
        findings = export_findings(results)
        with open(args.export_findings, "w", encoding="utf-8") as fh:
            json.dump(findings, fh, indent=2)
        print(f"[+] Wrote {len(findings)} finding(s) to {args.export_findings}")

    if args.strict and danger:
        sys.exit(3)


if __name__ == "__main__":
    main()
