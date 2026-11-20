#!/usr/bin/env python3
"""Provision pinned loopback labs, run bounded core checks, and enforce gold cases."""

import argparse
import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path

import requests


ROOT = Path(__file__).resolve().parents[1]
RUN_ID = uuid.uuid4().hex[:10]
RESOURCE_PREFIX = "catus-ci-" + RUN_ID
NETWORK_NAME = RESOURCE_PREFIX + "-network"
DVWA_DB_NAME = RESOURCE_PREFIX + "-mariadb"
DVWA_NAME = RESOURCE_PREFIX + "-dvwa"
JUICE_NAME = RESOURCE_PREFIX + "-juice-shop"
PINNED = json.loads((ROOT / "doctrine" / "benchmarks" / "lab-run-2026-11-18.json")
                   .read_text(encoding="utf-8"))
def _pinned(repository, pinned_key):
    return repository + "@" + PINNED["builds"]["crapi"][pinned_key].split("@", 1)[1]


CRAPI_IMAGES = {
    "crapi-identity": _pinned("crapi/crapi-identity", "identity_image"),
    "crapi-community": _pinned("crapi/crapi-community", "community_image"),
    "crapi-workshop": _pinned("crapi/crapi-workshop", "workshop_image"),
    "crapi-chatbot": _pinned("crapi/crapi-chatbot", "chatbot_image"),
    "crapi-web": _pinned("crapi/crapi-web", "web_image"),
    "api.mypremiumdealership.com": _pinned("crapi/gateway-service", "gateway_image"),
    "postgresdb": _pinned("postgres", "postgres_image"),
    "mongodb": _pinned("mongo", "mongodb_image"),
    "chromadb": _pinned("chromadb/chroma", "chromadb_image"),
    "mailhog": _pinned("crapi/mailhog", "mailhog_image"),
}


def _run(args, *, check=True, capture=True, cwd=None, env=None, timeout=180):
    result = subprocess.run(args, cwd=cwd, env=env, capture_output=capture,
                            text=True, check=False, timeout=timeout)
    if check and result.returncode:
        detail = (result.stderr or "").strip()[-1200:]
        raise RuntimeError("command failed: {}{}".format(
            " ".join(args[:4]), ": " + detail if detail else ""))
    return result


def _wait_http(url, timeout=180):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            response = requests.get(url, timeout=3, allow_redirects=False)
            if response.status_code < 500:
                return
        except requests.RequestException:
            pass
        time.sleep(2)
    raise RuntimeError("lab did not become ready: {}".format(url))


def _wait_dvwa_database(container_name, timeout=180):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        result = _run(["docker", "exec", container_name, "mariadb-admin", "ping",
                       "-h", "127.0.0.1", "--silent"], check=False, timeout=8)
        if result.returncode == 0:
            return
        time.sleep(2)
    raise RuntimeError("DVWA MariaDB did not become ready")


def _dvwa_session(base):
    session = requests.Session()
    def login():
        response = session.get(base + "/login.php", timeout=10)
        token = re.search(r"name='user_token' value='([^']+)'", response.text)
        if not token:
            raise RuntimeError("DVWA login CSRF token was not found")
        response = session.post(base + "/login.php", data={
            "username": "admin", "password": "password", "Login": "Login",
            "user_token": token.group(1)}, timeout=10)
        if response.url.endswith("login.php"):
            raise RuntimeError("DVWA seeded login failed")

    login()
    setup = session.get(base + "/setup.php", timeout=10)
    token = re.search(r"name='user_token' value='([^']+)'", setup.text)
    if not token:
        raise RuntimeError("DVWA setup CSRF token was not found")
    session.post(base + "/setup.php", data={
        "create_db": "Create / Reset Database", "user_token": token.group(1)}, timeout=20)
    # DVWA creates a fresh session while resetting the database; re-authenticate
    # before applying the low-security setting or running authenticated probes.
    login()
    security = session.get(base + "/security.php", timeout=10)
    token = re.search(r"name='user_token' value='([^']+)'", security.text)
    if not token:
        raise RuntimeError("DVWA security CSRF token was not found")
    session.post(base + "/security.php", data={
        "security": "low", "seclev_submit": "Submit", "user_token": token.group(1)}, timeout=10)
    verified = session.get(base + "/security.php", timeout=10)
    if '<option value="low" selected' not in verified.text:
        raise RuntimeError("DVWA low security level was not selected")
    storage = {"cookies": [{"name": cookie.name, "value": cookie.value,
                            "domain": "127.0.0.1", "path": cookie.path or "/",
                            "expires": cookie.expires or -1, "httpOnly": True,
                            "secure": bool(cookie.secure), "sameSite": "Strict"}
                           for cookie in session.cookies], "origins": []}
    return session, storage


def _manifest(directory, label, origin, tool, budget, *, role="anonymous", roles=None):
    document = {"schema_version": 1, "engagement": "ci-" + label,
                "scope": {"origins": [origin], "request_budget": budget,
                          "allow_state_changes": False},
                "targets": [{"id": "app", "url": origin + "/",
                             "roles": roles or [{"name": role}]}],
                "steps": [{"id": "scan", "tool": tool, "target": "app", "role": role,
                           "max_requests": budget}]}
    path = directory / (label + ".campaign.json")
    path.write_text(json.dumps(document), encoding="utf-8")
    return path


def _campaign_cli(directory, label, origin, tool, scanner_args, budget, env=None):
    manifest_path = _manifest(directory, label, origin, tool, budget)
    state_path = directory / (label + ".sqlite")
    output_path = directory / (label + ".json")
    command = [sys.executable, str(ROOT / "scripts" / "assessment_campaign.py"),
               "run-cli", "--manifest", str(manifest_path), "--step", "scan",
               "--confirm-target", origin, "--state-db", str(state_path),
               "--campaign-id", "ci-" + label, "--process-only", "--",
               *scanner_args, "--output", str(output_path)]
    completed = _run(command, env=env, cwd=str(ROOT), timeout=1200)
    if not output_path.is_file():
        detail = (completed.stdout + "\n" + completed.stderr).strip()[-1600:]
        raise RuntimeError("campaign step {} returned no scanner artifact{}".format(
            label, ": " + detail if detail else ""))
    result = json.loads(output_path.read_text(encoding="utf-8"))
    if not isinstance(result, dict):
        raise RuntimeError("scanner produced invalid JSON: {}".format(label))
    return result


def _native_api_discovery(directory, label, origin, budget=600):
    manifest_path = _manifest(directory, label, origin, "api_discovery", budget)
    state_path = directory / (label + ".sqlite")
    output_path = directory / (label + ".json")
    command = [sys.executable, str(ROOT / "scripts" / "assessment_campaign.py"),
               "run-step", "--manifest", str(manifest_path), "--step", "scan",
               "--confirm-target", origin, "--state-db", str(state_path),
               "--campaign-id", "ci-" + label, "--process-only", "--output", str(output_path)]
    completed = _run(command, check=False, cwd=str(ROOT), timeout=1800)
    if completed.returncode:
        raise RuntimeError("API discovery failed or exhausted its request budget: {}".format(label))
    result = json.loads(output_path.read_text(encoding="utf-8"))
    if result.get("execution", {}).get("budget_exhausted"):
        raise RuntimeError("API discovery exhausted its declared request budget: {}".format(label))
    return result


def _start_labs():
    _run(["docker", "network", "create", NETWORK_NAME])
    _run(["docker", "run", "-d", "--name", DVWA_DB_NAME, "--network", NETWORK_NAME,
          "--network-alias", "db", "-e", "MYSQL_ROOT_PASSWORD=dvwa", "-e", "MYSQL_DATABASE=dvwa",
          "-e", "MYSQL_USER=dvwa", "-e", "MYSQL_PASSWORD=p@ssw0rd",
          "mariadb:10@sha256:7d829180b5b2a9ba74f6242876ab401a0d7dd338a807e522ef92bc9698760f20"])
    _wait_dvwa_database(DVWA_DB_NAME)
    _run(["docker", "run", "-d", "--name", DVWA_NAME, "--network", NETWORK_NAME,
          "-p", "127.0.0.1:4280:80", "-e", "DB_SERVER=db",
          "ghcr.io/digininja/dvwa@sha256:61167ec23fbf861f7d96a7beb4be3612d043d48dbc6b239d4f90d7e8cdff8115"])
    _run(["docker", "run", "-d", "--name", JUICE_NAME,
          "-p", "127.0.0.1:3000:3000",
          "bkimminich/juice-shop@sha256:877fc77b12d72b42e486eb09b6b1711cc56514306d92006b284e7e7cf076a809"])

    temp_root = Path(tempfile.mkdtemp(prefix="catus-crapi-"))
    crapi_source = temp_root / "source"
    try:
        _run(["git", "clone", "--filter=blob:none", "--no-checkout",
              "https://github.com/OWASP/crAPI.git", str(crapi_source)], timeout=180)
        commit = PINNED["builds"]["crapi"]["source_commit"]
        _run(["git", "checkout", commit], cwd=str(crapi_source))
        compose_dir = crapi_source / "deploy" / "docker"
        override = {"services": {name: {"image": image} for name, image in CRAPI_IMAGES.items()}}
        override_path = compose_dir / "catus-pinned.override.json"
        override_path.write_text(json.dumps(override), encoding="utf-8")
        compose = ["docker", "compose", "-p", RESOURCE_PREFIX, "-f", "docker-compose.yml", "-f",
                   "docker-compose.minimal.yml", "-f", "catus-pinned.override.json"]
        _run([*compose, "pull"], cwd=str(compose_dir), timeout=1800)
        _run([*compose, "up", "-d"], cwd=str(compose_dir), timeout=1800)
        _wait_http("http://127.0.0.1:4280/login.php")
        _wait_http("http://127.0.0.1:3000/")
        _wait_http("http://127.0.0.1:8888/")
        return crapi_source, RESOURCE_PREFIX
    except Exception:
        _stop_crapi(crapi_source, RESOURCE_PREFIX)
        raise


def _stop_crapi(crapi_source, project):
    compose_dir = Path(crapi_source) / "deploy" / "docker"
    override = compose_dir / "catus-pinned.override.json"
    if compose_dir.exists() and override.exists():
        _run(["docker", "compose", "-p", project, "-f", "docker-compose.yml", "-f",
              "docker-compose.minimal.yml", "-f", "catus-pinned.override.json", "down", "-v"],
             cwd=str(compose_dir), check=False, timeout=600)
    shutil.rmtree(Path(crapi_source).parent, ignore_errors=True)


def run(output_path):
    docker = shutil.which("docker")
    if not docker:
        raise RuntimeError("Docker is required to run the pinned core lab matrix")
    output_path = Path(output_path).resolve()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    crapi_context = None
    try:
        crapi_context = _start_labs()
        with tempfile.TemporaryDirectory(prefix="catus-ci-artifacts-") as temp:
            directory = Path(temp)
            dvwa_session, storage = _dvwa_session("http://127.0.0.1:4280")
            storage_path = directory / "dvwa-storage.json"
            storage_path.write_text(json.dumps(storage), encoding="utf-8")
            environment = os.environ.copy()
            environment["DVWA_TEST_COOKIE"] = "; ".join(
                "{}={}".format(cookie.name, cookie.value) for cookie in dvwa_session.cookies)

            _campaign_cli(directory, "dvwa-crawl", "http://127.0.0.1:4280", "web_crawl",
                          ["--target", "http://127.0.0.1:4280/", "--depth", "2", "--max-pages", "25",
                           "--cookie-env", "DVWA_TEST_COOKIE"], 120, environment)
            _campaign_cli(directory, "dvwa-sqli-campaign-findings", "http://127.0.0.1:4280", "web_sqli",
                          ["--target", "http://127.0.0.1:4280/vulnerabilities/sqli/?id=1&Submit=Submit",
                           "--cookie-env", "DVWA_TEST_COOKIE", "--skip-time", "--delay", "0",
                           "--max-mutations", "0", "--waf-escalation-budget", "0"], 80, environment)
            _campaign_cli(directory, "dvwa-xss-campaign-findings", "http://127.0.0.1:4280", "web_xss",
                          ["--target", "http://127.0.0.1:4280/vulnerabilities/xss_r/?name=Guest",
                           "--cookie-env", "DVWA_TEST_COOKIE", "--delay", "0",
                           "--waf-escalation-budget", "0"], 20, environment)
            _campaign_cli(directory, "dvwa-xss-browser", "http://127.0.0.1:4280", "web_browser",
                          ["--target", "http://127.0.0.1:4280/vulnerabilities/xss_r/?name=Guest",
                           "--active", "--storage-state", str(storage_path), "--max-pages", "1",
                           "--max-requests", "50"], 60, environment)
            _campaign_cli(directory, "dvwa-lfi", "http://127.0.0.1:4280", "web_lfi",
                          ["--params", str(directory / "dvwa-crawl.json"), "--skip-lfi-chains",
                           "--cookie-env", "DVWA_TEST_COOKIE", "--delay", "0"], 100, environment)
            _campaign_cli(directory, "crapi-exposure", "http://127.0.0.1:8888", "web_exposure",
                          ["--target", "http://127.0.0.1:8888", "--delay", "0"], 12)
            _campaign_cli(directory, "juice-shop-exposure", "http://127.0.0.1:3000", "web_exposure",
                          ["--target", "http://127.0.0.1:3000", "--delay", "0"], 12)
            _campaign_cli(directory, "juice-shop-crawl", "http://127.0.0.1:3000", "web_crawl",
                          ["--target", "http://127.0.0.1:3000/", "--depth", "2", "--max-pages", "25"],
                          120)
            _campaign_cli(directory, "crapi-crawl", "http://127.0.0.1:8888", "web_crawl",
                          ["--target", "http://127.0.0.1:8888/", "--depth", "2", "--max-pages", "25"],
                          120)
            juice_api = _native_api_discovery(directory, "juice-shop-api", "http://127.0.0.1:3000", 1000)
            crapi_api = _native_api_discovery(directory, "crapi-api", "http://127.0.0.1:8888", 300)

            # Give the lab summarizer exactly its documented artifact names.
            summary_files = ("dvwa-sqli-campaign-findings.json", "dvwa-xss-campaign-findings.json",
                             "dvwa-xss-browser.json", "crapi-exposure.json", "juice-shop-exposure.json")
            artifact_names = {item.name for item in directory.iterdir()}
            for name in summary_files:
                if name not in artifact_names:
                    raise RuntimeError("required core lab artifact was not produced: {}; artifacts={}".format(
                        name, ", ".join(sorted(artifact_names))))
            summarizer = _load_summarizer()
            report = summarizer.summarize_lab_artifacts(directory)
            local_runner = _load_local_benchmark()
            local_report = local_runner.run_benchmark()
            combined_cases = report["cases"] + local_report["cases"]
            campaign = _load_campaign()
            report = campaign.evaluate_coverage(combined_cases, [
                {"case_id": case["id"], "status": case["status"],
                 **({"evidence_review": {"schema_version": 1,
                                          "assessment_state": "confirmed",
                                          "proof_checks": {"complete": True}}}
                    if case["status"] == "confirmed" else {})}
                for case in combined_cases])
            report["benchmark_parts"] = {
                "cross_lab": {**summarizer.summarize_lab_artifacts(directory),
                              "api_discovery": {
                                  "juice_shop": juice_api.get("execution", {}),
                                  "crapi": crapi_api.get("execution", {}),
                              }},
                "local_fixture": local_report,
            }
            gate = _load_gate().evaluate_release_gate(report)
            report["release_gate"] = gate
            output_path.write_text(json.dumps(report, indent=2, allow_nan=False) + "\n", encoding="utf-8")
            if not gate["ready"]:
                raise RuntimeError("core lab release gate failed: {}".format("; ".join(gate["failures"])))
    finally:
        _run(["docker", "rm", "-f", DVWA_NAME, DVWA_DB_NAME, JUICE_NAME], check=False)
        _run(["docker", "network", "rm", NETWORK_NAME], check=False)
        # Remove only the crAPI compose project created by this run.
        if crapi_context is not None:
            _stop_crapi(*crapi_context)


def _load_summarizer():
    path = ROOT / "scripts" / "summarize_lab_benchmark.py"
    spec = importlib.util.spec_from_file_location("catus_ci_lab_summarizer", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _load_gate():
    path = ROOT / "scripts" / "check_release_gate.py"
    spec = importlib.util.spec_from_file_location("catus_ci_release_gate", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _load_campaign():
    path = ROOT / "scripts" / "assessment_campaign.py"
    spec = importlib.util.spec_from_file_location("catus_ci_campaign", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _load_local_benchmark():
    path = ROOT / "scripts" / "run_local_benchmark.py"
    spec = importlib.util.spec_from_file_location("catus_ci_local_benchmark", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", default="targets/benchmark/core-lab-ci.json")
    args = parser.parse_args(argv)
    try:
        run(args.output)
    except (OSError, RuntimeError, subprocess.SubprocessError) as exc:
        print("[!] Core lab benchmark failed: {}".format(exc), file=sys.stderr)
        return 1
    print("[+] Core lab benchmark passed: {}".format(args.output))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
