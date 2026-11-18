#!/usr/bin/env python3
"""Optional request reservation hook used by campaign-launched skill CLIs.

The gate is dormant unless a campaign runner sets its environment. When active,
it fails closed for missing/invalid context, off-origin requests, inactive steps,
and exhausted step or campaign budgets. It records counters and event labels
only; request URLs and payloads are deliberately not persisted.
"""

import json
import ipaddress
import ntpath
import os
import sqlite3
import threading
import time
from urllib.parse import urlsplit


class CampaignGateError(RuntimeError):
    """A campaign gate prevented an outbound HTTP request."""


_STATUS_LOCK = threading.Lock()
_STATUS_FLAGS = {"budget_exhausted": False, "off_origin_requests_blocked": False,
                 "gate_errors": False}


def _mark_status(flag):
    status_path = os.environ.get("CATUS_CAMPAIGN_GATE_STATUS")
    if not status_path or flag not in _STATUS_FLAGS:
        return
    with _STATUS_LOCK:
        _STATUS_FLAGS[flag] = True
        temporary = status_path + ".tmp"
        try:
            with open(temporary, "w", encoding="utf-8") as stream:
                json.dump(_STATUS_FLAGS, stream, sort_keys=True)
            os.replace(temporary, status_path)
        except OSError:
            pass


def _origin(value):
    if not isinstance(value, str) or not value or any(char in value for char in "\r\n\\"):
        return None
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError:
        return None
    if (parsed.scheme.lower() not in ("http", "https") or not parsed.hostname
            or parsed.username is not None or parsed.password is not None or parsed.fragment):
        return None
    try:
        host = parsed.hostname.encode("idna").decode("ascii").lower()
    except UnicodeError:
        return None
    port = port if port is not None else (443 if parsed.scheme.lower() == "https" else 80)
    host = "[" + host + "]" if ":" in host else host
    return "{}://{}:{}".format(parsed.scheme.lower(), host, port)


def _reserve(database, campaign_id, step_id, request_url, allowed_origin):
    if _origin(request_url) != allowed_origin:
        _mark_status("off_origin_requests_blocked")
        raise CampaignGateError("campaign gate blocked an off-origin request")
    connection = sqlite3.connect(database, timeout=15)
    try:
        connection.execute("PRAGMA busy_timeout=15000")
        connection.execute("BEGIN IMMEDIATE")
        campaign = connection.execute(
            "SELECT request_budget, requests_used FROM campaigns WHERE campaign_id=?",
            (campaign_id,)).fetchone()
        step = connection.execute(
            "SELECT requests_used, status FROM campaign_steps WHERE campaign_id=? AND step_id=?",
            (campaign_id, step_id)).fetchone()
        registry = connection.execute(
            "SELECT max_requests FROM campaign_step_registry WHERE campaign_id=? AND step_id=?",
            (campaign_id, step_id)).fetchone()
        if campaign is None or step is None or registry is None:
            raise CampaignGateError("campaign gate context is not registered")
        if step[1] != "running":
            raise CampaignGateError("campaign gate requires a running step")
        if campaign[1] >= campaign[0] or step[0] >= registry[0]:
            _mark_status("budget_exhausted")
            raise CampaignGateError("campaign request budget exhausted")
        connection.execute("UPDATE campaigns SET requests_used=requests_used+1 WHERE campaign_id=?",
                           (campaign_id,))
        connection.execute("UPDATE campaign_steps SET requests_used=requests_used+1, updated_at=? "
                           "WHERE campaign_id=? AND step_id=?",
                           (time.time_ns(), campaign_id, step_id))
        connection.execute(
            "INSERT INTO campaign_events(campaign_id, step_id, event, created_at) VALUES (?, ?, ?, ?)",
            (campaign_id, step_id, "request_reserved", time.time_ns()))
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def reserve_from_environment(url, method="GET"):
    """Reserve one request if campaign mode is active; otherwise do nothing."""
    database = os.environ.get("CATUS_CAMPAIGN_GATE_DB")
    if not database:
        return False
    campaign_id = os.environ.get("CATUS_CAMPAIGN_GATE_CAMPAIGN")
    step_id = os.environ.get("CATUS_CAMPAIGN_GATE_STEP")
    allowed_origin = os.environ.get("CATUS_CAMPAIGN_GATE_ORIGIN")
    if not campaign_id or not step_id or not allowed_origin or _origin(allowed_origin) != allowed_origin:
        _mark_status("gate_errors")
        raise CampaignGateError("campaign gate environment is incomplete or invalid")
    try:
        _reserve(database, campaign_id, step_id, url, allowed_origin)
    except (sqlite3.Error, CampaignGateError):
        _mark_status("gate_errors")
        raise
    return True


def reserve_socket_from_environment(host, port):
    """Reserve one raw TCP probe against the selected origin or explicit endpoint scope."""
    return reserve_network_endpoint_from_environment(host, port, "tcp")


def _normalize_network_host(host):
    value = str(host).strip().strip("[]").rstrip(".")
    try:
        return ipaddress.ip_address(value).compressed.lower()
    except ValueError:
        return value.encode("idna").decode("ascii").lower()


def reserve_network_endpoint_from_environment(host, port, protocol="tcp"):
    """Reserve one explicitly scoped TCP/UDP operation."""
    database = os.environ.get("CATUS_CAMPAIGN_GATE_DB")
    if not database:
        return False
    allowed_origin = os.environ.get("CATUS_CAMPAIGN_GATE_ORIGIN")
    campaign_id = os.environ.get("CATUS_CAMPAIGN_GATE_CAMPAIGN")
    step_id = os.environ.get("CATUS_CAMPAIGN_GATE_STEP")
    try:
        parsed = urlsplit(allowed_origin or "")
        allowed_port = parsed.port or (443 if parsed.scheme.lower() == "https" else 80)
        normalized_host = _normalize_network_host(host)
        allowed_host = _normalize_network_host(parsed.hostname or "")
        normalized_port = int(port)
        valid = (_origin(allowed_origin) == allowed_origin and parsed.scheme.lower() in ("http", "https")
                 and protocol in ("tcp", "udp") and 1 <= normalized_port <= 65535
                 and bool(campaign_id) and bool(step_id))
    except (AttributeError, UnicodeError, TypeError, ValueError):
        valid = False
        normalized_port = 0
        normalized_host = ""
        allowed_host = ""
        allowed_port = 0
    if not valid:
        _mark_status("off_origin_requests_blocked")
        raise CampaignGateError("campaign gate blocked an invalid network endpoint")
    origin_scoped = protocol == "tcp" and normalized_host == allowed_host and normalized_port == allowed_port
    if not origin_scoped:
        connection = sqlite3.connect(database, timeout=15)
        try:
            scoped = connection.execute(
                "SELECT 1 FROM campaign_network_endpoints WHERE campaign_id=? AND host=? "
                "AND protocol=? AND port=?",
                (campaign_id, normalized_host, protocol, normalized_port)).fetchone()
        except sqlite3.Error:
            scoped = None
        finally:
            connection.close()
        if scoped is None:
            _mark_status("off_origin_requests_blocked")
            raise CampaignGateError("campaign gate blocked an out-of-scope network endpoint")
    _reserve(database, campaign_id, step_id, allowed_origin, allowed_origin)
    return True


def network_endpoint_is_scoped(host, port, protocol="tcp"):
    """Check a Python socket destination against campaign scope without charging it."""
    database = os.environ.get("CATUS_CAMPAIGN_GATE_DB")
    if not database:
        return True
    allowed_origin = os.environ.get("CATUS_CAMPAIGN_GATE_ORIGIN")
    try:
        parsed = urlsplit(allowed_origin or "")
        allowed_port = parsed.port or (443 if parsed.scheme.lower() == "https" else 80)
        normalized_host = _normalize_network_host(host)
        allowed_host = _normalize_network_host(parsed.hostname or "")
        normalized_port = int(port)
        if (_origin(allowed_origin) != allowed_origin or protocol not in ("tcp", "udp")
                or not 1 <= normalized_port <= 65535):
            return False
    except (AttributeError, TypeError, UnicodeError, ValueError):
        return False
    if protocol == "tcp" and normalized_port == allowed_port:
        allowed_addresses = set()
        try:
            decoded = json.loads(os.environ.get("CATUS_CAMPAIGN_GATE_ORIGIN_ADDRESSES", "[]"))
            allowed_addresses.update(_normalize_network_host(item) for item in decoded
                                     if isinstance(item, str))
        except (TypeError, ValueError, json.JSONDecodeError):
            pass
        if normalized_host == allowed_host or normalized_host in allowed_addresses:
            return True
    try:
        connection = sqlite3.connect(database, timeout=5)
        try:
            return connection.execute(
                "SELECT 1 FROM campaign_network_endpoints WHERE campaign_id=? AND host=? "
                "AND protocol=? AND port=?",
                (os.environ.get("CATUS_CAMPAIGN_GATE_CAMPAIGN"), normalized_host,
                 protocol, normalized_port),
            ).fetchone() is not None
        finally:
            connection.close()
    except sqlite3.Error:
        return False


_KNOWN_NETWORK_EXECUTABLES = {
    "amass", "curl", "dig", "ffuf", "gobuster", "httpx", "naabu", "nmap",
    "nuclei", "puredns", "subfinder", "wget", "whois",
}


def reserve_external_command_from_environment(command, *, shell=False):
    """Meter supported network commands or fail closed before launching them.

    The current adapters are one-request curl, one-query dig with an explicitly
    scoped resolver, and one TCP connect-scan nmap port. Variable-volume tools
    and commands with redirects, scripts, or hidden target lists are rejected.
    """
    if not os.environ.get("CATUS_CAMPAIGN_GATE_DB"):
        return False
    if shell:
        _mark_status("gate_errors")
        raise CampaignGateError("campaign gate blocks shell-mediated subprocesses")
    if isinstance(command, str):
        _mark_status("gate_errors")
        raise CampaignGateError("campaign gate requires an argument-list subprocess command")
    try:
        values = [str(value) for value in command]
        executable = ntpath.basename(values[0]).lower().removesuffix(".exe")
    except (IndexError, TypeError):
        _mark_status("gate_errors")
        raise CampaignGateError("campaign gate blocks an invalid child process command")
    if executable not in _KNOWN_NETWORK_EXECUTABLES:
        _mark_status("gate_errors")
        raise CampaignGateError(
            "campaign gate blocks child processes without an explicit command adapter: "
            + (executable or "<empty>")
        )
    if ntpath.basename(values[0]) != values[0]:
        _mark_status("gate_errors")
        raise CampaignGateError("campaign network commands must use the registered executable name from PATH")
    if any(value in values for value in ("--help", "-h", "--version", "-version")):
        return values
    if executable == "nmap":
        if len(values) == 4 and values[1] == "-p":
            port_text, host = values[2], values[3]
        elif len(values) == 3 and values[1].startswith("-p"):
            port_text, host = values[1][2:], values[2]
        else:
            port_text, host = "", ""
        try:
            address = ipaddress.ip_address(host)
            port = int(port_text)
        except ValueError:
            address, port = None, 0
        if address is None or str(port) != port_text or not 1 <= port <= 65535:
            _mark_status("gate_errors")
            raise CampaignGateError("campaign nmap adapter requires one literal IP and one explicit TCP port")
        reserve_network_endpoint_from_environment(str(address), port, "tcp")
        return [values[0], "-sT", "-Pn", "-n", "--max-retries", "0", "-p", str(port), str(address)]
    if executable == "dig":
        query_types = {"A", "AAAA", "CNAME", "MX", "NS", "PTR", "SOA", "SRV", "TXT"}
        resolvers = [value[1:] for value in values if value.startswith("@")]
        questions = [value for value in values[1:] if not value.startswith(("+", "-", "@"))
                     and value.upper() not in query_types]
        requested_types = [value.upper() for value in values[1:] if value.upper() in query_types]
        allowed_options = {"+tcp", "+notcp", "+short", "+noall", "+answer"}
        safe_options = [value.lower() for value in values[1:] if value.lower() in allowed_options]
        unsupported = [value for value in values[1:] if value.startswith(("+", "-"))
                       and value.lower() not in allowed_options]
        origin_host = (urlsplit(os.environ.get("CATUS_CAMPAIGN_GATE_ORIGIN", "")).hostname or "")
        try:
            question = _normalize_network_host(questions[-1]) if questions else ""
            expected = _normalize_network_host(origin_host)
        except (UnicodeError, ValueError):
            question = expected = ""
        if (len(resolvers) != 1 or not question or question != expected or len(questions) != 1
                or len(requested_types) > 1 or unsupported):
            _mark_status("gate_errors")
            raise CampaignGateError("campaign dig adapter allows one scoped hostname, resolver, and query type")
        tcp = "+tcp" in safe_options
        reserve_network_endpoint_from_environment(resolvers[0], 53, "tcp" if tcp else "udp")
        query_type = requested_types[0] if requested_types else "A"
        resolved_resolvers = {}
        try:
            resolved_resolvers = json.loads(os.environ.get(
                "CATUS_CAMPAIGN_GATE_ENDPOINT_ADDRESSES", "{}"))
        except (TypeError, ValueError, json.JSONDecodeError):
            pass
        resolver_addresses = resolved_resolvers.get(_normalize_network_host(resolvers[0]), [])
        try:
            resolver_host = str(ipaddress.ip_address(resolver_addresses[0]))
        except (IndexError, TypeError, ValueError):
            resolver_host = resolvers[0]
        return [values[0], "-r", "@" + resolver_host, question, query_type, "+tries=1", "+time=3",
                *safe_options]
    if executable == "curl":
        if any(value in values for value in (
                "-L", "--location", "--location-trusted", "--proxy", "-x", "--noproxy",
                "--connect-to",
                "--resolve", "--config", "-K", "--next", "--parallel", "--parallel-immediate",
                "--retry", "--retry-connrefused", "--retry-all-errors")) or any(
                    value.startswith(("--retry-", "--retry=", "--config=", "--connect-to=",
                                      "--resolve=", "--proxy=", "--noproxy=", "-K", "-x"))
                    for value in values[1:]):
            _mark_status("gate_errors")
            raise CampaignGateError("campaign curl adapter disallows retries, redirects, and routing overrides")
        urls = []
        for index, value in enumerate(values[1:], 1):
            if value.lower() == "--url" and index + 1 < len(values):
                urls.append(values[index + 1])
            elif value.lower().startswith("--url="):
                urls.append(value.split("=", 1)[1])
            elif (value.lower().startswith(("http://", "https://"))
                  and values[index - 1].lower() != "--url"):
                urls.append(value)
        if any(any(character in value for character in "{}[]")
               for value in urls):
            _mark_status("gate_errors")
            raise CampaignGateError("campaign curl adapter disallows URL globbing")
        if len(urls) != 1:
            _mark_status("gate_errors")
            raise CampaignGateError("campaign curl adapter requires exactly one explicit HTTP(S) URL")
        method = "GET"
        for index, value in enumerate(values[:-1]):
            if value in ("-X", "--request"):
                method = values[index + 1].upper()
        reserve_from_environment(urls[0], method)
        result = [values[0], "--disable", "--noproxy", "*", *values[1:]]
        try:
            resolved_origin = json.loads(os.environ.get(
                "CATUS_CAMPAIGN_GATE_ORIGIN_ADDRESSES", "[]"))
        except (TypeError, ValueError, json.JSONDecodeError):
            resolved_origin = []
        parsed_url = urlsplit(urls[0])
        if isinstance(resolved_origin, list) and resolved_origin and parsed_url.hostname:
            port = parsed_url.port or (443 if parsed_url.scheme.lower() == "https" else 80)
            try:
                resolved_address = str(ipaddress.ip_address(resolved_origin[0]))
            except (TypeError, ValueError):
                resolved_address = ""
            if resolved_address:
                result.extend(("--resolve", "{}:{}:{}".format(
                    parsed_url.hostname, port, resolved_address)))
        return result
    if executable == "whois":
        _mark_status("gate_errors")
        raise CampaignGateError("campaign whois adapter is unavailable until its referral behavior can be bounded")
    _mark_status("gate_errors")
    raise CampaignGateError("network executable has no campaign-compatible request adapter: " + executable)
