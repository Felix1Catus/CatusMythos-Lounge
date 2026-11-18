#!/usr/bin/env python3
"""Optional request reservation hook used by campaign-launched skill CLIs.

The gate is dormant unless a campaign runner sets its environment. When active,
it fails closed for missing/invalid context, off-origin requests, inactive steps,
and exhausted step or campaign budgets. It records counters and event labels
only; request URLs and payloads are deliberately not persisted.
"""

import json
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
