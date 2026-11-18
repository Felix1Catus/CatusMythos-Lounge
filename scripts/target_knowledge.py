#!/usr/bin/env python3
"""Opt-in, engagement-isolated target knowledge. No network access or probe execution."""
import argparse
import email.utils
import hashlib
import json
import math
import re
import sqlite3
import time
from contextlib import contextmanager
from datetime import timezone
from pathlib import Path
from urllib.parse import urlsplit

KINDS = ('technology', 'waf', 'auth', 'rate_limit', 'payload_failure', 'cloud_provider', 'api_inventory')
CONFIDENCES = ('observed', 'confirmed', 'hypothesis')
MAX_BUNDLE_BYTES = 10 * 1024 * 1024
MAX_BUNDLE_ROWS = 5000
MAX_HISTORY_ROWS_PER_ENGAGEMENT = 20000
MAX_TTL = {'technology': 86400, 'waf': 3600, 'auth': 900, 'rate_limit': 900,
           'payload_failure': 900, 'cloud_provider': 3600, 'api_inventory': 900}
_SAFE_RATE_HEADERS = ('ratelimit-limit', 'ratelimit-remaining', 'ratelimit-reset',
                      'x-ratelimit-limit', 'x-ratelimit-remaining', 'x-ratelimit-reset')


def canonical_origin(url):
    """Keep scheme, IDNA hostname and effective port; never accept credentials."""
    parsed = urlsplit(url)
    scheme = parsed.scheme.lower()
    if scheme not in ('http', 'https') or not parsed.hostname or parsed.username is not None or parsed.password is not None:
        raise ValueError('knowledge target must be a credential-free HTTP(S) URL')
    host = parsed.hostname.encode('idna').decode('ascii').lower()
    port = parsed.port if parsed.port is not None else (443 if scheme == 'https' else 80)
    if not 1 <= port <= 65535:
        raise ValueError('invalid target port')
    host = '[' + host + ']' if ':' in host else host
    return '{}://{}:{}'.format(scheme, host, port)


def digest(value):
    """Hash request context so cookies, tokens, query values and payloads are not persisted."""
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()).hexdigest()


def request_context(url, method, headers, parameter, original_value, baseline):
    return digest([url, method.upper(), sorted((k.lower(), v) for k, v in (headers or {}).items()),
                   parameter, original_value, baseline, 'error-based-sqli-v1'])


class KnowledgeStore:
    """Each operation uses its own connection; SQLite transactions serialize writers.

    The current view keeps the latest observation for an identical key/context;
    every write, migration snapshot, and deletion is retained in a local history
    table for audit. Expired observations never justify reuse.
    """
    request_context = staticmethod(request_context)
    digest = staticmethod(digest)

    def __init__(self, path, engagement, clock=time.time, refresh=False):
        if not isinstance(engagement, str) or not engagement.strip():
            raise ValueError('a nonempty engagement name is required')
        self.path = Path(path).expanduser().resolve()
        self.engagement = engagement.strip()
        self.clock = clock
        self.refresh = refresh
        self.reused_probes = 0
        # Require an existing parent so a typo cannot silently select another engagement directory.
        with self.connection() as db:
            version = db.execute('PRAGMA user_version').fetchone()[0]
            if version not in (0, 1, 2):
                raise ValueError('unsupported target-knowledge schema version')
            db.execute('''CREATE TABLE IF NOT EXISTS observations (
                engagement TEXT NOT NULL, origin TEXT NOT NULL, resource TEXT NOT NULL,
                kind TEXT NOT NULL, fact_key TEXT NOT NULL, context TEXT NOT NULL,
                value TEXT NOT NULL, source TEXT NOT NULL, confidence TEXT NOT NULL,
                observed_at REAL NOT NULL, expires_at REAL NOT NULL,
                PRIMARY KEY (engagement, origin, resource, kind, fact_key, context))''')
            db.execute('''CREATE TABLE IF NOT EXISTS observation_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                engagement TEXT NOT NULL, origin TEXT NOT NULL, resource TEXT NOT NULL,
                kind TEXT NOT NULL, fact_key TEXT NOT NULL, context TEXT NOT NULL,
                value TEXT NOT NULL, source TEXT NOT NULL, confidence TEXT NOT NULL,
                observed_at REAL NOT NULL, expires_at REAL NOT NULL,
                event TEXT NOT NULL, recorded_at REAL NOT NULL)''')
            db.execute('''CREATE INDEX IF NOT EXISTS observation_history_lookup
                ON observation_history (engagement, origin, resource, kind, fact_key, context, id)''')
            db.execute('''CREATE INDEX IF NOT EXISTS observation_history_prune
                ON observation_history (engagement, id DESC)''')
            if version < 2:
                db.execute('''INSERT INTO observation_history
                    (engagement, origin, resource, kind, fact_key, context, value, source,
                     confidence, observed_at, expires_at, event, recorded_at)
                    SELECT engagement, origin, resource, kind, fact_key, context, value, source,
                           confidence, observed_at, expires_at, 'migration_snapshot', observed_at
                    FROM observations AS current
                    WHERE NOT EXISTS (
                        SELECT 1 FROM observation_history AS history
                        WHERE history.engagement = current.engagement
                          AND history.origin = current.origin
                          AND history.resource = current.resource
                          AND history.kind = current.kind
                          AND history.fact_key = current.fact_key
                          AND history.context = current.context
                          AND history.event = 'migration_snapshot')''')
            self._trim_history(db)
            db.execute('PRAGMA user_version = 2')

    def _trim_history(self, db):
        """Bound local audit growth while retaining the newest engagement events."""
        db.execute('''DELETE FROM observation_history WHERE engagement = ? AND id NOT IN (
            SELECT id FROM observation_history WHERE engagement = ? ORDER BY id DESC LIMIT ?)''',
                   (self.engagement, self.engagement, MAX_HISTORY_ROWS_PER_ENGAGEMENT))

    @contextmanager
    def connection(self):
        db = sqlite3.connect(str(self.path), timeout=10)
        db.row_factory = sqlite3.Row
        try:
            with db:
                yield db
        finally:
            db.close()

    def observe(self, url, kind, key, value, source, confidence='observed', ttl=3600, context='', resource='/'):
        if kind not in KINDS or confidence not in CONFIDENCES:
            raise ValueError('unsupported knowledge kind or confidence')
        if not key or not source or not resource.startswith('/') or '?' in resource or '#' in resource:
            raise ValueError('key, source and an absolute resource path are required')
        if not math.isfinite(ttl) or ttl <= 0:
            raise ValueError('TTL must be finite and positive')
        encoded = json.dumps(value, sort_keys=True, allow_nan=False)
        if len(encoded.encode()) > 65536:
            raise ValueError('observation exceeds 64 KiB')
        now = self.clock()
        with self.connection() as db:
            record = (self.engagement, canonical_origin(url), resource, kind, key, context,
                      encoded, source, confidence, now, now + ttl)
            db.execute('''INSERT INTO observation_history
                (engagement, origin, resource, kind, fact_key, context, value, source,
                 confidence, observed_at, expires_at, event, recorded_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'observe', ?)''', (*record, now))
            db.execute('''INSERT INTO observations VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT (engagement, origin, resource, kind, fact_key, context)
                DO UPDATE SET value=excluded.value, source=excluded.source,
                confidence=excluded.confidence, observed_at=excluded.observed_at, expires_at=excluded.expires_at''',
                record)
            self._trim_history(db)

    def query(self, url, kind=None, key=None, context=None, resource=None, include_expired=False):
        conditions = ['engagement = ?', 'origin = ?']
        values = [self.engagement, canonical_origin(url)]
        for column, value in [('kind', kind), ('fact_key', key), ('context', context), ('resource', resource)]:
            if value is not None:
                conditions.append(column + ' = ?')
                values.append(value)
        if not include_expired:
            conditions.append('expires_at > ?')
            values.append(self.clock())
        with self.connection() as db:
            rows = db.execute('SELECT * FROM observations WHERE ' + ' AND '.join(conditions)
                              + ' ORDER BY kind, resource, fact_key, context', values).fetchall()
        return [dict(dict(row), value=json.loads(row['value'])) for row in rows]

    def history(self, url, kind=None, key=None, context=None, resource=None):
        """Return append-only local observation history, including expired/superseded facts."""
        conditions = ['engagement = ?', 'origin = ?']
        values = [self.engagement, canonical_origin(url)]
        for column, value in [('kind', kind), ('fact_key', key), ('context', context), ('resource', resource)]:
            if value is not None:
                conditions.append(column + ' = ?')
                values.append(value)
        with self.connection() as db:
            rows = db.execute('SELECT * FROM observation_history WHERE ' + ' AND '.join(conditions)
                              + ' ORDER BY id', values).fetchall()
        return [dict(dict(row), value=json.loads(row['value'])) for row in rows]

    def forget(self, url, kind, key=None, context=None, resource=None):
        """Delete selected observations for an explicitly refreshed target."""
        if kind not in KINDS:
            raise ValueError('unsupported knowledge kind')
        conditions = ['engagement = ?', 'origin = ?', 'kind = ?']
        values = [self.engagement, canonical_origin(url), kind]
        for column, value in [('fact_key', key), ('context', context), ('resource', resource)]:
            if value is not None:
                conditions.append(column + ' = ?')
                values.append(value)
        with self.connection() as db:
            rows = db.execute('SELECT * FROM observations WHERE ' + ' AND '.join(conditions), values).fetchall()
            now = self.clock()
            for row in rows:
                db.execute('''INSERT INTO observation_history
                    (engagement, origin, resource, kind, fact_key, context, value, source,
                     confidence, observed_at, expires_at, event, recorded_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'forget', ?)''',
                            tuple(row[column] for column in ('engagement', 'origin', 'resource', 'kind',
                                                             'fact_key', 'context', 'value', 'source',
                                                             'confidence', 'observed_at', 'expires_at')) + (now,))
            cursor = db.execute('DELETE FROM observations WHERE ' + ' AND '.join(conditions), values)
            self._trim_history(db)
            return cursor.rowcount

    def record_auth_outcome(self, url, role, status, headers=None, source='unknown', ttl=900, resource=None):
        """Store only role label, status classification, and a digest of auth headers."""
        if not isinstance(role, str) or not role.strip() or len(role) > 80:
            raise ValueError('role must be a nonempty label of at most 80 characters')
        if isinstance(status, bool) or not isinstance(status, int) or not 0 <= status <= 599:
            raise ValueError('status must be an HTTP status code or 0 for transport failure')
        if status == 0:
            outcome = 'transport_error'
        elif status in (401, 403):
            outcome = 'denied'
        elif 200 <= status < 300:
            outcome = 'success'
        else:
            outcome = 'other'
        context = digest(headers or {})
        resource = resource or urlsplit(url).path or '/'
        parsed_resource = urlsplit(resource)
        resource = parsed_resource.path if parsed_resource.scheme or parsed_resource.netloc else resource.split('?', 1)[0].split('#', 1)[0]
        if not resource.startswith('/') or len(resource) > 2048:
            raise ValueError('resource must be a bounded absolute path')
        key = 'role:' + role.strip()
        self.observe(url, 'auth', key, {'role': role.strip(), 'status': status, 'outcome': outcome},
                     source, confidence='observed', ttl=ttl, context=context, resource=resource)
        return context

    @staticmethod
    def _retry_after_seconds(headers, now=None):
        for name, value in (headers or {}).items():
            if str(name).lower() != 'retry-after':
                continue
            raw = str(value).strip()
            if re.fullmatch(r'\d{1,6}(?:\.\d{1,3})?', raw):
                return min(86400.0, float(raw))
            try:
                parsed = email.utils.parsedate_to_datetime(raw)
                if parsed.tzinfo is None:
                    parsed = parsed.replace(tzinfo=timezone.utc)
                seconds = parsed.timestamp() - (time.time() if now is None else now)
                return min(86400.0, max(0.0, seconds))
            except (TypeError, ValueError, OverflowError):
                return None
        return None

    def record_rate_limit(self, url, method, status_codes, headers=None, requests_sent=0,
                          delay=0, auth_headers=None, source='unknown', ttl=900, resource=None):
        """Store normalized limit signals; arbitrary headers and response data are excluded."""
        if not isinstance(method, str) or method.upper() not in ('GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'):
            raise ValueError('unsupported HTTP method')
        if headers is not None and not isinstance(headers, dict):
            raise ValueError('headers must be a mapping')
        if auth_headers is not None and not isinstance(auth_headers, dict):
            raise ValueError('auth_headers must be a mapping')
        if not isinstance(status_codes, dict) or len(status_codes) > 32:
            raise ValueError('status_codes must be a bounded mapping')
        normalized = {}
        for code, count in status_codes.items():
            code = str(code)
            if not re.fullmatch(r'\d{1,3}', code) or not 0 <= int(code) <= 599:
                raise ValueError('invalid HTTP status in rate-limit summary')
            if isinstance(count, bool) or not isinstance(count, int) or count < 0:
                raise ValueError('status counts must be nonnegative integers')
            normalized[code] = min(count, 100000)
        if isinstance(requests_sent, bool) or not isinstance(requests_sent, int) or not 0 <= requests_sent <= 100000:
            raise ValueError('requests_sent must be between 0 and 100000')
        if isinstance(delay, bool) or not isinstance(delay, (int, float)) or not math.isfinite(delay) or not 0 <= delay <= 60:
            raise ValueError('delay must be finite and between 0 and 60 seconds')
        safe_headers = {}
        for name, value in (headers or {}).items():
            normalized_name = str(name).lower()
            if normalized_name == 'retry-after':
                parsed = self._retry_after_seconds({name: value}, self.clock())
                if parsed is not None:
                    safe_headers['retry_after_seconds'] = parsed
            elif normalized_name in _SAFE_RATE_HEADERS and re.fullmatch(r'\d{1,12}', str(value).strip()):
                safe_headers[normalized_name] = min(int(str(value).strip()), 10**12)
        rate_seen = normalized.get('429', 0) > 0 or safe_headers.get('retry_after_seconds') is not None
        resource = resource or urlsplit(url).path or '/'
        parsed_resource = urlsplit(resource)
        resource = parsed_resource.path if parsed_resource.scheme or parsed_resource.netloc else resource.split('?', 1)[0].split('#', 1)[0]
        if not resource.startswith('/') or len(resource) > 2048:
            raise ValueError('resource must be a bounded absolute path')
        context = digest({'method': str(method).upper(), 'headers': auth_headers or {}})
        self.observe(url, 'rate_limit', 'behavior:' + str(method).upper(), {
            'method': str(method).upper(), 'status_codes': normalized,
            'rate_limit_observed': bool(rate_seen), 'requests_sent': requests_sent,
            'delay_seconds': float(delay), 'headers': safe_headers,
        }, source, confidence='observed', ttl=ttl, context=context, resource=resource)
        return context

    @staticmethod
    def _portable_value(kind, value):
        """Strict allowlist used at offline export/import boundaries."""
        if not isinstance(value, dict):
            return None
        if kind == 'auth':
            role, status, outcome = value.get('role'), value.get('status'), value.get('outcome')
            if (isinstance(role, str) and 0 < len(role) <= 80 and
                    isinstance(status, int) and not isinstance(status, bool) and 0 <= status <= 599 and
                    outcome in ('transport_error', 'denied', 'success', 'other')):
                return {'role': role, 'status': status, 'outcome': outcome}
            if set(value) == {'status'} and isinstance(status, int) and not isinstance(status, bool) and 0 <= status <= 599:
                return {'status': status}
            return None
        if kind == 'rate_limit':
            method, statuses = value.get('method'), value.get('status_codes')
            if set(value) == {'status'} and isinstance(value.get('status'), int) and not isinstance(value.get('status'), bool) and 0 <= value['status'] <= 599:
                return {'status': value['status']}
            if not isinstance(method, str) or method.upper() not in ('GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'):
                return None
            if not isinstance(statuses, dict) or len(statuses) > 32 or any(
                    not re.fullmatch(r'\d{1,3}', str(k)) or not 0 <= int(k) <= 599 or isinstance(v, bool) or
                    not isinstance(v, int) or not 0 <= v <= 100000 for k, v in statuses.items()):
                return None
            headers = value.get('headers', {})
            if not isinstance(headers, dict) or any(k not in _SAFE_RATE_HEADERS + ('retry_after_seconds',)
                    or isinstance(v, bool) or not isinstance(v, (int, float)) or not math.isfinite(v) or v < 0
                    for k, v in headers.items()):
                return None
            requests_sent, delay = value.get('requests_sent', 0), value.get('delay_seconds', 0)
            if (isinstance(requests_sent, bool) or not isinstance(requests_sent, int) or
                    not 0 <= requests_sent <= 100000 or isinstance(delay, bool) or
                    not isinstance(delay, (int, float)) or not math.isfinite(delay) or not 0 <= delay <= 60):
                return None
            limit_observed = value.get('rate_limit_observed', False)
            if not isinstance(limit_observed, bool):
                return None
            return {'method': method.upper(), 'status_codes': statuses,
                    'rate_limit_observed': limit_observed,
                    'requests_sent': requests_sent,
                    'delay_seconds': float(delay),
                    'headers': headers}
        if kind == 'technology':
            if set(value) <= {'technologies', 'versioned_components'}:
                technologies = value.get('technologies', [])
                components = value.get('versioned_components', [])
                if (not isinstance(technologies, list) or not isinstance(components, list) or
                        len(technologies) > 100 or len(components) > 100 or
                        any(not isinstance(item, str) or len(item) > 120 for item in technologies)):
                    return None
                safe_components = []
                for item in components:
                    if not isinstance(item, dict) or not isinstance(item.get('name'), str):
                        continue
                    component = {'name': item['name'][:120]}
                    version = item.get('version')
                    if isinstance(version, str) and re.fullmatch(r'[A-Za-z0-9._+-]{1,80}', version):
                        component['version'] = version
                    safe_components.append(component)
                return {'technologies': technologies, 'versioned_components': safe_components}
            if set(value) == {'name', 'version'}:
                name, version = value.get('name'), value.get('version')
                if isinstance(name, str) and len(name) <= 120 and isinstance(version, str) and re.fullmatch(r'[A-Za-z0-9._+-]{1,80}', version):
                    return {'name': name, 'version': version}
            return None
        if kind == 'waf' and isinstance(value.get('products'), list):
            return {'products': [str(x)[:120] for x in value['products'][:50]]}
        if kind == 'payload_failure' and value.get('outcome') == 'no_new_error' and value.get('status') == 200:
            return {'outcome': 'no_new_error', 'status': 200}
        if kind == 'cloud_provider' and isinstance(value.get('providers_detected'), list):
            providers = value['providers_detected']
            services = value.get('cloud_services', [])
            if (not providers or len(providers) > 50 or
                    any(not isinstance(item, str) or len(item) > 120 for item in providers) or
                    not isinstance(services, list) or len(services) > 100):
                return None
            safe_services = []
            allowed = ('type', 'hostname', 'cname', 'service', 'provider', 'header_match')
            for item in services:
                if isinstance(item, dict):
                    safe_services.append({key: item[key][:300] for key in allowed
                                          if isinstance(item.get(key), str)})
            return {'providers_detected': providers, 'cloud_services': safe_services}
        if kind == 'api_inventory' and isinstance(value, list):
            if not 0 < len(value) <= 1000:
                return None
            inventory = []
            for item in value:
                if not isinstance(item, dict):
                    return None
                path, status = item.get('path'), item.get('status')
                if (not isinstance(path, str) or not path.startswith('/') or '?' in path or '#' in path or
                        len(path) > 2048 or isinstance(status, bool) or not isinstance(status, int) or
                        not 0 <= status <= 599):
                    return None
                safe_item = {'path': path, 'status': status}
                for key, max_length in (('content_type', 200), ('api_type', 80)):
                    if isinstance(item.get(key), str):
                        safe_item[key] = item[key][:max_length]
                for key in ('response_length',):
                    candidate = item.get(key, 0)
                    if isinstance(candidate, int) and not isinstance(candidate, bool) and 0 <= candidate <= 10**9:
                        safe_item[key] = candidate
                if isinstance(item.get('auth_required'), bool):
                    safe_item['auth_required'] = item['auth_required']
                methods = item.get('methods_tested', [])
                if isinstance(methods, list) and len(methods) <= 8 and all(isinstance(m, str) and len(m) <= 16 for m in methods):
                    safe_item['methods_tested'] = methods
                versions = item.get('version_headers', {})
                safe_versions = {}
                if isinstance(versions, dict):
                    for key, candidate in versions.items():
                        if (str(key).lower() in ('api-version', 'x-api-version', 'x-version') and
                                isinstance(candidate, str) and re.fullmatch(r'v?\d+(?:\.\d+){0,3}', candidate)):
                            safe_versions[str(key).lower()] = candidate
                if safe_versions:
                    safe_item['version_headers'] = safe_versions
                inventory.append(safe_item)
            return inventory
        return None

    def export_bundle(self, url):
        origin = canonical_origin(url)
        rows = self.query(url)
        if len(rows) > MAX_BUNDLE_ROWS:
            raise ValueError('too many observations for one portable bundle')
        portable = []
        for row in rows:
            value = self._portable_value(row['kind'], row['value'])
            if value is None:
                continue
            item = {key: row[key] for key in ('resource', 'kind', 'fact_key', 'context', 'source',
                     'confidence', 'observed_at', 'expires_at')}
            item['value'] = value
            portable.append(item)
        return {'format': 'catus-target-knowledge', 'version': 1, 'engagement': self.engagement,
                'origin': origin, 'exported_at': self.clock(), 'observations': portable}

    def import_bundle(self, bundle, url):
        if not isinstance(bundle, dict) or bundle.get('format') != 'catus-target-knowledge' or bundle.get('version') != 1:
            raise ValueError('unsupported knowledge bundle format/version')
        if bundle.get('engagement') != self.engagement:
            raise ValueError('bundle engagement does not match selected engagement')
        if bundle.get('origin') != canonical_origin(url):
            raise ValueError('bundle origin does not match selected target origin')
        rows = bundle.get('observations')
        if not isinstance(rows, list) or len(rows) > MAX_BUNDLE_ROWS:
            raise ValueError('bundle observations must be a bounded list')
        now = self.clock()
        prepared = []
        for row in rows:
            if not isinstance(row, dict) or row.get('kind') not in KINDS:
                raise ValueError('invalid observation row')
            kind = row['kind']
            resource, key, context = row.get('resource'), row.get('fact_key'), row.get('context', '')
            source, confidence = row.get('source'), row.get('confidence')
            observed_at, expires_at = row.get('observed_at'), row.get('expires_at')
            if (not isinstance(resource, str) or not resource.startswith('/') or '?' in resource or '#' in resource or len(resource) > 2048 or
                    not isinstance(key, str) or not key or len(key) > 256 or
                    not isinstance(context, str) or len(context) > 128 or
                    (context and not re.fullmatch(r'[0-9a-f]{64}', context)) or
                    not isinstance(source, str) or not source or len(source) > 256 or
                    confidence not in CONFIDENCES or
                    any(isinstance(v, bool) or not isinstance(v, (int, float)) or not math.isfinite(v)
                        for v in (observed_at, expires_at))):
                raise ValueError('malformed observation metadata')
            remaining = expires_at - now
            if remaining <= 0:
                continue
            if observed_at > now + 300 or expires_at < observed_at or remaining > MAX_TTL[kind]:
                raise ValueError('observation expiry exceeds the allowed TTL for its kind')
            value = self._portable_value(kind, row.get('value'))
            if value is None:
                raise ValueError('observation value is not allowed in portable bundles')
            encoded = json.dumps(value, sort_keys=True, allow_nan=False)
            if len(encoded.encode('utf-8')) > 65536:
                raise ValueError('observation exceeds the storage size limit')
            prepared.append((self.engagement, canonical_origin(url), resource, kind, key, context,
                             encoded, source, confidence, observed_at, expires_at))
        imported = 0
        with self.connection() as db:
            for record in prepared:
                db.execute('''INSERT INTO observation_history
                    (engagement, origin, resource, kind, fact_key, context, value, source,
                     confidence, observed_at, expires_at, event, recorded_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'import', ?)''',
                           (*record, now))
                cursor = db.execute('''INSERT INTO observations VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT (engagement, origin, resource, kind, fact_key, context)
                    DO UPDATE SET value=excluded.value, source=excluded.source,
                    confidence=excluded.confidence, observed_at=excluded.observed_at, expires_at=excluded.expires_at
                    WHERE excluded.observed_at > observations.observed_at''',
                                    record)
                imported += cursor.rowcount
            self._trim_history(db)
        return imported

    def record_fingerprint(self, result):
        details = result.get('details', {})
        url = details.get('url')
        if not url:
            return
        self.observe(url, 'technology', 'stack', {
            'technologies': result.get('technologies', []),
            'versioned_components': details.get('versioned_components', []),
        }, 'recon-dominator/tech_fingerprint')
        if details.get('waf'):
            self.observe(url, 'waf', 'fingerprint', {'products': details['waf']},
                         'recon-dominator/tech_fingerprint')

    def record_response(self, url, status):
        """Status observations are signals, not confirmed auth/WAF conclusions."""
        resource = urlsplit(url).path or '/'
        if status in (401, 403):
            self.observe(url, 'auth', 'access_denied', {'status': status},
                         'webapp-exploit-hunter/sqli_tester', resource=resource, ttl=900)
        if status == 429:
            self.observe(url, 'rate_limit', 'http_429', {'status': status},
                         'webapp-exploit-hunter/sqli_tester', resource=resource, ttl=900)

    def failed_payload(self, url, context, payload):
        if self.refresh:
            return False
        rows = self.query(url, 'payload_failure', digest(payload), context,
                          urlsplit(url).path or '/')
        return any(row['confidence'] == 'observed' and isinstance(row['value'], dict)
                   and row['value'].get('outcome') == 'no_new_error'
                   for row in rows)

    def forget_failed_payload(self, url, context, payload):
        self.forget(url, 'payload_failure', digest(payload), context,
                    urlsplit(url).path or '/')

    def record_failed_payload(self, url, context, payload, status):
        if not 200 <= status < 300:
            raise ValueError('only clean 2xx payload outcomes can be cached')
        self.observe(url, 'payload_failure', digest(payload),
                     {'outcome': 'no_new_error', 'status': status},
                     'webapp-exploit-hunter/sqli_tester', ttl=900, context=context,
                     resource=urlsplit(url).path or '/')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--db', required=True, help='SQLite file in an existing engagement directory')
    parser.add_argument('--engagement', required=True)
    parser.add_argument('--target', required=True, help='Exact HTTP(S) origin or URL')
    parser.add_argument('--kind', choices=KINDS)
    parser.add_argument('--include-expired', action='store_true', help='Inspection only; expired facts are never reused')
    parser.add_argument('--history', action='store_true', help='Inspect bounded local history, including expired and superseded observations')
    transfer = parser.add_mutually_exclusive_group()
    transfer.add_argument('--export', metavar='PATH', help='Write an allowlisted offline bundle for --target')
    transfer.add_argument('--import', dest='import_path', metavar='PATH', help='Import a validated offline bundle for --target')
    args = parser.parse_args()
    try:
        store = KnowledgeStore(args.db, args.engagement)
        if args.history and (args.export or args.import_path):
            parser.error('--history cannot be combined with --export or --import')
        if args.export:
            bundle = store.export_bundle(args.target)
            encoded = json.dumps(bundle, indent=2, allow_nan=False).encode('utf-8')
            if len(encoded) > MAX_BUNDLE_BYTES:
                parser.error('export bundle exceeds 10 MiB')
            Path(args.export).write_bytes(encoded)
            print(json.dumps({'exported': len(bundle['observations']), 'path': str(Path(args.export).resolve())}))
        elif args.import_path:
            source = Path(args.import_path)
            encoded = source.read_bytes()
            if len(encoded) > MAX_BUNDLE_BYTES:
                parser.error('import bundle exceeds 10 MiB')
            bundle = json.loads(encoded.decode('utf-8'))
            imported = store.import_bundle(bundle, args.target)
            print(json.dumps({'imported': imported, 'engagement': args.engagement,
                              'origin': canonical_origin(args.target)}))
        elif args.history:
            print(json.dumps(store.history(args.target, args.kind), indent=2))
        else:
            print(json.dumps(store.query(args.target, args.kind, include_expired=args.include_expired), indent=2))
    except (OSError, ValueError, sqlite3.Error) as exc:
        parser.error(str(exc))


if __name__ == '__main__':
    main()
