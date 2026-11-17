#!/usr/bin/env python3
"""Opt-in, engagement-isolated target knowledge. No network access or probe execution."""
import argparse
import hashlib
import json
import math
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path
from urllib.parse import urlsplit

KINDS = ('technology', 'waf', 'auth', 'rate_limit', 'payload_failure')
CONFIDENCES = ('observed', 'confirmed', 'hypothesis')


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

    Last observation wins for an identical key/context. Expired observations never
    justify reuse; query(include_expired=True) is inspection only.
    """
    request_context = staticmethod(request_context)

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
            if version not in (0, 1):
                raise ValueError('unsupported target-knowledge schema version')
            db.execute('''CREATE TABLE IF NOT EXISTS observations (
                engagement TEXT NOT NULL, origin TEXT NOT NULL, resource TEXT NOT NULL,
                kind TEXT NOT NULL, fact_key TEXT NOT NULL, context TEXT NOT NULL,
                value TEXT NOT NULL, source TEXT NOT NULL, confidence TEXT NOT NULL,
                observed_at REAL NOT NULL, expires_at REAL NOT NULL,
                PRIMARY KEY (engagement, origin, resource, kind, fact_key, context))''')
            db.execute('PRAGMA user_version = 1')

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
        if not key or not source or not resource.startswith('/'):
            raise ValueError('key, source and an absolute resource path are required')
        if not math.isfinite(ttl) or ttl <= 0:
            raise ValueError('TTL must be finite and positive')
        encoded = json.dumps(value, sort_keys=True, allow_nan=False)
        if len(encoded.encode()) > 65536:
            raise ValueError('observation exceeds 64 KiB')
        now = self.clock()
        with self.connection() as db:
            db.execute('''INSERT INTO observations VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT (engagement, origin, resource, kind, fact_key, context)
                DO UPDATE SET value=excluded.value, source=excluded.source,
                confidence=excluded.confidence, observed_at=excluded.observed_at, expires_at=excluded.expires_at''',
                (self.engagement, canonical_origin(url), resource, kind, key, context,
                 encoded, source, confidence, now, now + ttl))

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
        with self.connection() as db:
            db.execute('DELETE FROM observations WHERE engagement=? AND origin=? AND resource=? '
                       'AND kind=? AND fact_key=? AND context=?',
                       (self.engagement, canonical_origin(url), urlsplit(url).path or '/',
                        'payload_failure', digest(payload), context))

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
    args = parser.parse_args()
    try:
        store = KnowledgeStore(args.db, args.engagement)
        print(json.dumps(store.query(args.target, args.kind, include_expired=args.include_expired), indent=2))
    except (OSError, ValueError, sqlite3.Error) as exc:
        parser.error(str(exc))


if __name__ == '__main__':
    main()
