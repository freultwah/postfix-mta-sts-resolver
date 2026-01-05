# pylint: disable=invalid-name,protected-access

import json
import logging

import psycopg
from psycopg import sql
from psycopg_pool import AsyncConnectionPool

from .defaults import POSTGRES_TIMEOUT
from .base_cache import BaseCache, CacheEntry

class PostgresCache(BaseCache):
    def __init__(self, *, timeout=POSTGRES_TIMEOUT, **kwargs):
        self._last_proactive_fetch_ts_id = 1
        psycopglogger = logging.getLogger("psycopg")
        if not psycopglogger.hasHandlers():  # pragma: no cover
            psycopglogger.addHandler(logging.NullHandler())
        self._timeout = timeout
        self._pool = None
        self.kwargs = kwargs

    async def setup(self):
        queries = [
            sql.SQL(
                "CREATE TABLE IF NOT EXISTS proactive_fetch_ts "
                "(id serial primary key, last_fetch_ts integer)"
            ),
            sql.SQL(
                "CREATE TABLE IF NOT EXISTS sts_policy_cache "
                "(id serial primary key, domain text, ts integer, "
                "pol_id text, pol_body jsonb)"
            ),
            sql.SQL(
                "CREATE UNIQUE INDEX IF NOT EXISTS sts_policy_domain "
                "ON sts_policy_cache (domain)"
            ),
            sql.SQL(
                "CREATE INDEX IF NOT EXISTS sts_policy_domain_ts "
                "ON sts_policy_cache (domain, ts)"
            ),
        ]

        conninfo = self.kwargs.get("dsn") or self.kwargs

        # Prevent implicit open
        self._pool = AsyncConnectionPool(conninfo=conninfo, open=False)
        await self._pool.open()

        async with self._pool.connection() as conn:
            async with conn.transaction():
                for q in queries:
                    await conn.execute(q)

    async def get_proactive_fetch_ts(self):
        async with self._pool.connection() as conn:
            async with conn.cursor() as cur:
                await cur.execute(
                    sql.SQL("SELECT last_fetch_ts FROM proactive_fetch_ts WHERE id = %s"),
                    [self._last_proactive_fetch_ts_id]
                )
                res = await cur.fetchone()
        return int(res[0]) if res is not None else 0

    async def set_proactive_fetch_ts(self, timestamp):
        async with self._pool.connection() as conn:
            async with conn.transaction():
                await conn.execute(
                    sql.SQL("""
                        INSERT INTO proactive_fetch_ts (last_fetch_ts, id)
                        VALUES (%s, %s)
                        ON CONFLICT (id) DO UPDATE SET last_fetch_ts = EXCLUDED.last_fetch_ts
                    """),
                    [int(timestamp), self._last_proactive_fetch_ts_id]
                )

    async def get(self, key):
        async with self._pool.connection() as conn:
            async with conn.cursor() as cur:
                await cur.execute(
                    sql.SQL("SELECT ts, pol_id, pol_body FROM sts_policy_cache WHERE domain=%s"),
                    [key]
                )
                res = await cur.fetchone()
        if res is not None:
            ts, pol_id, pol_body = res
            ts = int(ts)
            # Handle different possible types of pol_body
            if isinstance(pol_body, dict):
                return CacheEntry(ts, pol_id, pol_body)
            elif isinstance(pol_body, str):
                return CacheEntry(ts, pol_id, json.loads(pol_body))
            else:
                return CacheEntry(ts, pol_id, None)
        else:
            return None

    async def set(self, key, value):
        ts, pol_id, pol_body = value
        # Convert dictionary to JSON string if needed
        if isinstance(pol_body, dict):
            pol_body_json = json.dumps(pol_body)
        else:
            pol_body_json = pol_body

        async with self._pool.connection() as conn:
            async with conn.transaction():
                await conn.execute(
                    sql.SQL("""
                        INSERT INTO sts_policy_cache (domain, ts, pol_id, pol_body) VALUES (%s, %s, %s, %s)
                        ON CONFLICT (domain) DO UPDATE
                        SET ts = EXCLUDED.ts, pol_id = EXCLUDED.pol_id, pol_body = EXCLUDED.pol_body
                        WHERE sts_policy_cache.ts < EXCLUDED.ts
                    """),
                    [key, int(ts), pol_id, pol_body_json]
                )

    async def scan(self, token, amount_hint):
        if token is None:
            token = 1

        async with self._pool.connection() as conn:
            async with conn.cursor() as cur:
                await cur.execute(
                    sql.SQL("SELECT id, ts, pol_id, pol_body, domain FROM sts_policy_cache "
                           "WHERE id >= %s ORDER BY id ASC LIMIT %s"),
                    [token, amount_hint]
                )
                res = await cur.fetchall()

        if res:
            result = []
            new_token = token
            for row in res:
                rowid, ts, pol_id, pol_body, domain = row
                ts = int(ts)
                rowid = int(rowid)
                new_token = max(new_token, rowid)
                # Handle different possible types of pol_body
                if isinstance(pol_body, dict):
                    result.append((domain, CacheEntry(ts, pol_id, pol_body)))
                elif isinstance(pol_body, str):
                    result.append((domain, CacheEntry(ts, pol_id, json.loads(pol_body))))
                else:
                    result.append((domain, CacheEntry(ts, pol_id, None)))
            new_token += 1
            return new_token, result
        else:
            return None, []

    async def teardown(self):
        if self._pool is not None:
            await self._pool.close()
