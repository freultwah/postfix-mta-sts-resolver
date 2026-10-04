import asyncio
import tempfile
from unittest import mock

import pytest

import postfix_mta_sts_resolver.sqlite_cache as sqlite_cache
from postfix_mta_sts_resolver.sqlite_cache import SqliteConnPool

CONN_INIT = [
    "PRAGMA journal_mode=WAL",
    "PRAGMA synchronous=NORMAL",
]

@pytest.fixture
def dbfile():
    with tempfile.NamedTemporaryFile() as f:
        yield f.name

@pytest.mark.asyncio
async def test_raises_re(dbfile):
    pool = SqliteConnPool(1, (dbfile,), init_queries=CONN_INIT)
    with pytest.raises(RuntimeError):
        async with pool.borrow() as conn:
            pass

@pytest.mark.asyncio
@pytest.mark.timeout(2)
async def test_basic(dbfile):
    pool = SqliteConnPool(1, (dbfile,), init_queries=CONN_INIT)
    await pool.prepare()
    try:
        async with pool.borrow() as conn:
            await conn.execute("create table if not exists t (id int)")
        async with pool.borrow() as conn:
            for i in range(10):
                await conn.execute("insert into t (id) values (?)", (i,))
            await conn.commit()
        async with pool.borrow() as conn:
            async with conn.execute('select sum(id) from t') as cur:
                res = await cur.fetchone()
        assert res[0] == sum(range(10))
    finally:
        await pool.stop()

@pytest.mark.asyncio
@pytest.mark.timeout(2)
async def test_early_stop(dbfile):
    pool = SqliteConnPool(5, (dbfile,), init_queries=CONN_INIT)
    await pool.prepare()
    async with pool.borrow() as conn:
        await pool.stop()
        await conn.execute("create table if not exists t (id int)")
        for i in range(10):
            await conn.execute("insert into t (id) values (?)", (i,))
        await conn.commit()
        async with conn.execute('select sum(id) from t') as cur:
            res = await cur.fetchone()
    assert res[0] == sum(range(10))

@pytest.mark.asyncio
@pytest.mark.timeout(2)
async def test_borrow_timeout(dbfile):
    pool = SqliteConnPool(1, (dbfile,), init_queries=CONN_INIT)
    await pool.prepare()
    try:
        async with pool.borrow(1) as conn1:
            with pytest.raises(asyncio.TimeoutError):
                async with pool.borrow(1) as conn2:
                    pass
    finally:
        await pool.stop()

@pytest.mark.asyncio
@pytest.mark.timeout(2)
async def test_conn_reuse(dbfile):
    pool = SqliteConnPool(1, (dbfile,), init_queries=CONN_INIT)
    await pool.prepare()
    try:
        async with pool.borrow() as conn:
            first = conn
        async with pool.borrow() as conn:
            second = conn
        assert first is second
    finally:
        await pool.stop()

@pytest.mark.asyncio
@pytest.mark.timeout(2)
async def test_conn_ressurection(dbfile):
    class TestError(Exception):
        pass
    pool = SqliteConnPool(1, (dbfile,), init_queries=CONN_INIT)
    await pool.prepare()
    try:
        with pytest.raises(TestError):
            async with pool.borrow() as conn:
                first = conn
                async with conn.execute("SELECT 1") as cur:
                    result = await cur.fetchone()
                    assert result[0] == 1
                raise TestError()
        async with pool.borrow() as conn:
            async with conn.execute("SELECT 1") as cur:
                result = await cur.fetchone()
                assert result[0] == 1
            second = conn
        assert first is not second
    finally:
        await pool.stop()

@pytest.mark.asyncio
@pytest.mark.timeout(2)
async def test_bad_init(dbfile):
    pool = SqliteConnPool(1, (dbfile,), init_queries=['BOGUSQUERY'])
    try:
        with pytest.raises(Exception):
            await pool.prepare()
    finally:
        await pool.stop()

@pytest.mark.asyncio
@pytest.mark.timeout(2)
async def test_new_conn_closes_on_cancellation(dbfile):
    # A CancelledError (a BaseException on modern Python) raised while
    # initializing a connection must still close it, otherwise the
    # connection leaks.
    closed = []
    class FakeCursor:
        async def __aenter__(self):
            return self
        async def __aexit__(self, *exc):
            return False
        async def execute(self, q):
            raise asyncio.CancelledError()
    class FakeDB:
        def cursor(self):
            return FakeCursor()
        async def close(self):
            closed.append(True)
    pool = SqliteConnPool(1, (dbfile,), init_queries=CONN_INIT)
    with mock.patch.object(sqlite_cache.aiosqlite, "connect",
                           new=mock.AsyncMock(return_value=FakeDB())):
        with pytest.raises(asyncio.CancelledError):
            await pool._new_conn()
    assert closed == [True]
