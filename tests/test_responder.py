import sys
import asyncio
import itertools
import socket
import os
import time

import pytest

from postfix_mta_sts_resolver import netstring
from postfix_mta_sts_resolver.responder import STSSocketmapResponder, ZoneEntry
from postfix_mta_sts_resolver.resolver import STSFetchResult as FR
import postfix_mta_sts_resolver.utils as utils
import postfix_mta_sts_resolver.base_cache as base_cache

from testdata import load_testdata


class _MockResolver:
    def __init__(self, status, policy=None):
        self._status = status
        self._policy = policy
        self.calls = []

    async def resolve(self, domain, last_known_id=None):
        self.calls.append((domain, last_known_id))
        return self._status, self._policy

    async def close(self):
        pass

@pytest.fixture
async def responder():
    import postfix_mta_sts_resolver.utils as utils
    cfg = utils.populate_cfg_defaults(None)
    cfg["zones"]["test2"] = cfg["default_zone"]
    cache = utils.create_cache(cfg['cache']['type'],
                               cfg['cache']['options'])
    await cache.setup()
    resp = STSSocketmapResponder(cfg, cache)
    await resp.start()
    result = resp, cfg['host'], cfg['port']
    yield result
    await resp.stop()
    await resp.close()
    await cache.teardown()

@pytest.fixture
async def unix_responder():
    import postfix_mta_sts_resolver.utils as utils
    cfg = utils.populate_cfg_defaults({'path': '/tmp/mta-sts.sock', 'mode': 0o666})
    cfg["zones"]["test2"] = cfg["default_zone"]
    cache = utils.create_cache(cfg['cache']['type'],
                               cfg['cache']['options'])
    await cache.setup()
    resp = STSSocketmapResponder(cfg, cache)
    await resp.start()
    result = resp, cfg['path']
    yield result
    await resp.stop()
    await resp.close()
    await cache.teardown()

buf_sizes = [4096, 128, 16, 1]
reqresps = list(load_testdata('refdata'))
bufreq_pairs = tuple(itertools.product(reqresps, buf_sizes))
@pytest.mark.parametrize("params", bufreq_pairs)
@pytest.mark.asyncio
@pytest.mark.timeout(5)
async def test_responder(responder, params):
    (request, response), bufsize = params
    resp, host, port = responder
    stream_reader = netstring.StreamReader()
    string_reader = stream_reader.next_string()
    reader, writer = await asyncio.open_connection(host, port)
    try:
        writer.write(netstring.encode(request))
        res = b''
        while True:
            try:
                part = string_reader.read()
            except netstring.WantRead:
                buf = await reader.read(bufsize)
                assert buf
                stream_reader.feed(buf)
            else:
                if not part:
                    break
                res += part
        assert res == response
    finally:
        writer.close()

@pytest.mark.parametrize("params", tuple(itertools.product(reqresps, buf_sizes)))
@pytest.mark.asyncio
@pytest.mark.timeout(5)
async def test_unix_responder(unix_responder, params):
    (request, response), bufsize = params
    resp, path = unix_responder
    stream_reader = netstring.StreamReader()
    string_reader = stream_reader.next_string()
    assert os.stat(path).st_mode & 0o777 == 0o666
    reader, writer = await asyncio.open_unix_connection(path)
    try:
        writer.write(netstring.encode(request))
        res = b''
        while True:
            try:
                part = string_reader.read()
            except netstring.WantRead:
                data = await reader.read(bufsize)
                assert data
                stream_reader.feed(data)
            else:
                if not part:
                    break
                res += part
        assert res == response
    finally:
        writer.close()

@pytest.mark.asyncio
@pytest.mark.timeout(5)
async def test_empty_dialog(responder):
    resp, host, port = responder
    reader, writer = await asyncio.open_connection(host, port)
    writer.close()

@pytest.mark.asyncio
@pytest.mark.timeout(5)
async def test_corrupt_dialog(responder):
    resp, host, port = responder
    reader, writer = await asyncio.open_connection(host, port)
    msg = netstring.encode(b'test good.loc')[:-1] + b'!'
    writer.write(msg)
    assert await reader.read() == b''
    writer.close()

@pytest.mark.asyncio
@pytest.mark.timeout(5)
async def test_early_disconnect(responder):
    resp, host, port = responder
    reader, writer = await asyncio.open_connection(host, port)
    writer.write(netstring.encode(b'test good.loc'))
    writer.close()

@pytest.mark.asyncio
@pytest.mark.timeout(5)
async def test_cached(responder):
    resp, host, port = responder
    reader, writer = await asyncio.open_connection(host, port)
    stream_reader = netstring.StreamReader()
    writer.write(netstring.encode(b'test good.loc'))
    writer.write(netstring.encode(b'test good.loc'))
    answers = []
    try:
        for _ in range(2):
            string_reader = stream_reader.next_string()
            res = b''
            while True:
                try:
                    part = string_reader.read()
                except netstring.WantRead:
                    data = await reader.read(4096)
                    assert data
                    stream_reader.feed(data)
                else:
                    if not part:
                        break
                    res += part
            answers.append(res)
        assert answers[0] == answers[1]
    finally:
        writer.close()

@pytest.mark.asyncio
@pytest.mark.timeout(7)
async def test_fast_expire(responder):
    resp, host, port = responder
    reader, writer = await asyncio.open_connection(host, port)
    stream_reader = netstring.StreamReader()
    async def answer():
        string_reader = stream_reader.next_string()
        res = b''
        while True:
            try:
                part = string_reader.read()
            except netstring.WantRead:
                data = await reader.read(4096)
                assert data
                stream_reader.feed(data)
            else:
                if not part:
                    break
                res += part
        return res
    try:
        writer.write(netstring.encode(b'test fast-expire.loc'))
        answer_a = await answer()
        await asyncio.sleep(2)
        writer.write(netstring.encode(b'test fast-expire.loc'))
        answer_b = await answer()
        assert answer_a == answer_b == b'OK secure match=mail.loc servername=hostname'
    finally:
        writer.close()

@pytest.mark.parametrize("params", tuple(itertools.product(reqresps, buf_sizes)))
@pytest.mark.asyncio
@pytest.mark.timeout(5)
async def test_responder_with_custom_socket(responder, params):
    (request, response), bufsize = params
    resp, host, port = responder
    sock = await utils.create_custom_socket(host, 0, flags=0,
                                            options=[(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)])
    stream_reader = netstring.StreamReader()
    string_reader = stream_reader.next_string()
    await asyncio.get_running_loop().run_in_executor(None, sock.connect, (host, port))
    reader, writer = await asyncio.open_connection(sock=sock)
    try:
        writer.write(netstring.encode(request))
        res = b''
        while True:
            try:
                part = string_reader.read()
            except netstring.WantRead:
                data = await reader.read(bufsize)
                assert data
                stream_reader.feed(data)
            else:
                if not part:
                    break
                res += part
        assert res == response
    finally:
        writer.close()


def _make_responder(cfg, cache, resolver):
    resp = STSSocketmapResponder(cfg, cache)
    resp._default_zone = ZoneEntry(False, resolver, True, False)
    return resp


@pytest.mark.asyncio
async def test_expired_policy_forces_full_fetch():
    # P1: an expired cached policy must not be passed to the DNS change-
    # check (last_known_id must be None) so that a full HTTPS fetch happens
    # and the policy lifetime stays tied to the last fetch (RFC 8461 §3.2).
    cfg = utils.populate_cfg_defaults(None)
    cfg["cache_grace"] = 0
    cache = utils.create_cache(cfg['cache']['type'], cfg['cache']['options'])
    await cache.setup()
    try:
        resp = _make_responder(cfg, cache, _MockResolver(FR.NOT_CHANGED))
        now = time.time()  # pylint: disable=invalid-name
        await cache.set("good.loc",
                        base_cache.CacheEntry(now - 100, "pol1",
                                              {"version": "STSv1", "mode": "enforce",
                                               "mx": ["mail.loc"], "max_age": 1}))
        await resp.process_request(b'test good.loc')
        assert resp._default_zone.resolver.calls == [("good.loc", None)]
    finally:
        await cache.teardown()


@pytest.mark.asyncio
async def test_unexpired_policy_uses_cached_id():
    # P1: a not-yet-expired cached policy is passed to the DNS change-check.
    cfg = utils.populate_cfg_defaults(None)
    cfg["cache_grace"] = 0
    cache = utils.create_cache(cfg['cache']['type'], cfg['cache']['options'])
    await cache.setup()
    try:
        resp = _make_responder(cfg, cache, _MockResolver(FR.NOT_CHANGED))
        now = time.time()  # pylint: disable=invalid-name
        await cache.set("good.loc",
                        base_cache.CacheEntry(now - 10, "pol1",
                                              {"version": "STSv1", "mode": "enforce",
                                               "mx": ["mail.loc"], "max_age": 86400}))
        await resp.process_request(b'test good.loc')
        assert resp._default_zone.resolver.calls == [("good.loc", "pol1")]
    finally:
        await cache.teardown()


@pytest.mark.asyncio
async def test_not_changed_does_not_reset_ts():
    # P1: a NOT_CHANGED (DNS id match) must not reset the cached fetch
    # timestamp; the policy lifetime stays tied to the last HTTPS fetch.
    cfg = utils.populate_cfg_defaults(None)
    cfg["cache_grace"] = 0
    cache = utils.create_cache(cfg['cache']['type'], cfg['cache']['options'])
    await cache.setup()
    try:
        resp = _make_responder(cfg, cache, _MockResolver(FR.NOT_CHANGED))
        init_ts = time.time() - 10  # pylint: disable=invalid-name
        await cache.set("good.loc",
                        base_cache.CacheEntry(init_ts, "pol1",
                                              {"version": "STSv1", "mode": "enforce",
                                               "mx": ["mail.loc"], "max_age": 86400}))
        await resp.process_request(b'test good.loc')
        result = await cache.get("good.loc")
        assert result.ts == init_ts
    finally:
        await cache.teardown()
