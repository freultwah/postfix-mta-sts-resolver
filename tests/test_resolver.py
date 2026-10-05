import collections.abc
import contextlib
import os
from types import SimpleNamespace

import pytest

import postfix_mta_sts_resolver.resolver as resolver
from postfix_mta_sts_resolver.resolver import STSFetchResult as FR
from postfix_mta_sts_resolver.resolver import STSResolver as Resolver
from postfix_mta_sts_resolver.resolver import _extract_txt_records


def _aiodns4_result(*txt_bytes):
    """Build an aiodns >= 4.0 query_dns() style DNSResult."""
    answer = [
        SimpleNamespace(data=SimpleNamespace(data=b)) for b in txt_bytes
    ]
    return SimpleNamespace(answer=answer)


def _aiodns3_result(*texts):
    """Build an aiodns 3.x query() style list of records."""
    return [SimpleNamespace(text=t) for t in texts]


def test_extract_txt_records_aiodns4():
    result = _aiodns4_result(
        b'v=STSv1;id=20200428155800Z', b'other record')
    assert _extract_txt_records(result) == [
        'v=STSv1;id=20200428155800Z', 'other record']


def test_extract_txt_records_aiodns3():
    result = _aiodns3_result(
        'v=STSv1;id=20200428155800Z', b'bytes record')
    assert _extract_txt_records(result) == [
        'v=STSv1;id=20200428155800Z', 'bytes record']


def test_extract_txt_records_drops_non_ascii():
    result = _aiodns4_result(b'v=STSv1;id=x', b'\xff\xfe invalid')
    assert _extract_txt_records(result) == ['v=STSv1;id=x']

@contextlib.contextmanager
def set_env(**environ):
    old_environ = dict(os.environ)
    os.environ.update(environ)
    try:
        yield
    finally:
        os.environ.clear()
        os.environ.update(old_environ)

@pytest.mark.parametrize("domain", ['good.loc', 'good.loc.'])
@pytest.mark.asyncio
@pytest.mark.timeout(5)
async def test_simple_resolve(domain):
    resolver = Resolver(timeout=1)
    status, (ver, policy) = await resolver.resolve(domain)
    assert status is FR.VALID
    assert 'mx' in policy
    assert isinstance(policy['mx'], collections.abc.Iterable)
    assert all(isinstance(dom, str) for dom in policy['mx'])
    assert policy['version'] == 'STSv1'
    assert policy['mode'] in ('none', 'enforce', 'testing')
    assert isinstance(policy['max_age'], int)
    assert policy['max_age'] > 0
    assert isinstance(ver, str)
    assert ver
    status, body2 = await resolver.resolve(domain, ver)
    assert status is FR.NOT_CHANGED
    assert body2 is None
    await resolver.close()

@pytest.mark.parametrize("domain,expected_status", [("good.loc", FR.VALID),
                                                    ("good.loc.", FR.VALID),
                                                    ("testing.loc", FR.VALID),
                                                    (".good.loc", FR.NONE),
                                                    (".good.loc.", FR.NONE),
                                                    ("valid-none.loc", FR.VALID),
                                                    ("no-record.loc", FR.NONE),
                                                    ("no-data.loc", FR.NONE),
                                                    ("bad-record1.loc", FR.NONE),
                                                    ("bad-record2.loc", FR.NONE),
                                                    ("bad-record3.loc", FR.NONE),
                                                    ("bad-policy1.loc", FR.FETCH_ERROR),
                                                    ("bad-policy2.loc", FR.FETCH_ERROR),
                                                    ("bad-policy3.loc", FR.FETCH_ERROR),
                                                    ("bad-policy4.loc", FR.FETCH_ERROR),
                                                    ("bad-policy5.loc", FR.FETCH_ERROR),
                                                    ("bad-policy6.loc", FR.FETCH_ERROR),
                                                    ("bad-policy7.loc", FR.FETCH_ERROR),
                                                    ("bad-policy8.loc", FR.FETCH_ERROR),
                                                    ("static-overlength.loc", FR.FETCH_ERROR),
                                                    ("chunked-overlength.loc", FR.FETCH_ERROR),
                                                    ("bad-cert1.loc", FR.FETCH_ERROR),
                                                    ("bad-cert2.loc", FR.FETCH_ERROR),
                                                    ])
@pytest.mark.asyncio
@pytest.mark.timeout(5)
async def test_resolve_status(domain, expected_status):
    resolver = Resolver(timeout=1)
    status, body = await resolver.resolve(domain)
    assert status is expected_status
    if expected_status is FR.VALID:
        ver, pol = body
        if pol['mode'] != 'none':
            assert isinstance(pol['mx'], collections.abc.Iterable)
            assert pol['mx']
    else:
        assert body is None
    await resolver.close()

@pytest.mark.asyncio
@pytest.mark.timeout(5)
async def test_resolve_dns_timeout():
    resolver = Resolver(timeout=1)
    status, body = await resolver.resolve('blackhole.loc')
    assert status is FR.FETCH_ERROR
    assert body is None
    await resolver.close()

@pytest.mark.asyncio
@pytest.mark.timeout(5)
async def test_proxy():
    with set_env(https_proxy='http://127.0.0.2:1380'):
        resolver = Resolver()
    status, (ver, pol) = await resolver.resolve("good.loc")
    assert status is FR.VALID
    assert pol['mode'] == 'enforce'
    assert pol['mx'] == ['mail.loc']
    await resolver.close()

@pytest.mark.asyncio
@pytest.mark.timeout(5)
async def test_proxy_negative():
    with set_env(https_proxy='http://127.0.0.2:18888'):
        resolver = Resolver()
    status, body = await resolver.resolve("good.loc")
    assert status is FR.FETCH_ERROR
    assert body is None
    await resolver.close()
