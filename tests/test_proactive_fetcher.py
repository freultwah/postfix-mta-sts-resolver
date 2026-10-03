import asyncio
import time

import pytest

from postfix_mta_sts_resolver import base_cache, utils
from postfix_mta_sts_resolver.proactive_fetcher import STSProactiveFetcher

from postfix_mta_sts_resolver.utils import populate_cfg_defaults, create_cache


@pytest.fixture
async def cache():
    cfg = populate_cfg_defaults(None)
    cache = create_cache(cfg['cache']['type'],
                         cfg['cache']['options'])
    await cache.setup()
    yield cache
    await cache.teardown()


# The proactive fetcher always performs a full HTTPS fetch (it does not rely
# on the DNS ID change-check), so any domain with a valid policy is refreshed
# (ts reset, body present) regardless of the cached policy ID.
@pytest.mark.parametrize("domain, init_policy_id, expected_policy_id, ts_reset, body_present",
                         [("good.loc", "19990907T090909", "20180907T090909", True, True),
                          ("good.loc", "20180907T090909", "20180907T090909", True, True),
                          ("valid-none.loc", "19990907T090909", "20180907T090909", True, True),
                          ("blackhole.loc", "19990907T090909", "19990907T090909", False, False),
                          ("bad-record1.loc", "19990907T090909", "19990907T090909", False, False),
                          ("bad-policy1.loc", "19990907T090909", "19990907T090909", False, False)
                          ])
@pytest.mark.asyncio
@pytest.mark.timeout(10)
async def test_cache_update(cache,
                            domain, init_policy_id,
                            expected_policy_id, ts_reset, body_present):
    cfg = utils.populate_cfg_defaults(None)
    cfg['proactive_policy_fetching']['enabled'] = True
    cfg['proactive_policy_fetching']['interval'] = 1
    cfg['proactive_policy_fetching']['grace_ratio'] = 1000
    cfg["default_zone"]["timeout"] = 1
    cfg['shutdown_timeout'] = 1

    init_ts = time.time() - 10
    await cache.set(domain, base_cache.CacheEntry(init_ts, init_policy_id, {}))

    pf = STSProactiveFetcher(cfg, cache)
    await pf.start()

    # Wait for policy fetcher to do its rounds
    await asyncio.sleep(3)

    # Verify
    assert time.time() - await cache.get_proactive_fetch_ts() < 10

    result = await cache.get(domain)
    assert result
    assert result.pol_id == expected_policy_id
    if ts_reset:
        # A full HTTPS fetch happened: the timestamp was updated and a fresh
        # policy body was stored.
        assert time.time() - result.ts < 10
    else:
        # No valid policy could be fetched: the original entry is preserved.
        assert result.ts == init_ts
    assert bool(result.pol_body) == body_present

    await pf.stop()
    await pf.close()

@pytest.mark.asyncio
@pytest.mark.timeout(10)
async def test_no_cache_update_during_grace_period(cache):
    cfg = utils.populate_cfg_defaults(None)
    cfg['proactive_policy_fetching']['enabled'] = True
    cfg['proactive_policy_fetching']['interval'] = 86400
    cfg['proactive_policy_fetching']['grace_ratio'] = 2.0
    cfg['shutdown_timeout'] = 1

    init_record = base_cache.CacheEntry(time.time() - 1, "19990907T090909", {})
    await cache.set("good.loc", init_record)

    pf = STSProactiveFetcher(cfg, cache)
    await pf.start()

    # Wait for policy fetcher to do its round
    await asyncio.sleep(3)

    # Verify
    assert time.time() - await cache.get_proactive_fetch_ts() < 10

    result = await cache.get("good.loc")
    assert result == init_record  # no update (cached being fresh enough)

    await pf.stop()
    await pf.close()

@pytest.mark.asyncio
@pytest.mark.timeout(10)
async def test_respect_previous_proactive_fetch_ts(cache):
    cfg = utils.populate_cfg_defaults(None)
    cfg['proactive_policy_fetching']['enabled'] = True
    cfg['proactive_policy_fetching']['interval'] = 86400
    cfg['proactive_policy_fetching']['grace_ratio'] = 2.0
    cfg['shutdown_timeout'] = 1

    previous_proactive_fetch_ts = time.time() - 1
    init_record = base_cache.CacheEntry(0, "19990907T090909", {})
    await cache.set("good.loc", init_record)
    await cache.set_proactive_fetch_ts(previous_proactive_fetch_ts)

    pf = STSProactiveFetcher(cfg, cache)
    await pf.start()

    # Wait for policy fetcher to do its potential work
    await asyncio.sleep(3)

    # Verify
    assert previous_proactive_fetch_ts == await cache.get_proactive_fetch_ts()

    result = await cache.get("good.loc")
    assert result == init_record  # no update

    await pf.stop()
    await pf.close()


class _FailingCache:
    """A cache whose scan() always raises, simulating a backend outage."""

    def __init__(self):
        self.scan_calls = 0

    async def setup(self):
        pass

    async def teardown(self):
        pass

    async def get(self, key):
        return None

    async def set(self, key, value):
        pass

    async def safe_set(self, domain, entry, logger):
        pass

    async def get_proactive_fetch_ts(self):
        return 0

    async def set_proactive_fetch_ts(self, timestamp):
        pass

    async def scan(self, token, amount_hint):
        self.scan_calls += 1
        raise RuntimeError("simulated backend outage")


@pytest.mark.asyncio
@pytest.mark.timeout(10)
async def test_fetch_survives_transient_cache_failure():
    # P3: a transient cache failure (e.g. a brief backend outage) must not
    # terminate the background refresher task; it should log and retry on
    # the next cycle.
    cfg = utils.populate_cfg_defaults(None)
    cfg['proactive_policy_fetching']['enabled'] = True
    cfg['proactive_policy_fetching']['interval'] = 1
    cfg['proactive_policy_fetching']['concurrency_limit'] = 2
    cfg["default_zone"]["timeout"] = 1
    cfg['shutdown_timeout'] = 1

    cache = _FailingCache()
    pf = STSProactiveFetcher(cfg, cache)
    await pf.start()

    # Give it time to attempt (and fail) at least one cycle.
    await asyncio.sleep(3)

    # The task must still be running (not terminated by the exception) and
    # must have retried the failing scan.
    assert not pf._periodic_fetch_task.done()
    assert cache.scan_calls >= 1

    await pf.stop()
    await pf.close()
