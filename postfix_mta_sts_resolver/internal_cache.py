import collections
from itertools import islice

from .base_cache import BaseCache


class InternalLRUCache(BaseCache):
    def __init__(self, cache_size=10000):
        self._cache_size = cache_size
        self._cache = collections.OrderedDict()
        self._proactive_fetch_ts = 0

    async def setup(self):
        pass

    async def teardown(self):
        pass

    async def get(self, key):
        try:
            value = self._cache.pop(key)
            self._cache[key] = value
            return value
        except KeyError:
            return None

    async def set(self, key, value):
        try:
            self._cache.pop(key)
        except KeyError:
            if len(self._cache) >= self._cache_size:
                self._cache.popitem(last=False)
        self._cache[key] = value

    async def scan(self, token, amount_hint):
        if token is None:
            token = 0

        total = len(self._cache)
        if token >= total:
            return None, []
        amount = min(total - token, amount_hint)
        new_token = token + amount
        if new_token >= total:
            new_token = None
        # Take "amount" of oldest entries starting from the cursor.
        # Deliberately no LRU refresh here: refreshing would reorder
        # the dict and invalidate position-based cursors.
        result = list(islice(self._cache.items(), token, token + amount))
        return new_token, result

    async def get_proactive_fetch_ts(self):
        return self._proactive_fetch_ts

    async def set_proactive_fetch_ts(self, timestamp):
        self._proactive_fetch_ts = timestamp
