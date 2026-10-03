import collections

from .base_cache import BaseCache


class InternalLRUCache(BaseCache):
    def __init__(self, cache_size=10000):
        self._cache_size = cache_size
        self._cache = collections.OrderedDict()
        self._proactive_fetch_ts = 0
        # Active scan snapshots: scan_id -> list of keys captured when the
        # scan started. See scan() for why a snapshot is required.
        self._snapshots = {}
        self._next_scan_id = 0

    async def setup(self):
        pass

    async def teardown(self):
        self._snapshots.clear()

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
            # Start a new scan. Snapshot the current keys so that LRU
            # reordering triggered by concurrent get()/set() (e.g. the
            # proactive workers refreshing entries between pages) cannot
            # shift a positional cursor and thereby skip or repeat entries.
            self._next_scan_id += 1
            scan_id = self._next_scan_id
            self._snapshots[scan_id] = list(self._cache.keys())
            position = 0
        else:
            scan_id, position = token

        snapshot = self._snapshots.get(scan_id)
        if snapshot is None:
            # Unknown or already-completed snapshot; nothing left to return.
            return None, []

        end = min(position + amount_hint, len(snapshot))
        # Use the dict's own .get() (no LRU refresh) so that reading values
        # during the scan does not reorder the cache.
        result = [(key, self._cache[key]) for key in snapshot[position:end]
                  if key in self._cache]
        position = end

        if position >= len(snapshot):
            # Scan complete; drop the snapshot.
            del self._snapshots[scan_id]
            return None, result
        return (scan_id, position), result

    async def get_proactive_fetch_ts(self):
        return self._proactive_fetch_ts

    async def set_proactive_fetch_ts(self, timestamp):
        self._proactive_fetch_ts = timestamp
