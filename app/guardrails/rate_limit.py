"""Rate limiting. In-memory token bucket for demo; swap dict for Redis in prod.
Runs FIRST in the pipeline so over-limit traffic costs no model inference."""
import time
from collections import defaultdict
from threading import Lock

import config


class RateLimiter:
    def __init__(self, tiers=None):
        self.tiers = tiers or config.RATE_TIERS
        self._buckets = defaultdict(list)
        self._lock = Lock()

    def allow(self, key, tier="free"):
        limit = self.tiers.get(tier, self.tiers["free"])
        now = time.time()
        with self._lock:
            window = [t for t in self._buckets[key] if now - t < 60]
            if len(window) >= limit:
                self._buckets[key] = window
                return False
            window.append(now)
            self._buckets[key] = window
            return True

    def reset(self):
        with self._lock:
            self._buckets.clear()


limiter = RateLimiter()
