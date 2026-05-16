"""Rate limiting and jitter helpers."""
from __future__ import annotations

import random
import time


def rate_limit(delay: float) -> None:
    """Sleep `delay` seconds. No-op when delay <= 0."""
    if delay > 0:
        time.sleep(delay)


def apply_stealth(*, rate: float = 0.0, jitter: float = 0.0) -> None:
    """Sleep for `rate` seconds plus up to `jitter` seconds of random padding.

    Both args default to 0 (no delay). Jitter is a uniform sample on [0, jitter),
    which is enough to break trivially-regular request cadence without needing
    a more sophisticated distribution.
    """
    delay = rate
    if jitter > 0:
        delay += random.uniform(0, jitter)
    if delay > 0:
        time.sleep(delay)
