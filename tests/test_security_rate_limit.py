"""Tests for the webhook rate limiter."""

from src.security.rate_limit import SlidingWindowRateLimiter


def test_limiter_allows_up_to_limit():
    limiter = SlidingWindowRateLimiter(limit=2, window_seconds=60)
    assert limiter.check("client")[0] is True
    assert limiter.check("client")[0] is True
    allowed, retry_after = limiter.check("client")
    assert allowed is False
    assert retry_after > 0


def test_limiter_is_per_key():
    limiter = SlidingWindowRateLimiter(limit=1, window_seconds=60)
    assert limiter.check("a")[0] is True
    assert limiter.check("a")[0] is False
    assert limiter.check("b")[0] is True


def test_reset_clears_buckets():
    limiter = SlidingWindowRateLimiter(limit=1, window_seconds=60)
    limiter.check("a")
    limiter.reset()
    assert limiter.check("a")[0] is True
