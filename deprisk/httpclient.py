"""Dependency-free HTTP client built on urllib.

Small wrapper that adds JSON helpers, timeouts, a User-Agent and retry/backoff
for transient failures and rate limits.  Network errors are surfaced as
:class:`FetchError` so callers can record "NO_DATA" rather than crashing.
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from typing import Optional

DEFAULT_TIMEOUT = 30
USER_AGENT = "deprisk/0.1.0 (+dependency-risk-dashboard)"
RETRYABLE = {429, 500, 502, 503, 504}


class FetchError(Exception):
    def __init__(self, message: str, status: Optional[int] = None):
        super().__init__(message)
        self.status = status
        self.message = message


def _request(
    url: str,
    method: str = "GET",
    payload=None,
    timeout: int = DEFAULT_TIMEOUT,
    headers: Optional[dict] = None,
):
    data = None
    hdrs = {"User-Agent": USER_AGENT, "Accept": "application/json"}
    if headers:
        hdrs.update(headers)
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        hdrs["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, headers=hdrs, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as e:
        body = b""
        try:
            body = e.read()
        except Exception:
            pass
        raise FetchError(f"HTTP {e.code} for {url}", status=e.code) from e
    except urllib.error.URLError as e:
        raise FetchError(f"network error for {url}: {e.reason}") from e
    except Exception as e:  # noqa: BLE001
        raise FetchError(f"error for {url}: {e}") from e


def get_json(
    url: str,
    timeout: int = DEFAULT_TIMEOUT,
    retries: int = 2,
    not_found_ok: bool = True,
):
    """GET JSON.  Returns None for 404 (when ``not_found_ok``) or raises FetchError."""
    last: Optional[FetchError] = None
    for attempt in range(retries + 1):
        try:
            status, body = _request(url, "GET", timeout=timeout)
            if body in (b"", b"null"):
                return None
            return json.loads(body.decode("utf-8"))
        except FetchError as e:
            last = e
            if e.status == 404 and not_found_ok:
                return None
            if e.status in RETRYABLE and attempt < retries:
                time.sleep(1.5 * (attempt + 1))
                continue
            raise
        except json.JSONDecodeError:
            raise FetchError(f"invalid JSON from {url}")
    raise last or FetchError(f"failed to fetch {url}")


def post_json(
    url: str,
    payload,
    timeout: int = DEFAULT_TIMEOUT,
    retries: int = 2,
):
    """POST JSON.  Raises FetchError on failure (no 404 swallowing)."""
    last: Optional[FetchError] = None
    for attempt in range(retries + 1):
        try:
            status, body = _request(url, "POST", payload=payload, timeout=timeout)
            if body in (b"", b"null"):
                return None
            return json.loads(body.decode("utf-8"))
        except FetchError as e:
            last = e
            if e.status in RETRYABLE and attempt < retries:
                time.sleep(1.5 * (attempt + 1))
                continue
            raise
        except json.JSONDecodeError:
            raise FetchError(f"invalid JSON from {url}")
    raise last or FetchError(f"failed to post {url}")
