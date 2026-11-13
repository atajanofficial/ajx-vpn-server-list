"""Fetch the official VPN Gate public relay feed for AJX VPN.

Only the source already used by the Android project is contacted. The request
uses HTTPS with Python's default certificate verification; redirects are
followed only when they stay on a ``vpngate.net`` host. Bodies are size-limited
and retried a small number of times for transient failures.

Usage:
    python scripts/fetch_servers.py --output "$RUNNER_TEMP/vpngate.csv"

Environment overrides:
    AJX_SOURCE_URL       replace the source URL (must stay HTTPS)
    AJX_SOURCE_FILE      read a local file instead of the network (tests)
"""

from __future__ import annotations

import argparse
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Optional

from validate_servers import SOURCE_URL

MAX_BODY_BYTES = 16 * 1024 * 1024
DEFAULT_TIMEOUT_SECONDS = 60
DEFAULT_ATTEMPTS = 3
USER_AGENT = "AJX-VPN-ServerList/1.0 (+https://github.com/ajx-vpn/ajx-vpn-server-list)"
ALLOWED_HOST_SUFFIX = "vpngate.net"


class FetchError(Exception):
    """A refresh that must not replace the published list."""


def _validate_url(url: str) -> str:
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme != "https":
        raise FetchError("the source URL must use HTTPS")
    host = (parsed.hostname or "").lower()
    if host != ALLOWED_HOST_SUFFIX and not host.endswith("." + ALLOWED_HOST_SUFFIX):
        raise FetchError(f"the source host {host!r} is not a VPN Gate host")
    return url


def _read_limited(response, max_bytes: int) -> str:
    declared = response.headers.get("Content-Length")
    if declared is not None:
        try:
            if int(declared) > max_bytes:
                raise FetchError(f"the source body exceeds {max_bytes} bytes")
        except ValueError:
            pass

    chunks = []
    total = 0
    while True:
        chunk = response.read(64 * 1024)
        if not chunk:
            break
        total += len(chunk)
        if total > max_bytes:
            raise FetchError(f"the source body exceeds {max_bytes} bytes")
        chunks.append(chunk)
    return b"".join(chunks).decode("utf-8", errors="replace")


def fetch_source(
    url: str = SOURCE_URL,
    *,
    timeout: int = DEFAULT_TIMEOUT_SECONDS,
    attempts: int = DEFAULT_ATTEMPTS,
    max_bytes: int = MAX_BODY_BYTES,
) -> str:
    """Downloads the feed, retrying transient failures with a short backoff."""

    url = _validate_url(url)
    last_error: Optional[BaseException] = None
    for attempt in range(1, attempts + 1):
        try:
            request = urllib.request.Request(
                url,
                headers={
                    "Accept": "text/plain, */*",
                    "Cache-Control": "no-cache",
                    "User-Agent": USER_AGENT,
                },
            )
            with urllib.request.urlopen(request, timeout=timeout) as response:
                final_host = (urllib.parse.urlparse(response.geturl()).hostname or "").lower()
                if final_host != ALLOWED_HOST_SUFFIX and not final_host.endswith(
                    "." + ALLOWED_HOST_SUFFIX
                ):
                    raise FetchError(
                        f"the source redirected to a non-VPN Gate host {final_host!r}"
                    )
                body = _read_limited(response, max_bytes)
            if not body.strip():
                raise FetchError("the source returned an empty body")
            return body
        except FetchError:
            raise
        except urllib.error.HTTPError as error:
            last_error = error
            retryable = error.code == 429 or 500 <= error.code <= 599
            if not retryable or attempt == attempts:
                raise FetchError(f"the source returned HTTP {error.code}") from error
        except (urllib.error.URLError, TimeoutError, OSError) as error:
            last_error = error
            if attempt == attempts:
                raise FetchError(f"the source could not be reached: {error}") from error
        time.sleep(min(2 ** (attempt - 1), 8))
    raise FetchError(f"the source could not be reached: {last_error}")


def load_source(
    *,
    url: str = SOURCE_URL,
    source_file: Optional[str] = None,
    timeout: int = DEFAULT_TIMEOUT_SECONDS,
    attempts: int = DEFAULT_ATTEMPTS,
) -> str:
    """Reads the feed from a local file when supplied, otherwise the network."""

    if source_file:
        with open(source_file, "r", encoding="utf-8", errors="replace") as handle:
            body = handle.read()
        if not body.strip():
            raise FetchError("the local source file is empty")
        return body
    return fetch_source(url, timeout=timeout, attempts=attempts)


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, help="path for the raw feed")
    parser.add_argument("--url", default=os.environ.get("AJX_SOURCE_URL", SOURCE_URL))
    parser.add_argument("--source-file", default=os.environ.get("AJX_SOURCE_FILE"))
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT_SECONDS)
    parser.add_argument("--attempts", type=int, default=DEFAULT_ATTEMPTS)
    args = parser.parse_args(argv)

    try:
        body = load_source(
            url=args.url,
            source_file=args.source_file,
            timeout=args.timeout,
            attempts=args.attempts,
        )
    except FetchError as error:
        print(f"FETCH_FAILED: {error}", file=sys.stderr)
        return 1

    with open(args.output, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(body)
    print(f"FETCHED: {len(body)} characters from {args.url}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
