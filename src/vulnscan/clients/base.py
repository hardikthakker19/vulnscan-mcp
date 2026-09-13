"""Base async HTTP client with retry and rate limiting."""

from __future__ import annotations

import logging
from typing import Any

import httpx
from tenacity import (
    before_sleep_log,
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)

logger = logging.getLogger(__name__)

# Retry on server errors, rate limits, and connection errors
RETRYABLE_STATUS_CODES = {429, 500, 502, 503, 504}


class RateLimitError(Exception):
    """Raised when API rate limit is exceeded."""


class APIError(Exception):
    """Raised on non-retryable API errors."""
    def __init__(self, status_code: int, message: str):
        self.status_code = status_code
        super().__init__(f"API Error {status_code}: {message}")


class BaseClient:
    """Base async HTTP client with exponential backoff retry."""

    def __init__(
        self,
        base_url: str,
        headers: dict[str, str] | None = None,
        timeout: float = 30.0,
    ):
        self.base_url = base_url
        self._headers = headers or {}
        self._timeout = timeout
        self._client: httpx.AsyncClient | None = None

    async def _get_client(self) -> httpx.AsyncClient:
        """Get or create the async HTTP client."""
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(
                base_url=self.base_url,
                headers=self._headers,
                timeout=httpx.Timeout(self._timeout),
                follow_redirects=True,
                http2=True,
            )
        return self._client

    @retry(
        stop=stop_after_attempt(5),
        wait=wait_exponential(multiplier=1, min=2, max=60),
        retry=retry_if_exception_type((RateLimitError, httpx.TransportError)),
        before_sleep=before_sleep_log(logger, logging.WARNING),
        reraise=True,
    )
    async def _request(
        self,
        method: str,
        path: str,
        params: dict[str, Any] | None = None,
        **kwargs: Any,
    ) -> dict[str, Any] | list[Any]:
        """Make an HTTP request with retry logic."""
        client = await self._get_client()

        response = await client.request(method, path, params=params, **kwargs)

        if response.status_code == 403:
            logger.warning(f"403 Forbidden on {path} — may be rate limited")
            raise RateLimitError(f"403 on {path}")

        if response.status_code in RETRYABLE_STATUS_CODES:
            raise RateLimitError(
                f"Retryable status {response.status_code} on {path}"
            )

        if response.status_code != 200:
            raise APIError(response.status_code, response.text[:500])

        return response.json()

    async def get(
        self,
        path: str = "",
        params: dict[str, Any] | None = None,
        **kwargs: Any,
    ) -> dict[str, Any] | list[Any]:
        """Make a GET request."""
        return await self._request("GET", path, params=params, **kwargs)

    async def close(self) -> None:
        """Close the HTTP client."""
        if self._client and not self._client.is_closed:
            await self._client.aclose()
            self._client = None
