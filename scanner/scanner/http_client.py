"""HTTP mijoz — barcha so'rovlar shu yerdan o'tadi (rate-limit, timeout, UA)."""

from __future__ import annotations

import time
from dataclasses import dataclass

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


@dataclass
class Response:
    """requests.Response ustidan yengil o'ram."""

    url: str
    status: int
    headers: dict
    text: str
    elapsed: float
    cookies: object = None
    ok: bool = True
    error: str = ""


class HttpClient:
    """Rate-limit va timeout bilan boshqariladigan HTTP mijoz."""

    DEFAULT_UA = (
        "NasiyaScanner/1.0 (+security-testing; authorized-use-only)"
    )

    def __init__(
        self,
        *,
        timeout: float = 10.0,
        delay: float = 0.3,
        user_agent: str | None = None,
        verify_tls: bool = True,
        max_body: int = 2_000_000,
        proxies: dict | None = None,
    ):
        self.timeout = timeout
        self.delay = delay
        self.max_body = max_body
        self._last_request = 0.0

        self.session = requests.Session()
        self.session.headers.update(
            {
                "User-Agent": user_agent or self.DEFAULT_UA,
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.9,uz;q=0.8",
            }
        )
        self.session.verify = verify_tls
        if proxies:
            self.session.proxies.update(proxies)

        retry = Retry(
            total=1,
            backoff_factor=0.3,
            status_forcelist=(502, 503, 504),
            allowed_methods=frozenset(["GET", "POST", "HEAD"]),
        )
        adapter = HTTPAdapter(max_retries=retry, pool_connections=10, pool_maxsize=10)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)

    def _throttle(self) -> None:
        now = time.monotonic()
        wait = self.delay - (now - self._last_request)
        if wait > 0:
            time.sleep(wait)
        self._last_request = time.monotonic()

    def request(
        self,
        method: str,
        url: str,
        *,
        params: dict | None = None,
        data: dict | None = None,
        allow_redirects: bool = True,
    ) -> Response:
        self._throttle()
        try:
            resp = self.session.request(
                method.upper(),
                url,
                params=params,
                data=data,
                timeout=self.timeout,
                allow_redirects=allow_redirects,
                stream=True,
            )
            # katta javoblarni cheklaymiz
            content = resp.raw.read(self.max_body, decode_content=True) or b""
            try:
                text = content.decode(resp.encoding or "utf-8", errors="replace")
            except (LookupError, TypeError):
                text = content.decode("utf-8", errors="replace")
            resp.close()
            return Response(
                url=resp.url,
                status=resp.status_code,
                headers=dict(resp.headers),
                text=text,
                elapsed=resp.elapsed.total_seconds(),
                cookies=resp.cookies,
                ok=True,
            )
        except requests.exceptions.SSLError as exc:
            return Response(url, 0, {}, "", 0.0, ok=False, error=f"SSL: {exc}")
        except requests.exceptions.RequestException as exc:
            return Response(url, 0, {}, "", 0.0, ok=False, error=str(exc))

    def get(self, url: str, **kw) -> Response:
        return self.request("GET", url, **kw)

    def post(self, url: str, **kw) -> Response:
        return self.request("POST", url, **kw)
