"""
Küçük, bağımlılıksız HTTP istemcisi (sadece urllib).

İki önemli güvenlik özelliği:
  * İstek bütçesi: toplam istek sayısı ScanConfig.max_requests ile sınırlı.
    Böylece araç yanlışlıkla bir DoS/brute-force aracına dönüşemez.
  * İstekler arası gecikme: hedefe nazik davranır.
"""
from __future__ import annotations

import re
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

# Oturum benzeri cookie adlarını yakalamak için (pasif token toplama).
_SESSION_COOKIE_HINT = re.compile(r"sess|token|auth|sid|jwt|login", re.I)


class RequestBudgetExceeded(Exception):
    """İstek bütçesi (max_requests) tükendiğinde atılır."""


@dataclass
class Response:
    """Bir HTTP yanıtının bizim ihtiyaç duyduğumuz kısımları."""
    status: int
    headers: Dict[str, str]           # başlıklar (küçük harfe indirgenmiş anahtarlar)
    set_cookies: list                 # ham Set-Cookie satırları
    body: str
    elapsed: float                    # yanıt süresi (saniye)
    url: str

    def header(self, name: str) -> Optional[str]:
        return self.headers.get(name.lower())


class HttpClient:
    """urllib tabanlı, bütçeli istemci."""

    def __init__(self, max_requests: int, delay: float, timeout: float, verify_tls: bool):
        self.max_requests = max_requests
        self.delay = delay
        self.timeout = timeout
        self.count = 0
        # Tarama boyunca görülen oturum token'ları: [(cookie_adi, deger), ...]
        self.observed_session_tokens: List[Tuple[str, str]] = []
        self._ctx = ssl.create_default_context()
        if not verify_tls:
            self._ctx.check_hostname = False
            self._ctx.verify_mode = ssl.CERT_NONE

    @property
    def remaining(self) -> int:
        return self.max_requests - self.count

    def _spend(self) -> None:
        if self.count >= self.max_requests:
            raise RequestBudgetExceeded(
                f"İstek bütçesi doldu ({self.max_requests}). "
                "Daha fazla test için max_requests artırılmalı."
            )
        self.count += 1

    def request(self, method: str, url: str, data: Optional[Dict[str, str]] = None,
                headers: Optional[Dict[str, str]] = None) -> Response:
        self._spend()
        if self.delay and self.count > 1:
            time.sleep(self.delay)

        body_bytes = None
        if data is not None:
            body_bytes = urllib.parse.urlencode(data).encode()

        req_headers = {"User-Agent": "loginscan/0.1 (self-audit)"}
        if headers:
            req_headers.update(headers)

        req = urllib.request.Request(url, data=body_bytes, method=method.upper(),
                                     headers=req_headers)
        start = time.time()
        try:
            with urllib.request.urlopen(req, timeout=self.timeout, context=self._ctx) as resp:
                return self._to_response(resp, start, url)
        except urllib.error.HTTPError as e:
            # 4xx/5xx de geçerli bir yanıttır — inceleriz.
            return self._to_response(e, start, url)

    def _to_response(self, resp, start: float, url: str) -> Response:
        raw = resp.read() if hasattr(resp, "read") else b""
        try:
            text = raw.decode("utf-8", errors="replace")
        except Exception:
            text = ""
        headers = {}
        set_cookies = []
        for k, v in resp.headers.items():
            lk = k.lower()
            if lk == "set-cookie":
                set_cookies.append(v)
            headers[lk] = v
        # Python bazı sürümlerde birden çok Set-Cookie'yi tek başlıkta birleştirir;
        # get_all daha güvenilir:
        try:
            all_cookies = resp.headers.get_all("Set-Cookie")
            if all_cookies:
                set_cookies = list(all_cookies)
        except Exception:
            pass
        # Oturum benzeri cookie'lerin değerlerini pasif olarak biriktir.
        for raw in set_cookies:
            nv = raw.split(";", 1)[0]
            if "=" in nv:
                name, value = nv.split("=", 1)
                name, value = name.strip(), value.strip()
                if value and _SESSION_COOKIE_HINT.search(name):
                    self.observed_session_tokens.append((name, value))
        return Response(
            status=getattr(resp, "status", getattr(resp, "code", 0)) or 0,
            headers=headers,
            set_cookies=set_cookies,
            body=text,
            elapsed=time.time() - start,
            url=url,
        )

    def post(self, url: str, data: Dict[str, str], headers: Optional[Dict[str, str]] = None) -> Response:
        return self.request("POST", url, data=data, headers=headers)

    def get(self, url: str, headers: Optional[Dict[str, str]] = None) -> Response:
        return self.request("GET", url, data=None, headers=headers)
