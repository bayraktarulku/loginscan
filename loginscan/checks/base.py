"""
Kontrollerin paylaştığı yardımcılar:
  * login form verisi hazırlama
  * "başarısız giriş" temel (baseline) yanıtı alma
  * bir yanıtın "giriş başarılı" gibi görünüp görünmediğini kestirme

Not: Genel bir login endpoint'inde başarıyı %100 kesin anlamak zordur.
Bu yüzden birden çok sinyali birleştirir ve kanıtı rapora koyarız —
kesin hüküm değil, "incelenmeli" işareti veririz.
"""
from __future__ import annotations

import re
import secrets
from typing import Dict, List, Optional

from ..http import HttpClient, Response
from ..models import ScanConfig

# Yanıt gövdesinde görülürse veritabanı hatası sızıntısı sayılır.
SQL_ERROR_SIGNS = [
    "sql syntax", "sqlite3.", "sqlite error", "psycopg2", "pg::",
    "mysql_fetch", "you have an error in your sql",
    "unclosed quotation mark", "quoted string not properly terminated",
    "odbc", "ora-0", "syntax error", "sqlalchemy",
]

# Cookie adı bunlardan birine benzerse oturum cookie'si sayılır.
SESSION_COOKIE_HINT = re.compile(r"sess|token|auth|sid|jwt|login", re.I)


def random_username(prefix: str = "nouser") -> str:
    return f"{prefix}_{secrets.token_hex(4)}"


def build_data(cfg: ScanConfig, username: str, password: str) -> Dict[str, str]:
    data = dict(cfg.extra_fields)
    data[cfg.username_field] = username
    data[cfg.password_field] = password
    return data


def submit_login(client: HttpClient, cfg: ScanConfig, username: str, password: str) -> Response:
    return client.request(cfg.method, cfg.url, data=build_data(cfg, username, password))


def cookie_names(resp: Response) -> List[str]:
    names = []
    for raw in resp.set_cookies:
        # "name=value; Path=/; HttpOnly" → name
        head = raw.split("=", 1)[0].strip()
        if head:
            names.append(head)
    return names


def session_cookies(resp: Response) -> List[str]:
    return [n for n in cookie_names(resp) if SESSION_COOKIE_HINT.search(n)]


def baseline_fail(client: HttpClient, cfg: ScanConfig) -> Response:
    """Kesinlikle var olmayan bir kullanıcıyla giriş dener → 'başarısız' referansı."""
    return submit_login(client, cfg, random_username(), "wrong_" + secrets.token_hex(3))


def has_sql_error(body: str) -> Optional[str]:
    low = body.lower()
    for sign in SQL_ERROR_SIGNS:
        if sign in low:
            return sign
    return None


def looks_like_success(resp: Response, baseline: Response, cfg: ScanConfig) -> Optional[str]:
    """
    Yanıt 'giriş başarılı' gibi mi görünüyor? Sinyal bulursa açıklamasını,
    yoksa None döner. Yanlış-pozitifi azaltmak için muhafazakârdır.
    """
    # 1) Kullanıcının verdiği başarı ipuçları
    for token in cfg.success_indicators:
        if token and token.lower() in resp.body.lower():
            return f"yanıtta başarı metni görüldü: '{token}'"

    # 2) Başarısız denemede olmayan bir oturum cookie'si şimdi verildiyse
    new_sess = set(session_cookies(resp)) - set(session_cookies(baseline))
    if new_sess:
        return f"başarısız denemede olmayan oturum cookie'si verildi: {sorted(new_sess)}"

    # 3) Yönlendirme farkı (başarısızda değil ama burada 3xx)
    if 300 <= resp.status < 400 and not (300 <= baseline.status < 400):
        loc = resp.header("location") or "?"
        return f"başarısız denemede olmayan yönlendirme (HTTP {resp.status} → {loc})"

    return None
