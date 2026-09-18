"""
loginscan komut satırı arayüzü.

Örnek:
    loginscan http://127.0.0.1:8001/ --i-own-this --user admin
    loginscan https://site/login --i-own-this --user admin --json rapor.json
"""
from __future__ import annotations

import argparse
import sys
from typing import List, Optional

from . import __version__
from .authorization import AUTHORIZATION_NOTICE, NotAuthorized
from .models import ScanConfig, Status
from .scanner import Scanner


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="loginscan",
        description="Kendi login endpoint'inizi savunma amaçlı tarar (yalnızca yetkili kullanım).",
        epilog=AUTHORIZATION_NOTICE,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("url", help="Login isteğinin gittiği adres (ör. https://site/login)")
    p.add_argument("--i-own-this", action="store_true",
                   help="Bu sistemi test etme yetkiniz olduğunu beyan eder (zorunlu).")
    p.add_argument("--user", dest="known_username", default=None,
                   help="Sisteminizde GERÇEKTEN var olan bir kullanıcı adı (şifre değil).")
    p.add_argument("--method", default="POST", help="Login HTTP metodu (varsayılan POST).")
    p.add_argument("--username-field", default="username", help="Kullanıcı adı form alanı adı.")
    p.add_argument("--password-field", default="password", help="Şifre form alanı adı.")
    p.add_argument("--login-page", dest="login_page_url", default=None,
                   help="Login formunun HTML sayfası (başlık kontrolü için).")
    p.add_argument("--success", dest="success_indicators", action="append", default=[],
                   metavar="METIN", help="Yanıtta görülürse 'giriş başarılı' sayılacak metin (birden çok verilebilir).")
    p.add_argument("--field", dest="extra_fields", action="append", default=[],
                   metavar="AD=DEGER", help="Her isteğe eklenecek sabit form alanı (ör. csrf=abc).")
    p.add_argument("--max-requests", type=int, default=25,
                   help="Toplam istek üst sınırı (varsayılan 25).")
    p.add_argument("--delay", type=float, default=0.3, help="İstekler arası bekleme (sn).")
    p.add_argument("--timeout", type=float, default=10.0, help="İstek zaman aşımı (sn).")
    p.add_argument("--insecure", action="store_true", help="TLS sertifika doğrulamasını kapat.")
    p.add_argument("--json", dest="json_path", default=None, metavar="DOSYA",
                   help="Raporu JSON olarak bu dosyaya yaz.")
    p.add_argument("--version", action="version", version=f"loginscan {__version__}")
    return p


def _parse_fields(pairs: List[str]) -> dict:
    out = {}
    for item in pairs:
        if "=" not in item:
            raise SystemExit(f"--field '{item}' geçersiz; AD=DEGER bekleniyor.")
        k, v = item.split("=", 1)
        out[k.strip()] = v
    return out


def main(argv: Optional[List[str]] = None) -> int:
    args = _build_parser().parse_args(argv)

    cfg = ScanConfig(
        url=args.url,
        method=args.method,
        username_field=args.username_field,
        password_field=args.password_field,
        known_username=args.known_username,
        success_indicators=args.success_indicators,
        login_page_url=args.login_page_url,
        max_requests=args.max_requests,
        delay=args.delay,
        timeout=args.timeout,
        verify_tls=not args.insecure,
        extra_fields=_parse_fields(args.extra_fields),
    )

    try:
        report = Scanner(cfg, authorized=args.i_own_this).run()
    except NotAuthorized as e:
        print(str(e), file=sys.stderr)
        return 2

    print(report.to_text())

    if args.json_path:
        with open(args.json_path, "w", encoding="utf-8") as fh:
            fh.write(report.to_json())
        print(f"\nJSON rapor yazıldı: {args.json_path}")

    # Açık bulunduysa çıkış kodu 1 (CI/otomasyon için kullanışlı).
    return 1 if any(f.status == Status.VULNERABLE for f in report.findings) else 0


if __name__ == "__main__":
    raise SystemExit(main())
