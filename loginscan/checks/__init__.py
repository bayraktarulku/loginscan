"""Kontrol modülleri. Her biri run(client, cfg) -> List[Finding] sağlar."""
from . import cookies, enumeration, headers, ratelimit, session, sqli

# Scanner'ın çalıştıracağı sıra. Enumeration'ı sqli'den ÖNCE koyuyoruz:
# sqli çok sayıda başarısız giriş yapar ve hedefin rate limiter'ını tetikleyip
# enumeration ölçümünü kirletebilir. En çok istek yapan ratelimit en sonda.
ALL_CHECKS = [headers, enumeration, sqli, cookies, session, ratelimit]

__all__ = ["ALL_CHECKS", "sqli", "enumeration", "ratelimit", "cookies", "session", "headers"]
