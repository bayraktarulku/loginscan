"""
GÜVENLİ login sunucusu — aynı özellik, açıklar kapatılmış hali.
vulnerable_app.py ile satır satır karşılaştırın; farkı görmek öğreticidir.

Uygulanan savunmalar:
  1. Parametreli sorgu (prepared statement) → SQL Injection kapalı
  2. Şifreler scrypt ile hash'lenip saklanıyor (asla düz metin)
  3. Tek ve genel hata mesajı + sabit süre → user enumeration zorlaşır
  4. IP + kullanıcı bazlı basit rate limiting → brute-force yavaşlar
  5. Kriptografik rastgele oturum token'ı + HttpOnly/SameSite cookie

Çalıştırma:  python3 secure_app.py
Sonra tarayıcı:  http://127.0.0.1:8002/
"""
import sqlite3
import http.server
import urllib.parse
import hashlib
import hmac
import os
import secrets
import time
import collections

DB = ":memory:"
_conn = sqlite3.connect(DB, check_same_thread=False)


PBKDF2_ITERS = 200_000


def hash_password(password: str, salt: bytes = None) -> str:
    """PBKDF2-HMAC-SHA256 ile parola hash'i. Kendi kripto algoritmanızı YAZMAYIN.
    (Üretimde bcrypt/argon2/scrypt tercih edin; burada harici paket olmasın diye
     her Python'da bulunan pbkdf2_hmac kullanıldı.)"""
    if salt is None:
        salt = os.urandom(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, PBKDF2_ITERS)
    return salt.hex() + "$" + digest.hex()


def verify_password(password: str, stored: str) -> bool:
    salt_hex, digest_hex = stored.split("$")
    salt = bytes.fromhex(salt_hex)
    candidate = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, PBKDF2_ITERS)
    # sabit-zamanlı karşılaştırma → timing sızıntısını engeller
    return hmac.compare_digest(candidate.hex(), digest_hex)


def seed():
    c = _conn.cursor()
    c.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password_hash TEXT)")
    for u, p in [("admin", "S3cretAdmin!"), ("ulku", "kediler123"), ("test", "test")]:
        # SAVUNMA #2: sadece hash saklanıyor
        c.execute(
            "INSERT INTO users (username, password_hash) VALUES (?, ?)",
            (u, hash_password(p)),
        )
    _conn.commit()


_sessions = {}

# SAVUNMA #4: (ip, kullanıcı) başına son denemeler
_attempts = collections.defaultdict(list)
MAX_ATTEMPTS = 5
WINDOW = 300  # saniye


def rate_limited(key) -> bool:
    now = time.time()
    _attempts[key] = [t for t in _attempts[key] if now - t < WINDOW]
    return len(_attempts[key]) >= MAX_ATTEMPTS


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        # DEFENSE #6: per-request CSRF token, double-submit (cookie + hidden field).
        token = secrets.token_urlsafe(16)
        self.send_response(200)
        self.send_header("Set-Cookie", f"csrf={token}; SameSite=Strict; Path=/")
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(LOGIN_FORM.format(csrf=token).encode())

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode()
        data = urllib.parse.parse_qs(body)
        username = data.get("username", [""])[0]
        password = data.get("password", [""])[0]
        ip = self.client_address[0]
        key = (ip, username)

        # DEFENSE #6: if a browser sends the csrf cookie, the form token must match.
        cookie_csrf = self._cookie("csrf")
        if cookie_csrf and cookie_csrf != data.get("csrf", [""])[0]:
            self._send(403, "<h2>CSRF validation failed</h2>")
            return

        # SAVUNMA #4: çok deneme → engelle
        if rate_limited(key):
            self._send(429, "<h2>Çok fazla deneme</h2><p>Lütfen sonra tekrar deneyin.</p>")
            return

        c = _conn.cursor()
        # SAVUNMA #1: parametreli sorgu — girdi asla SQL metnine karışmaz
        row = c.execute(
            "SELECT id, username, password_hash FROM users WHERE username = ?",
            (username,),
        ).fetchone()

        # SAVUNMA #3: kullanıcı yoksa bile hash doğrulaması yaparak süreyi eşitle
        DUMMY = hash_password("dummy")
        stored = row[2] if row else DUMMY
        ok = verify_password(password, stored) and row is not None

        if ok:
            _attempts[key].clear()
            token = secrets.token_urlsafe(32)      # SAVUNMA #5: tahmin edilemez
            _sessions[token] = row[1]
            self.send_response(200)
            # SAVUNMA #5: HttpOnly + SameSite (+ gerçek dağıtımda Secure/HTTPS)
            self.send_header(
                "Set-Cookie",
                f"session={token}; HttpOnly; SameSite=Strict; Path=/",
            )
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(f"<h2>Giriş başarılı — hoş geldin {row[1]}</h2>".encode())
        else:
            _attempts[key].append(time.time())
            # SAVUNMA #3: her durumda AYNI genel mesaj
            self._send(401, "<h2>Giriş başarısız</h2><p>Kullanıcı adı veya şifre hatalı.</p>")

    def _cookie(self, name):
        raw = self.headers.get("Cookie", "")
        for part in raw.split(";"):
            if "=" in part:
                k, v = part.strip().split("=", 1)
                if k == name:
                    return v
        return None

    def _send(self, code, html):
        self.send_response(code)
        # DEFENSE #7: don't cache auth responses
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(html.encode())


LOGIN_FORM = """
<h1>GÜVENLİ Login (öğrenme demosu)</h1>
<form method="POST" action="/">
  <input type="hidden" name="csrf" value="{csrf}">
  Kullanıcı: <input name="username"><br>
  Şifre:     <input name="password" type="password"><br>
  <button>Giriş</button>
</form>
<p>admin / S3cretAdmin!  — SQLi ve enumeration burada işe yaramaz.</p>
"""


if __name__ == "__main__":
    seed()
    print("GÜVENLİ sunucu:  http://127.0.0.1:8002/  (Ctrl+C ile durdur)")
    http.server.HTTPServer(("127.0.0.1", 8002), Handler).serve_forever()
