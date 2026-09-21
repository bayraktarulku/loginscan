"""
KASITLI OLARAK AÇIKLI login sunucusu — SADECE ÖĞRENME AMAÇLI.
Bunu asla gerçek bir ortamda, internete açık şekilde çalıştırmayın.

Barındırdığı açıklar (README'de her biri açıklanıyor):
  1. SQL Injection ile kimlik doğrulama atlatma
  2. Şifrelerin düz metin (plaintext) saklanması
  3. Kullanıcı adı sızdırma (user enumeration) — farklı hata mesajları
  4. Brute-force koruması yok (sınırsız deneme)
  5. Tahmin edilebilir / güvensiz oturum (session) token'ı

Çalıştırma:  python3 vulnerable_app.py
Sonra tarayıcı:  http://127.0.0.1:8001/
"""
import sqlite3
import http.server
import urllib.parse
import traceback

DB = ":memory:"
_conn = sqlite3.connect(DB, check_same_thread=False)


def seed():
    c = _conn.cursor()
    c.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)")
    # AÇIK #2: şifreler düz metin olarak yazılıyor
    c.executescript(
        "INSERT INTO users (username, password) VALUES "
        "('admin', 'S3cretAdmin!'),"
        "('ulku',  'kediler123'),"
        "('test',  'test');"
    )
    _conn.commit()


# AÇIK #5: sıradan artan sayı = tahmin edilebilir oturum kimliği
_next_session = 1000
_sessions = {}


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):  # konsolu sade tut
        pass

    def do_GET(self):
        params = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        # AÇIK #6: ?next= doğrulanmadan yönlendirmeye konuyor (open redirect)
        nxt = params.get("next", [None])[0]
        if nxt:
            self.send_response(302)
            self.send_header("Location", nxt)
            self.end_headers()
            return
        # AÇIK #7: kimlik doğrulama GET ile de yapılıyor (verb tampering,
        # şifre URL'de/loglarda görünür)
        if "username" in params and "password" in params:
            self._login(params["username"][0], params["password"][0])
            return
        host = self.headers.get("Host", "")
        page = LOGIN_FORM + f'<p>Reset link: <a href="http://{host}/reset">reset</a></p>'
        self._send(200, page)

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode()
        data = urllib.parse.parse_qs(body)
        self._login(data.get("username", [""])[0], data.get("password", [""])[0])

    def _login(self, username, password):
        c = _conn.cursor()
        # AÇIK #1: kullanıcı girdisi doğrudan sorguya yapıştırılıyor (SQL Injection)
        query = (
            "SELECT id, username FROM users "
            f"WHERE username = '{username}' AND password = '{password}'"
        )
        print(f"[VULN][SQL] {query}")
        try:
            row = c.execute(query).fetchone()
        except sqlite3.Error:
            self._send(500, f"<h2>Server error</h2><pre>{traceback.format_exc()}</pre>")
            return

        if row:
            global _next_session
            token = _next_session          # AÇIK #5
            _next_session += 1
            _sessions[token] = row[1]
            self.send_response(200)
            # AÇIK #5: Secure / HttpOnly bayrakları yok
            self.send_header("Set-Cookie", f"session={token}")
            self._cors()
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(
                f"<h2>Giriş başarılı — hoş geldin {row[1]}</h2>"
                f"<p>session cookie = {token}</p>".encode()
            )
        else:
            # AÇIK #3: kullanıcı var mı yok mu farklı mesaj → enumeration
            exists = c.execute(
                f"SELECT 1 FROM users WHERE username = '{username}'"
            ).fetchone()
            if exists:
                msg = "Şifre yanlış."               # kullanıcı GERÇEK
            else:
                msg = "Böyle bir kullanıcı yok."     # kullanıcı YOK
            # AÇIK #4: yanlış deneme sayacı / kilit yok — sınırsız denenebilir
            self._send(401, f"<h2>Giriş başarısız</h2><p>{msg}</p>")

    def _cors(self):
        # AÇIK #8: Origin ne olursa olsun yansıtılıyor + credentials açık (CORS)
        origin = self.headers.get("Origin")
        if origin:
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Access-Control-Allow-Credentials", "true")

    def _send(self, code, html):
        self.send_response(code)
        self._cors()
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(html.encode())


LOGIN_FORM = """
<h1>AÇIKLI Login (öğrenme demosu)</h1>
<form method="POST" action="/">
  Kullanıcı: <input name="username"><br>
  Şifre:     <input name="password" type="password"><br>
  <button>Giriş</button>
</form>
<p>Deneyin: admin / S3cretAdmin!  &nbsp;|&nbsp; SQLi: kullanıcı = <code>admin'--</code></p>
"""


if __name__ == "__main__":
    seed()
    print("AÇIKLI sunucu:  http://127.0.0.1:8001/  (Ctrl+C ile durdur)")
    http.server.HTTPServer(("127.0.0.1", 8001), Handler).serve_forever()
