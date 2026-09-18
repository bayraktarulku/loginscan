"""
Login güvenlik testleri — adımları ekranda gösterir.
SADECE kendi çalıştırdığınız demo sunuculara karşı kullanın.

Kullanım:
    python3 vulnerable_app.py      # 1. terminal (port 8001)
    python3 test_login.py 8001     # 2. terminal → açıkları GÖRÜRSÜNÜZ

    python3 secure_app.py          # 1. terminal (port 8002)
    python3 test_login.py 8002     # 2. terminal → aynı testler artık BAŞARISIZ

Sadece Python standart kütüphanesi kullanır.
"""
import sys
import time
import urllib.request
import urllib.parse
import urllib.error

PORT = sys.argv[1] if len(sys.argv) > 1 else "8001"
URL = f"http://127.0.0.1:{PORT}/"


def attempt(username, password):
    """Bir login denemesi yap; (http_kodu, gövde, süre) döndür."""
    data = urllib.parse.urlencode({"username": username, "password": password}).encode()
    t0 = time.perf_counter()
    try:
        r = urllib.request.urlopen(URL, data=data, timeout=5)
        code, body = r.status, r.read().decode()
    except urllib.error.HTTPError as e:
        code, body = e.code, e.read().decode()
    return code, body, time.perf_counter() - t0


def hr(title):
    print("\n" + "=" * 60 + f"\n {title}\n" + "=" * 60)


# --- TEST 1: SQL Injection ile kimlik doğrulama atlatma -------------
hr("TEST 1 — SQL Injection ile giriş atlatma")
# username = admin'--  → sorgudaki şifre kontrolü yorum satırına düşer
code, body, _ = attempt("admin'--", "herhangi_bir_sey")
if "başarılı" in body:
    print("[!] AÇIK: 'admin'-- yükü ile şifre BİLMEDEN giriş yapıldı.")
else:
    print("[OK] SQLi engellendi (parametreli sorgu).")

# --- TEST 2: Kullanıcı adı sızdırma (enumeration) -------------------
hr("TEST 2 — Kullanıcı adı sızdırma (enumeration)")
_, body_real, _ = attempt("admin", "yanlissifre")
_, body_fake, _ = attempt("boyle_biri_yok", "yanlissifre")
print(f"   Var olan kullanıcı  -> {body_real.strip()[:60]!r}")
print(f"   Olmayan kullanıcı   -> {body_fake.strip()[:60]!r}")
if body_real != body_fake:
    print("[!] AÇIK: Mesajlar farklı → geçerli kullanıcılar ayırt edilebiliyor.")
else:
    print("[OK] Mesajlar aynı → enumeration zorlaştı.")

# --- TEST 3: Brute-force koruması var mı? --------------------------
hr("TEST 3 — Brute-force / rate limiting")
blocked = False
for i in range(1, 9):
    code, _, _ = attempt("admin", f"deneme{i}")
    print(f"   deneme {i}: HTTP {code}")
    if code == 429:
        blocked = True
        break
if blocked:
    print("[OK] Sunucu çok denemeden sonra engelledi (HTTP 429).")
else:
    print("[!] AÇIK: 8 deneme sınırsız kabul edildi — brute-force mümkün.")

# --- TEST 4: Sözlük saldırısı (dictionary attack) ------------------
hr("TEST 4 — Küçük sözlük saldırısı (admin hesabı)")
wordlist = ["123456", "password", "admin", "S3cretAdmin!", "qwerty"]
found = None
for pw in wordlist:
    code, body, _ = attempt("admin", pw)
    ok = "başarılı" in body
    print(f"   admin / {pw:<14} -> {'BULUNDU' if ok else '-'}")
    if ok:
        found = pw
        break
    time.sleep(0.05)
if found:
    print(f"[!] Şifre kırıldı: {found}  (zayıf şifre + koruma yoksa böyle olur)")
else:
    print("[OK] Sözlükteki şifreler tutmadı / sunucu engelledi.")

print("\nNot: Güvenli sunucuda (8002) 1, 2, 4 başarısız olmalı; 3 ise 429 vermeli.")
