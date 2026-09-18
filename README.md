# loginscan

Kendi login endpoint'inizi **savunma amaçlı** tarayan, bağımlılıksız (yalnızca Python
standart kütüphanesi) hafif bir güvenlik aracı. Kendi sisteminizin adresini verirsiniz,
`loginscan` sırayla bir dizi kontrol çalıştırıp **açıkları bulur ve nasıl düzeltileceğini**
söyler.

> ⚠️ **Yalnızca yetkili kullanım.** Bu aracı sadece **size ait** olan veya **yazılı test
> izniniz** olan sistemlerde çalıştırın. İzinsiz güvenlik taraması birçok ülkede suçtur.
> Araç, açık bir onay (`--i-own-this` / `authorized=True`) olmadan çalışmaz.

## Neden "güvenli"?

Bu bir saldırı aracı değildir. Bilinçli olarak:

- **Şifre kırmaz** — sözlük/brute-force yapmaz, şifre listesi taşımaz. "Brute-force testi"
  yalnızca *rate limiting var mı* diye 5-6 istekle yoklar.
- **Düşük hacimlidir** — toplam istek sayısı bir bütçeyle sınırlıdır (varsayılan 25).
- **Zarar vermez** — yalnızca tespit amaçlı, iyi bilinen zararsız girdiler gönderir; veri
  değiştirmez.

## Kurulum

```bash
pip install .
# veya geliştirme için:
pip install -e .
```

## Kullanım (komut satırı)

```bash
loginscan http://127.0.0.1:8001/ --i-own-this --user admin --success "Giriş başarılı"
```

Faydalı seçenekler:

| Seçenek | Açıklama |
|---|---|
| `--i-own-this` | **Zorunlu.** Test yetkiniz olduğunu beyan eder. |
| `--user ADMIN` | Sisteminizde **gerçekten var olan** bir kullanıcı adı (şifre değil). Enumeration testini güçlendirir. |
| `--success "metin"` | Yanıtta görülürse "giriş başarılı" sayılacak metin. Birden çok verilebilir. |
| `--username-field` / `--password-field` | Form alan adları (varsayılan `username` / `password`). |
| `--field csrf=abc` | Her isteğe eklenecek sabit form alanı (ör. CSRF token). |
| `--login-page URL` | Login formunun HTML sayfası (başlık kontrolü için). |
| `--max-requests 25` | Toplam istek üst sınırı. |
| `--json rapor.json` | Raporu JSON olarak da yaz. |
| `--insecure` | TLS sertifika doğrulamasını kapat (kendi test sunucunuz için). |

Çıkış kodu: açık bulunduysa `1`, temizse `0`, yetki yoksa `2` (CI için kullanışlı).

## Kullanım (Python API)

```python
from loginscan import Scanner, ScanConfig

cfg = ScanConfig(
    url="http://127.0.0.1:8001/",
    known_username="admin",
    success_indicators=["Giriş başarılı"],
)
report = Scanner(cfg, authorized=True).run()

print(report.to_text())          # okunabilir rapor
print(report.to_json())          # JSON
print(len(report.vulnerabilities))
```

## Yaptığı kontroller

| Kontrol | Ne arar |
|---|---|
| `sqli` | SQL injection ile kimlik atlatma + veritabanı hata sızıntısı |
| `enumeration` | Var olan/olmayan kullanıcıya farklı yanıt (kullanıcı adı sızdırma) |
| `ratelimit` | Peş peşe başarısız denemeler engelleniyor mu (brute-force koruması) |
| `cookies` | Oturum cookie'sinde HttpOnly / Secure / SameSite bayrakları |
| `session` | Oturum token'ı tahmin edilebilir mi (kısa/sayısal/sıralı/düşük entropi) |
| `headers` | HTTPS, HSTS, nosniff, clickjacking koruması, Referrer-Policy, sürüm sızıntısı |

## Öğrenme demosu

Bu depodaki `vulnerable_app.py` (açıklı) ve `secure_app.py` (güvenli) sunucuları,
`loginscan`'i deneyip aradaki farkı görmek için idealdir:

```bash
python3 vulnerable_app.py    # 1. terminal → port 8001
loginscan http://127.0.0.1:8001/ --i-own-this --user admin --success "Giriş başarılı"
#   → 4 açık bulunur

python3 secure_app.py        # port 8002
loginscan http://127.0.0.1:8002/ --i-own-this --user admin --success "Giriş başarılı"
#   → SQLi / enumeration / rate-limit hepsi [OK]
```

## Lisans

MIT. Sorumluluk kullanıcıya aittir; yalnızca yetkili sistemlerde kullanın.
