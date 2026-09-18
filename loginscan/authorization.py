"""
Yetki kapısı.

Bu araç YALNIZCA size ait olan ya da yazılı test izniniz olan sistemlere
karşı çalıştırılmalıdır. İzinsiz güvenlik taraması birçok ülkede suçtur.

Scanner, `authorized=True` verilmeden çalışmayı reddeder.
"""
from __future__ import annotations


AUTHORIZATION_NOTICE = (
    "UYARI: loginscan yalnızca sahibi olduğunuz veya yazılı test izniniz olan\n"
    "sistemlerde kullanılmalıdır. İzinsiz tarama yasa dışıdır ve etik değildir.\n"
    "Tarayarak bu sistemi test etme yetkiniz olduğunu beyan etmiş olursunuz."
)


class NotAuthorized(Exception):
    """Yetki onayı verilmediğinde atılır."""


def ensure_authorized(authorized: bool) -> None:
    if not authorized:
        raise NotAuthorized(
            "Tarama reddedildi: yetki onayı yok.\n\n"
            + AUTHORIZATION_NOTICE
            + "\n\nPython API: Scanner(config, authorized=True)\n"
            "CLI:        --i-own-this bayrağını ekleyin."
        )
