from os import urandom
import secrets
import hashlib

MODE2SIZE = {2001: 32, 2012: 64}


def bytes2long(b: bytes) -> int:
    return int.from_bytes(b, "big")


def long2bytes(n: int, size: int) -> bytes:
    return n.to_bytes(size, "big")


def modinv(a: int, m: int) -> int:
    return pow(a, -1, m)


class GOST3410Curve:
    def __init__(self, p, q, a, b, x, y):
        self.p = p  # модуль конечного поля
        self.q = q  # порядок подгруппы (простое число)
        self.a = a % p
        self.b = b % p  # коэффициенты уравнения Вейерштрасса y2≡x3+ax+b(mod p)
        self.x = x % p
        self.y = y % p  # координаты базовой точки G
        lhs = (self.y * self.y) % self.p
        rhs = ((self.x * self.x + self.a) * self.x + self.b) % self.p
        if lhs != rhs:
            raise ValueError("Invalid parameters")

    def add(self, P, Q):
        if P is None:
            return Q
        if Q is None:
            return P
        x1, y1 = P
        x2, y2 = Q
        if x1 == x2:
            if (y1 + y2) % self.p == 0:
                return None
            return self.double(P)
        num = (y2 - y1) % self.p
        den = (x2 - x1) % self.p
        lam = (num * modinv(den, self.p)) % self.p
        xr = (lam * lam - x1 - x2) % self.p
        yr = (lam * (x1 - xr) - y1) % self.p
        return xr, yr

    def double(self, P):
        if P is None:
            return None
        x1, y1 = P
        if y1 % self.p == 0:
            return None
        num = (3 * x1 * x1 + self.a) % self.p
        den = (2 * y1) % self.p
        lam = (num * modinv(den, self.p)) % self.p
        xr = (lam * lam - 2 * x1) % self.p
        yr = (lam * (x1 - xr) - y1) % self.p
        return xr, yr

    def scalar_mul(self, k, P=None):
        if k % self.q == 0 or k == 0:
            return None
        if P is None:
            P = (self.x, self.y)
        result = None
        addend = P
        while k:
            if k & 1:
                result = self.add(result, addend)
            addend = self.add(addend, addend)
            k >>= 1
        return result

    def exp(self, degree, x=None, y=None):
        if degree <= 0:
            raise ValueError("Bad degree value")
        base = (x, y) if (x is not None and y is not None) else None
        P = self.scalar_mul(degree, base)
        if P is None:
            raise ValueError("Result is point at infinity")
        return P


def _h(s: str) -> int:
    return int.from_bytes(bytes.fromhex(s), "big")


CURVES = {
    "id-GostR3410-2001-CryptoPro-A-ParamSet": GOST3410Curve(
        p=_h("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD97"),
        q=_h("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF6C611070995AD10045841B09B761B893"),
        a=_h("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD94"),
        b=_h("00000000000000000000000000000000000000000000000000000000000000a6"),
        x=_h("0000000000000000000000000000000000000000000000000000000000000001"),
        y=_h("8D91E471E0989CDA27DF505A453F2B7635294F2DDF23E3B122ACC99C9E9F1E14"),
    ),
    "id-tc26-gost-3410-12-512-paramSetA": GOST3410Curve(
        p=_h(
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFDC7"
        ),
        q=_h(
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF27E69532F48D89116F"
            "F22B8D4E0560609B4B38ABFAD2B85DCACDB1411F10B275"
        ),
        a=_h(
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFDC4"
        ),
        b=_h(
            "E8C2505DEDFC86DDC1BD0B2B6667F1DA34B82574761CB0E879BD081CFD0B6265EE3CB090F30D27614C"
            "B4574010DA90DD862EF9D4EBEE4761503190785A71C760"
        ),
        x=_h(
            "0000000000000000000000000000000000000000000000000000000000000000000000000000000000"
            "0000000000000000000000000000000000000000000003"
        ),
        y=_h(
            "7503CFE87A836AE3A61B8816E25450E6CE5E1C93ACF1ABC1778064FDCBEFA921DF1626BE4FD036E93D"
            "75E6A50E3A41E98028FE5FC235F5B889A589CB5215F2A4"
        ),
    ),
}
CURVES["id-GostR3410-2001-CryptoPro-XchA-ParamSet"] = CURVES["id-GostR3410-2001-CryptoPro-A-ParamSet"]
DEFAULT_CURVE = CURVES["id-GostR3410-2001-CryptoPro-A-ParamSet"]


def public_key(curve, prv):
    return curve.exp(prv)


def sign(curve, prv, digest, rand=None, mode=2001):
    size = MODE2SIZE[mode]
    q = curve.q
    e = bytes2long(digest) % q
    if e == 0:
        e = 1
    while True:
        if rand is None:
            k_bytes = secrets.token_bytes(size)
        else:
            if len(rand) != size:
                raise ValueError("rand length != %d" % size)
            k_bytes = rand
        k = bytes2long(k_bytes) % q
        if k == 0:
            if rand is not None:
                raise ValueError("Provided rand yields k == 0")
            continue
        rx, ry = curve.exp(k)
        r = rx % q
        if r == 0:
            if rand is not None:
                raise ValueError("Provided rand yields r == 0")
            continue
        s = (prv * r + (k * e) % q) % q
        if s == 0:
            if rand is not None:
                raise ValueError("Provided rand yields s == 0")
            continue
        return long2bytes(s, size) + long2bytes(r, size)


def verify(curve, pub, digest, signature, mode=2001):
    size = MODE2SIZE[mode]
    if len(signature) != size * 2:
        raise ValueError("Invalid signature length")
    q = curve.q
    s = bytes2long(signature[:size])
    r = bytes2long(signature[size:])
    if r <= 0 or r >= q or s <= 0 or s >= q:
        return False
    e = bytes2long(digest) % q
    if e == 0:
        e = 1
    try:
        v = modinv(e, q)
    except ValueError:
        return False
    z1 = (s * v) % q
    z2 = (q - (r * v) % q) % q
    p1 = curve.scalar_mul(z1)
    p2 = curve.scalar_mul(z2, pub)
    C = curve.add(p1, p2)
    if C is None:
        return False
    cx, _ = C
    return (cx % q) == r


def run_mode(curve_name: str, mode: int, message: bytes):
    print(f"\n=== Демонстрация: mode={mode}, curve={curve_name} ===")
    curve = CURVES[curve_name]
    size = MODE2SIZE[mode]
    digest = hashlib.sha256(message).digest()
    print(f"Хеш сообщения (SHA-256): {digest.hex()}")
    while True:
        prv_bytes = urandom(size)
        prv = bytes2long(prv_bytes) % curve.q
        if 0 < prv < curve.q:
            break
    print(f"Приватный ключ (hex, {size} байт): {long2bytes(prv, size).hex()}")
    pub_x, pub_y = public_key(curve, prv)
    print(f"Публичный ключ X: {long2bytes(pub_x, size).hex()}")
    print(f"Публичный ключ Y: {long2bytes(pub_y, size).hex()}")
    sig = sign(curve, prv, digest, mode=mode)
    print(f"Подпись (s||r, {len(sig)} байт): {sig.hex()}")
    ok = verify(curve, (pub_x, pub_y), digest, sig, mode=mode)
    print(f"Результат проверки подписи: {'УСПЕШНО' if ok else 'ОШИБКА'}")
    assert ok, f"Подпись не прошла проверку для mode={mode}, curve={curve_name}"
    assert len(sig) == 2 * size, f"Ожидалось {2 * size} байт подписи, получено {len(sig)}"


def main():
    message_text = "Привет, GOST 34.10! Демонстрация двух режимов."
    message = message_text.encode("utf-8")
    print("=== Лабораторная работа №6: Демонстрация ГОСТ Р 34.10 (две конфигурации) ===")
    print(f"Исходное сообщение: {message_text!r}")
    demo_list = [
        ("id-GostR3410-2001-CryptoPro-A-ParamSet", 2001),
        ("id-tc26-gost-3410-12-512-paramSetA", 2012),
    ]
    for curve_name, mode in demo_list:
        try:
            run_mode(curve_name, mode, message)
        except Exception as exc:
            print(f"\nОшибка при выполнении mode={mode}, curve={curve_name}: {exc}")
            raise
    print("\n✅ Демонстрация завершена — оба режима успешно выполнены.")


if __name__ == "__main__":
    main()
