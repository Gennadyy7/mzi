from __future__ import annotations
from dataclasses import dataclass
from typing import Optional, Tuple, Dict
import secrets


MODE2SIZE = {2001: 32, 2012: 64}


def int_from_bytes(b: bytes) -> int:
    return int.from_bytes(b, byteorder="big")


def int_to_bytes(i: int, size: int) -> bytes:
    return i.to_bytes(length=size, byteorder="big")


def modinvert(a: int, n: int) -> int:
    a = a % n
    if a == 0:
        raise ValueError("no inverse")
    t, newt = 0, 1
    r, newr = n, a
    while newr != 0:
        q = r // newr
        t, newt = newt, t - q * newt
        r, newr = newr, r - q * newr
    if r != 1:
        raise ValueError("no inverse")
    return t % n


@dataclass
class GOST3410Curve:
    p: int
    q: int
    a: int
    b: int
    x: int
    y: int

    def point_add(self, p1: Tuple[int, int], p2: Tuple[int, int]) -> Tuple[int, int]:
        (x1, y1), (x2, y2) = p1, p2
        if x1 == x2 and y1 == y2:
            inv = modinvert((2 * y1) % self.p, self.p)
            lam = ((3 * x1 * x1 + self.a) * inv) % self.p
        else:
            inv = modinvert((x2 - x1) % self.p, self.p)
            lam = ((y2 - y1) * inv) % self.p
        xr = (lam * lam - x1 - x2) % self.p
        yr = (lam * (x1 - xr) - y1) % self.p
        return xr, yr

    def scalar_mul(self, k: int, point: Optional[Tuple[int, int]] = None) -> Tuple[int, int]:
        if k <= 0:
            raise ValueError
        px, py = (self.x, self.y) if point is None else point
        rx, ry = None, None
        curx, cury = px, py
        while k:
            if k & 1:
                if rx is None:
                    rx, ry = curx, cury
                else:
                    rx, ry = self.point_add((rx, ry), (curx, cury))
            k >>= 1
            if k:
                curx, cury = self.point_add((curx, cury), (curx, cury))
        return rx, ry


def _h(s: str) -> int:
    return int(s.replace("\n", "").replace(" ", ""), 16)


CURVES: Dict[str, GOST3410Curve] = {
    "id-GostR3410-2001-CryptoPro-A-ParamSet": GOST3410Curve(
        p=_h("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD97"),
        q=_h("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF6C611070995AD10045841B09B761B893"),
        a=_h("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD94"),
        b=_h("00000000000000000000000000000000000000000000000000000000000000A6"),
        x=_h("1"),
        y=_h("8D91E471E0989CDA27DF505A453F2B7635294F2DDF23E3B122ACC99C9E9F1E14"),
    ),
    "id-GostR3410-2001-CryptoPro-B-ParamSet": GOST3410Curve(
        p=_h("8000000000000000000000000000000000000000000000000000000000000C99"),
        q=_h("800000000000000000000000000000015F700CFFF1A624E5E497161BCC8A198F"),
        a=_h("8000000000000000000000000000000000000000000000000000000000000C96"),
        b=_h("3E1AFD2FEE187E9C63995F126D8A1D54C72F046997E8C870998C4FEE9A7F0BEB"),
        x=_h("1"),
        y=_h("3FA8124359F966844B5AE1C362F3553D3C1CA2975667C06DBD7A66C0C6A6243A"),
    ),
}

DEFAULT_CURVE = CURVES["id-GostR3410-2001-CryptoPro-A-ParamSet"]


def public_key(curve: GOST3410Curve, prv: int) -> Tuple[int, int]:
    return curve.scalar_mul(prv)


def sign(curve: GOST3410Curve, prv: int, digest: bytes, rand: Optional[bytes] = None, mode: int = 2001) -> bytes:
    size = MODE2SIZE[mode]
    q = curve.q
    e = int_from_bytes(digest) % q
    if e == 0:
        e = 1
    while True:
        if rand is None:
            rand = secrets.token_bytes(size)
        k = int_from_bytes(rand) % q
        if k == 0:
            rand = None
            continue
        r_x, _ = curve.scalar_mul(k)
        r = r_x % q
        if r == 0:
            rand = None
            continue
        s = (prv * r + k * e) % q
        if s == 0:
            rand = None
            continue
        return int_to_bytes(s, size) + int_to_bytes(r, size)


def verify(curve: GOST3410Curve, pub: Tuple[int, int], digest: bytes, signature: bytes, mode: int = 2001) -> bool:
    size = MODE2SIZE[mode]
    if len(signature) != size * 2:
        return False
    q = curve.q
    p = curve.p
    s = int_from_bytes(signature[:size])
    r = int_from_bytes(signature[size:])
    if not (0 < r < q and 0 < s < q):
        return False
    e = int_from_bytes(digest) % q
    if e == 0:
        e = 1
    try:
        v = modinvert(e, q)
    except ValueError:
        return False
    z1 = (s * v) % q
    z2 = (q - (r * v) % q) % q
    p1x, p1y = curve.scalar_mul(z1)
    q1x, q1y = curve.scalar_mul(z2, point=pub)
    denom = (q1x - p1x) % p
    try:
        inv_denom = modinvert(denom, p)
    except ValueError:
        return False
    num = (q1y - p1y) % p
    lm = (inv_denom * num) % p
    lm = (lm * lm - p1x - q1x) % p
    lm = lm % q
    return lm == r


def main():
    import hashlib
    text = "Привет, GOST 34.10-2012! This is a test message for digital signature."
    msg = text.encode('utf-8')
    digest = hashlib.sha256(msg).digest()
    curve = DEFAULT_CURVE
    prv = int_from_bytes(secrets.token_bytes(32)) % curve.q
    pub = public_key(curve, prv)
    sig = sign(curve, prv, digest)
    ok = verify(curve, pub, digest, sig)
    print("Message:", msg)
    print("Private key:", hex(prv))
    print("Public key:", (hex(pub[0]), hex(pub[1])))
    print("Signature:", sig.hex())
    print("Valid:", ok)


if __name__ == "__main__":
    main()
