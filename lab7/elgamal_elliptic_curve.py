from __future__ import annotations

import os
import random

from lab2.main import BelCipher, CFBMode
from lab5.streebog import GOST34112012


class FieldElement:
    def __init__(self, value: int, p: int):
        if not (0 <= value < p):
            raise ValueError("Value must be in [0, p).")
        self.value = value % p
        self.p = p

    def __add__(self, other: FieldElement) -> FieldElement:
        if self.p != other.p:
            raise ValueError("Cannot add elements of different fields.")
        return FieldElement((self.value + other.value) % self.p, self.p)

    def __sub__(self, other: FieldElement) -> FieldElement:
        if self.p != other.p:
            raise ValueError("Cannot subtract elements of different fields.")
        return FieldElement((self.value - other.value) % self.p, self.p)

    def __mul__(self, other: FieldElement) -> FieldElement:
        if self.p != other.p:
            raise ValueError("Cannot multiply elements of different fields.")
        return FieldElement((self.value * other.value) % self.p, self.p)

    def __truediv__(self, other: FieldElement) -> FieldElement:
        if self.p != other.p:
            raise ValueError("Cannot divide elements of different fields.")
        if other.value == 0:
            raise ZeroDivisionError("Division by zero in field.")
        inv = pow(other.value, -1, self.p)
        return FieldElement((self.value * inv) % self.p, self.p)

    def __neg__(self) -> FieldElement:
        return FieldElement((-self.value) % self.p, self.p)

    def __eq__(self, other) -> bool:
        return isinstance(other, FieldElement) and self.value == other.value and self.p == other.p

    def __repr__(self) -> str:
        return f"FieldElement({self.value}, {self.p})"


class Point:
    def __init__(self, x: FieldElement | None, y: FieldElement | None, curve: EllipticCurve):
        self.curve = curve
        if x is None and y is None:
            self.x = None
            self.y = None
        else:
            if x is None or y is None:
                raise ValueError("Both coordinates must be provided unless point is at infinity.")
            if not curve.is_on_curve(x, y):
                raise ValueError("Point is not on the curve.")
            self.x = x
            self.y = y

    @property
    def is_infinity(self) -> bool:
        return self.x is None and self.y is None

    def __add__(self, other: Point) -> Point:
        if self.curve != other.curve:
            raise ValueError("Points must be on the same curve.")

        if self.is_infinity:
            return other
        if other.is_infinity:
            return self

        p = self.curve.p
        a = self.curve.a

        x1, y1 = self.x, self.y
        x2, y2 = other.x, other.y

        if x1 == x2:
            if y1 == -y2:
                return Point.infinity(self.curve)
            if y1.value == 0:
                return Point.infinity(self.curve)
            numerator = FieldElement(3, p) * x1 * x1 + a
            denominator = FieldElement(2, p) * y1
            lam = numerator / denominator
        else:
            lam = (y2 - y1) / (x2 - x1)

        x3 = lam * lam - x1 - x2
        y3 = lam * (x1 - x3) - y1

        return Point(x3, y3, self.curve)

    def __neg__(self) -> Point:
        if self.is_infinity:
            return self
        return Point(self.x, -self.y, self.curve)

    def __mul__(self, scalar: int) -> Point:
        if scalar < 0:
            raise ValueError("Scalar must be non-negative.")
        if scalar == 0:
            return Point.infinity(self.curve)

        result = Point.infinity(self.curve)
        addend = self

        while scalar:
            if scalar & 1:
                result = result + addend
            addend = addend + addend
            scalar >>= 1

        return result

    def __rmul__(self, scalar: int) -> Point:
        return self.__mul__(scalar)

    def __eq__(self, other) -> bool:
        if not isinstance(other, Point):
            return False
        if self.curve != other.curve:
            return False
        if self.is_infinity and other.is_infinity:
            return True
        if self.is_infinity or other.is_infinity:
            return False
        return self.x == other.x and self.y == other.y

    def __repr__(self) -> str:
        if self.is_infinity:
            return "Point(infinity)"
        return f"Point({self.x.value}, {self.y.value})"

    @staticmethod
    def infinity(curve: EllipticCurve) -> Point:
        return Point(None, None, curve)


class EllipticCurve:
    def __init__(self, p: int, a: int, b: int, Gx: int, Gy: int, n: int):
        if (4 * pow(a, 3, p) + 27 * pow(b, 2, p)) % p == 0:
            raise ValueError("Invalid curve: discriminant is zero.")
        self.p = p
        self.a = FieldElement(a % p, p)
        self.b = FieldElement(b % p, p)
        self.G = Point(FieldElement(Gx, p), FieldElement(Gy, p), self)
        self.n = n

    def is_on_curve(self, x: FieldElement, y: FieldElement) -> bool:
        left = y * y
        right = x * x * x + self.a * x + self.b
        return left == right

    def random_scalar(self) -> int:
        return random.randrange(1, self.n)


class EC_ElGamal:
    def __init__(self, curve: EllipticCurve):
        self.curve = curve

    def generate_keypair(self) -> tuple[int, Point]:
        d = self.curve.random_scalar()
        Q = d * self.curve.G
        return d, Q

    def encrypt(self, message_scalar: int, public_key: Point) -> tuple[Point, Point]:
        if not (0 <= message_scalar < self.curve.n):
            raise ValueError("Message scalar out of range.")
        k = self.curve.random_scalar()
        C1 = k * self.curve.G
        Pm = message_scalar * self.curve.G
        C2 = Pm + k * public_key
        return C1, C2

    @staticmethod
    def decrypt(private_key: int, ciphertext: tuple[Point, Point]) -> Point:
        C1, C2 = ciphertext
        shared_secret = private_key * C1
        Pm = C2 + (-shared_secret)
        return Pm

    def recover_scalar_from_point(self, P: Point) -> int | None:
        if P.is_infinity:
            return 0
        candidate = self.curve.G
        for m in range(1, self.curve.n):
            if candidate == P:
                return m
            candidate = candidate + self.curve.G
        return None

    def decrypt_session_key_scalar(self, private_key: int, ciphertext: tuple[Point, Point]) -> int:
        Pm = self.decrypt(private_key, ciphertext)
        return self.recover_scalar_from_point(Pm)


def derive_key(scalar: int) -> bytes:
    data = str(scalar).encode()
    hasher = GOST34112012(digest_bits=256, data=data)
    return hasher.digest()


def hybrid_encrypt_file(input_path: str, output_path: str, public_key: Point, curve: EllipticCurve):
    ecc = EC_ElGamal(curve)

    k = curve.random_scalar()

    session_key = derive_key(k)

    iv = os.urandom(16)

    cipher = BelCipher(session_key)
    cfb = CFBMode(cipher)
    cfb.encrypt_file(input_path, "temp_enc.bin", iv)

    C1, C2 = ecc.encrypt(k, public_key)

    with open(output_path, "wb") as f:
        f.write(C1.x.value.to_bytes(2, 'big'))
        f.write(C1.y.value.to_bytes(2, 'big'))
        f.write(C2.x.value.to_bytes(2, 'big'))
        f.write(C2.y.value.to_bytes(2, 'big'))
        f.write(iv)
        with open("temp_enc.bin", "rb") as enc_f:
            f.write(enc_f.read())

    os.remove("temp_enc.bin")


def hybrid_decrypt_file(input_path: str, output_path: str, private_key: int, curve: EllipticCurve):
    ecc = EC_ElGamal(curve)

    with open(input_path, "rb") as f:
        C1x = int.from_bytes(f.read(2), 'big')
        C1y = int.from_bytes(f.read(2), 'big')
        C2x = int.from_bytes(f.read(2), 'big')
        C2y = int.from_bytes(f.read(2), 'big')
        iv = f.read(16)
        encrypted_data = f.read()

    C1 = Point(FieldElement(C1x, curve.p), FieldElement(C1y, curve.p), curve)
    C2 = Point(FieldElement(C2x, curve.p), FieldElement(C2y, curve.p), curve)

    k = ecc.decrypt_session_key_scalar(private_key, (C1, C2))
    if k is None:
        raise ValueError("Failed to recover session key scalar")

    session_key = derive_key(k)

    with open("temp_dec.bin", "wb") as f:
        f.write(encrypted_data)

    cipher = BelCipher(session_key)
    cfb = CFBMode(cipher)
    cfb.decrypt_file("temp_dec.bin", output_path, iv)

    os.remove("temp_dec.bin")


if __name__ == "__main__":
    p, a, b, Gx, Gy, n = 751, -1, 188, 0, 376, 727
    curve = EllipticCurve(p, a, b, Gx, Gy, n)
    ecc = EC_ElGamal(curve)
    private_key, public_key = ecc.generate_keypair()
    with open("test.txt", "w") as f:
        f.write("Секретное сообщение для лабораторной по защите информации!")
    hybrid_encrypt_file("test.txt", "test.hybrid", public_key, curve)
    hybrid_decrypt_file("test.hybrid", "test_decrypted.txt", private_key, curve)
    with open("test.txt", "r") as f1, open("test_decrypted.txt", "r") as f2:
        assert f1.read() == f2.read()
    print("✅ Гибридная схема работает!")
