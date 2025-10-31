from __future__ import annotations
import random


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


if __name__ == "__main__":
    p = 751
    a = -1
    b = 188
    Gx, Gy = 0, 376
    n = 727

    curve = EllipticCurve(p=p, a=a, b=b, Gx=Gx, Gy=Gy, n=n)
    ecc = EC_ElGamal(curve)

    d, Q = ecc.generate_keypair()
    print(f"Private key: {d}")
    print(f"Public key: {Q}")

    m = 123
    print(f"\nOriginal message scalar: {m}")

    C1, C2 = ecc.encrypt(m, Q)
    print(f"Ciphertext: C1={C1}, C2={C2}")

    Pm = ecc.decrypt(d, (C1, C2))
    print(f"Decrypted point: {Pm}")

    m_recovered = ecc.recover_scalar_from_point(Pm)
    print(f"Recovered message scalar: {m_recovered}")

    assert m == m_recovered, "Decryption failed!"
    print("\n✅ EC-ElGamal test passed.")
