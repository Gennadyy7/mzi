import hashlib
import io
import logging
import secrets
import struct
from dataclasses import dataclass

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger("Rabin")


def is_probable_prime(n, k=10):
    if n < 2:
        return False
    small_primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29]
    for p in small_primes:
        if n % p == 0:
            return n == p
    d = n - 1
    s = 0
    while d % 2 == 0:
        d //= 2
        s += 1
    for _ in range(k):
        a = secrets.randbelow(n-3) + 2
        x = pow(a, d, n)
        if x == 1 or x == n-1:
            continue
        for _ in range(s-1):
            x = (x * x) % n
            if x == n-1:
                break
        else:
            return False
    return True


def generate_prime(bits):
    assert bits >= 3
    while True:
        p = secrets.randbits(bits) | (1 << (bits-1)) | 1
        rem = p % 4
        if rem != 3:
            p += (3 - rem)
        if p.bit_length() != bits:
            continue
        if is_probable_prime(p):
            logger.debug(f"Сгенерировано простое число p (бит={bits}): {p}")
            return p


def egcd(a, b):
    if b == 0:
        return a, 1, 0
    g, x1, y1 = egcd(b, a % b)
    return g, y1, x1 - (a // b) * y1


def inv_mod(a, m):
    g, x, y = egcd(a, m)
    if g != 1:
        raise ValueError("Модульное обратное не существует")
    return x % m


@dataclass
class RabinKeyPair:
    p: int
    q: int
    n: int

    @classmethod
    def generate(cls, bits_each=256):
        logger.info("Генерация пары ключей Рабина...")
        p = generate_prime(bits_each)
        q = generate_prime(bits_each)
        while q == p:
            q = generate_prime(bits_each)
        n = p * q
        logger.info(f"Ключи сгенерированы: p_бит={p.bit_length()}, q_бит={q.bit_length()}, n_бит={n.bit_length()}")
        return cls(p=p, q=q, n=n)


class RabinCrypto:
    PADDING_MARKER = b'RBN'
    CHECKSUM_LEN = 2

    def __init__(self, keypair: RabinKeyPair):
        self.keypair = keypair
        self.n = keypair.n
        self.block_size = (self.n.bit_length() - 1) // 8
        min_overhead = 1 + len(self.PADDING_MARKER) + self.CHECKSUM_LEN
        if self.block_size <= min_overhead:
            raise ValueError("Ключ слишком мал для паддинга. Увеличьте размер ключа.")
        self.usable_bytes = self.block_size - min_overhead
        logger.info(
            f"RabinCrypto инициализирован: "
            f"n_бит={self.n.bit_length()}, "
            f"размер_блока={self.block_size}, "
            f"полезных_байт={self.usable_bytes}"
        )

    def _pad_block(self, data: bytes) -> bytes:
        chk = hashlib.sha256(data).digest()[:self.CHECKSUM_LEN]
        return b'\x00' + self.PADDING_MARKER + data + chk

    def _unpad_and_verify(self, padded: bytes) -> bytes | None:
        if len(padded) < 1 + len(self.PADDING_MARKER) + self.CHECKSUM_LEN:
            return None
        if padded[0] != 0:
            return None
        if padded[1:1+len(self.PADDING_MARKER)] != self.PADDING_MARKER:
            return None
        data = padded[1+len(self.PADDING_MARKER):-self.CHECKSUM_LEN]
        chk = padded[-self.CHECKSUM_LEN:]
        if hashlib.sha256(data).digest()[:self.CHECKSUM_LEN] != chk:
            return None
        return data

    def _encrypt_int(self, m: int) -> int:
        return (m * m) % self.n

    @staticmethod
    def _bytes_to_int(b: bytes) -> int:
        return int.from_bytes(b, 'big')

    @staticmethod
    def _int_to_bytes(i: int, size: int) -> bytes:
        return i.to_bytes(size, 'big')

    def encrypt(self, plaintext: bytes) -> bytes:
        chunks = [plaintext[i:i+self.usable_bytes] for i in range(0, len(plaintext), self.usable_bytes)]
        ciphertext_blocks = []
        for chunk in chunks:
            padded = self._pad_block(chunk)
            m = self._bytes_to_int(padded)
            if m >= self.n:
                raise ValueError("Целое число паддинг-блока >= n; увеличьте ключ или уменьшите блок.")
            c = self._encrypt_int(m)
            c_bytes = self._int_to_bytes(c, (self.n.bit_length() + 7)//8)
            ciphertext_blocks.append(c_bytes)
            logger.debug(f"Зашифрован блок {chunk!r} -> длина_шифротекста={len(c_bytes)}")
        n_bytes = self._int_to_bytes(self.n, (self.n.bit_length() + 7)//8)
        out = io.BytesIO()
        out.write(struct.pack(">I", len(n_bytes)))
        out.write(n_bytes)
        out.write(struct.pack(">H", len(ciphertext_blocks)))
        for c_bytes in ciphertext_blocks:
            out.write(struct.pack(">H", len(c_bytes)))
            out.write(c_bytes)
        return out.getvalue()

    @staticmethod
    def _sqrt_mod_prime(c, p):
        return pow(c, (p + 1) // 4, p)

    def _crt_combine(self, mp, mq):
        p, q = self.keypair.p, self.keypair.q
        n = self.n
        g, a, b = egcd(p, q)
        if g != 1:
            raise ValueError("p и q не взаимно просты")
        r1 = (a * p * mq + b * q * mp) % n
        r2 = n - r1
        r3 = (a * p * mq - b * q * mp) % n
        r4 = n - r3
        roots = sorted({r1, r2, r3, r4})
        return roots

    def _decrypt_int(self, c: int) -> bytes:
        p, q, n = self.keypair.p, self.keypair.q, self.n
        mp = self._sqrt_mod_prime(c % p, p)
        mq = self._sqrt_mod_prime(c % q, q)
        roots = self._crt_combine(mp, mq)
        logger.debug(f"Вычислены корни: {roots}")
        byte_len = (n.bit_length() + 7)//8
        for r in roots:
            b = self._int_to_bytes(r, byte_len)
            for start in range(0, byte_len):
                candidate = b[start:]
                res = self._unpad_and_verify(candidate)
                if res is not None:
                    logger.debug(f"Найден корректный корень при сдвиге={start}")
                    return res
        raise ValueError("Не удалось расшифровать блок: среди корней не найдено валидного паддинга.")

    def decrypt(self, blob: bytes) -> bytes:
        buf = io.BytesIO(blob)
        n_len_packed = buf.read(4)
        if len(n_len_packed) != 4:
            raise ValueError("Неверный формат шифротекста (длина n).")
        (n_len,) = struct.unpack(">I", n_len_packed)
        n_bytes = buf.read(n_len)
        if len(n_bytes) != n_len:
            raise ValueError("Неверный формат шифротекста (байты n).")
        n_from_file = int.from_bytes(n_bytes, 'big')
        if n_from_file != self.n:
            logger.warning("Публичный модуль в шифротексте не совпадает с keypair.n")
        (block_count,) = struct.unpack(">H", buf.read(2))
        plaintext_parts = []
        for i in range(block_count):
            (c_len,) = struct.unpack(">H", buf.read(2))
            c_bytes = buf.read(c_len)
            if len(c_bytes) != c_len:
                raise ValueError("Неверный формат шифротекста (байты c).")
            c_int = int.from_bytes(c_bytes, 'big')
            part = self._decrypt_int(c_int)
            plaintext_parts.append(part)
            logger.debug(f"Расшифрован блок {i+1}/{block_count}")
        return b''.join(plaintext_parts)


def main():
    kp = RabinKeyPair.generate(bits_each=64)
    rc = RabinCrypto(kp)
    message = "Привет, Rabin! Это короткое тестовое сообщение.".encode('utf-8')
    logger.info(f"Исходное сообщение ({len(message)} байт): {message!r}")
    ciphertext = rc.encrypt(message)
    logger.info(f"Размер шифротекста: {len(ciphertext)} байт")
    recovered = rc.decrypt(ciphertext)
    logger.info(f"Восстановленное сообщение ({len(recovered)} байт): {recovered!r}")
    assert recovered == message
    logger.info("Демонстрация успешна: восстановленное == исходное")


if __name__ == "__main__":
    main()
