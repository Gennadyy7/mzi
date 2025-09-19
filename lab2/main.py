import logging
from abc import ABC, abstractmethod

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler("cipher.log", encoding="utf-8"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


class BelCipher:
    _H_TABLE = [
        0xB1,0x94,0xBA,0xC8,0x0A,0x08,0xF5,0x3B,0x36,0x6D,0x00,0x8E,0x58,0x4A,0x5D,0xE4,
        0x85,0x04,0xFA,0x9D,0x1B,0xB6,0xC7,0xAC,0x25,0x2E,0x72,0xC2,0x02,0xFD,0xCE,0x0D,
        0x5B,0xE3,0xD6,0x12,0x17,0xB9,0x61,0x81,0xFE,0x67,0x86,0xAD,0x71,0x6B,0x89,0x0B,
        0x5C,0xB0,0xC0,0xFF,0x33,0xC3,0x56,0xB8,0x35,0xC4,0x05,0xAE,0xD8,0xE0,0x7F,0x99,
        0xE1,0x2B,0xDC,0x1A,0xE2,0x82,0x57,0xEC,0x70,0x3F,0xCC,0xF0,0x95,0xEE,0x8D,0xF1,
        0xC1,0xAB,0x76,0x38,0x9F,0xE6,0x78,0xCA,0xF7,0xC6,0xF8,0x60,0xD5,0xBB,0x9C,0x4F,
        0xF3,0x3C,0x65,0x7B,0x63,0x7C,0x30,0x6A,0xDD,0x4E,0xA7,0x79,0x9E,0xB2,0x3D,0x31,
        0x3E,0x98,0xB5,0x6E,0x27,0xD3,0xBC,0xCF,0x59,0x1E,0x18,0x1F,0x4C,0x5A,0xB7,0x93,
        0xE9,0xDE,0xE7,0x2C,0x8F,0x0C,0x0F,0xA6,0x2D,0xDB,0x49,0xF4,0x6F,0x73,0x96,0x47,
        0x06,0x07,0x53,0x16,0xED,0x24,0x7A,0x37,0x39,0xCB,0xA3,0x83,0x03,0xA9,0x8B,0xF6,
        0x92,0xBD,0x9B,0x1C,0xE5,0xD1,0x41,0x01,0x54,0x45,0xFB,0xC9,0x5E,0x4D,0x0E,0xF2,
        0x68,0x20,0x80,0xAA,0x22,0x7D,0x64,0x2F,0x26,0x87,0xF9,0x34,0x90,0x40,0x55,0x11,
        0xBE,0x32,0x97,0x13,0x43,0xFC,0x9A,0x48,0xA0,0x2A,0x88,0x5F,0x19,0x4B,0x09,0xA1,
        0x7E,0xCD,0xA4,0xD0,0x15,0x44,0xAF,0x8C,0xA5,0x84,0x50,0xBF,0x66,0xD2,0xE8,0x8A,
        0xA2,0xD7,0x46,0x52,0x42,0xA8,0xDF,0xB3,0x69,0x74,0xC5,0x51,0xEB,0x23,0x29,0x21,
        0xD4,0xEF,0xD9,0xB4,0x3A,0x62,0x28,0x75,0x91,0x14,0x10,0xEA,0x77,0x6C,0xDA,0x1D
    ]

    def __init__(self, key: bytes):
        if len(key) != 32:
            raise ValueError("Ключ должен быть длиной 256 бит (32 байта).")
        self._theta = [int.from_bytes(key[i*4:(i+1)*4], 'little') for i in range(8)]
        self._K = [self._theta[j % 8] for j in range(56)]

    @staticmethod
    def _rotl32(x, r):
        return ((x << r) | (x >> (32 - r))) & 0xFFFFFFFF

    def _G(self, u, r):
        b = [(u >> (8*i)) & 0xFF for i in range(4)]
        hb = [self._H_TABLE[x] for x in b]
        hword = hb[0] | (hb[1] << 8) | (hb[2] << 16) | (hb[3] << 24)
        return self._rotl32(hword, r)

    def encrypt_block(self, block: bytes) -> bytes:
        if len(block) != 16:
            raise ValueError("Блок должен быть 16 байт.")
        a = int.from_bytes(block[0:4], 'little')
        b = int.from_bytes(block[4:8], 'little')
        c = int.from_bytes(block[8:12], 'little')
        d = int.from_bytes(block[12:16], 'little')

        for i in range(8):
            k = self._K[7*i:7*(i+1)]
            b ^= self._G(a ^ k[0], 5)
            c ^= self._G(d ^ k[1], 21)
            a ^= self._G(b ^ k[2], 13)
            e = self._G((b ^ c) ^ k[3], 21) ^ (i+1)
            b ^= e
            c ^= e
            d ^= self._G(c ^ k[4], 13)
            b ^= self._G(a ^ k[5], 21)
            c ^= self._G(d ^ k[6], 5)

            a, b = b, a
            c, d = d, c
            b, c = c, b

        y = b.to_bytes(4, 'little') + d.to_bytes(4, 'little') + a.to_bytes(4, 'little') + c.to_bytes(4, 'little')
        return y

    def decrypt_block(self, block: bytes) -> bytes:
        if len(block) != 16:
            raise ValueError("Блок должен быть 16 байт.")
        a = int.from_bytes(block[0:4], 'little')
        b = int.from_bytes(block[4:8], 'little')
        c = int.from_bytes(block[8:12], 'little')
        d = int.from_bytes(block[12:16], 'little')

        for i in range(8, 0, -1):
            k = self._K[7*(i-1):7*i]

            b ^= self._G(a ^ k[6], 5)
            c ^= self._G(d ^ k[5], 21)
            a ^= self._G(b ^ k[4], 13)
            e = self._G((b ^ c) ^ k[3], 21) ^ i
            b ^= e
            c ^= e
            d ^= self._G(c ^ k[2], 13)
            b ^= self._G(a ^ k[1], 21)
            c ^= self._G(d ^ k[0], 5)

            a, b = b, a
            c, d = d, c
            a, d = d, a

        y = c.to_bytes(4, 'little') + a.to_bytes(4, 'little') + d.to_bytes(4, 'little') + b.to_bytes(4, 'little')
        return y


class CipherMode(ABC):
    def __init__(self, cipher: BelCipher):
        self.cipher = cipher

    @abstractmethod
    def encrypt_file(self, input_path, output_path, iv=None):
        pass

    @abstractmethod
    def decrypt_file(self, input_path, output_path, iv=None):
        pass


class ECBMode(CipherMode):
    @staticmethod
    def _pad(data: bytes) -> bytes:
        pad_len = 16 - (len(data) % 16)
        return data + bytes([pad_len]) * pad_len

    @staticmethod
    def _unpad(data: bytes) -> bytes:
        pad_len = data[-1]
        if pad_len < 1 or pad_len > 16 or data[-pad_len:] != bytes([pad_len]) * pad_len:
            raise ValueError("Некорректный паддинг")
        return data[:-pad_len]

    def encrypt_file(self, input_path, output_path, iv=None):
        with open(input_path, 'rb') as f:
            data = f.read()
        data = self._pad(data)
        out = bytearray()
        for i in range(0, len(data), 16):
            out += self.cipher.encrypt_block(data[i:i+16])
        with open(output_path, 'wb') as f:
            f.write(out)

    def decrypt_file(self, input_path, output_path, iv=None):
        with open(input_path, 'rb') as f:
            data = f.read()
        if len(data) % 16 != 0:
            raise ValueError("Некорректная длина шифротекста")
        out = bytearray()
        for i in range(0, len(data), 16):
            out += self.cipher.decrypt_block(data[i:i+16])
        out = self._unpad(bytes(out))
        with open(output_path, 'wb') as f:
            f.write(out)


class CFBMode(CipherMode):
    def encrypt_file(self, input_path, output_path, iv=None):
        if iv is None or len(iv) != 16:
            raise ValueError("CFB требует IV длиной 16 байт")
        with open(input_path, 'rb') as f:
            data = f.read()
        out = bytearray()
        prev = iv
        for i in range(0, len(data), 16):
            block = data[i:i+16]
            gamma = self.cipher.encrypt_block(prev)[:len(block)]
            ct = bytes(x ^ y for x, y in zip(block, gamma))
            out += ct
            prev = ct if len(ct) == 16 else ct + bytes(16 - len(ct))
        with open(output_path, 'wb') as f:
            f.write(out)

    def decrypt_file(self, input_path, output_path, iv=None):
        if iv is None or len(iv) != 16:
            raise ValueError("CFB требует IV длиной 16 байт")
        with open(input_path, 'rb') as f:
            data = f.read()
        out = bytearray()
        prev = iv
        for i in range(0, len(data), 16):
            block = data[i:i+16]
            gamma = self.cipher.encrypt_block(prev)[:len(block)]
            pt = bytes(x ^ y for x, y in zip(block, gamma))
            out += pt
            prev = block if len(block) == 16 else block + bytes(16 - len(block))
        with open(output_path, 'wb') as f:
            f.write(out)


def main():
    key = bytes.fromhex("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F")
    iv = bytes.fromhex("FEDCBA98765432100123456789ABCDEF")
    cipher = BelCipher(key)
    ecb = ECBMode(cipher)
    cfb = CFBMode(cipher)

    test_content = b"Hello, World! This is a test for Belarusian cipher.\nLine 2.\nLine 3 with some more text."
    with open("test_input.txt", "wb") as f:
        f.write(test_content)

    ecb.encrypt_file("test_input.txt", "ecb_enc.bin")
    ecb.decrypt_file("ecb_enc.bin", "ecb_dec.txt")
    with open("ecb_dec.txt", "rb") as f:
        print("ECB:", f.read() == test_content)

    cfb.encrypt_file("test_input.txt", "cfb_enc.bin", iv)
    cfb.decrypt_file("cfb_enc.bin", "cfb_dec.txt", iv)
    with open("cfb_dec.txt", "rb") as f:
        print("CFB:", f.read() == test_content)


if __name__ == "__main__":
    main()
