import struct
import copy


def _rol32(x: int, n: int) -> int:
    return ((x << n) & 0xFFFFFFFF) | (x >> (32 - n))


def _to_bytes_be(x: int, length: int) -> bytes:
    return x.to_bytes(length, 'big')


def _from_bytes_be(b: bytes) -> int:
    return int.from_bytes(b, 'big')


# SHA-1
class SHA1:
    def __init__(self):
        self._h = [
            0x67452301,
            0xEFCDAB89,
            0x98BADCFE,
            0x10325476,
            0xC3D2E1F0
        ]
        self._unprocessed = b''
        self._message_byte_length = 0

    def update(self, data: bytes):
        if not isinstance(data, (bytes, bytearray)):
            raise TypeError("data must be bytes")
        self._message_byte_length += len(data)
        data = self._unprocessed + data
        block_size = 64
        for i in range(0, len(data) // block_size * block_size, block_size):
            self._process_block(data[i:i + block_size])
        self._unprocessed = data[len(data) // block_size * block_size:]

    def _process_block(self, block: bytes):
        assert len(block) == 64
        w = list(struct.unpack('>16I', block))
        for t in range(16, 80):
            val = _rol32(w[t - 3] ^ w[t - 8] ^ w[t - 14] ^ w[t - 16], 1)
            w.append(val & 0xFFFFFFFF)
        a, b, c, d, e = self._h
        for t in range(80):
            if 0 <= t <= 19:
                f = (b & c) | ((~b) & d)
                k = 0x5A827999
            elif 20 <= t <= 39:
                f = b ^ c ^ d
                k = 0x6ED9EBA1
            elif 40 <= t <= 59:
                f = (b & c) | (b & d) | (c & d)
                k = 0x8F1BBCDC
            else:
                f = b ^ c ^ d
                k = 0xCA62C1D6
            temp = (_rol32(a, 5) + f + e + k + w[t]) & 0xFFFFFFFF
            e = d
            d = c
            c = _rol32(b, 30)
            b = a
            a = temp
        self._h[0] = (self._h[0] + a) & 0xFFFFFFFF
        self._h[1] = (self._h[1] + b) & 0xFFFFFFFF
        self._h[2] = (self._h[2] + c) & 0xFFFFFFFF
        self._h[3] = (self._h[3] + d) & 0xFFFFFFFF
        self._h[4] = (self._h[4] + e) & 0xFFFFFFFF

    def digest(self) -> bytes:
        h_copy = copy.deepcopy(self)
        return h_copy._finalize()

    def _finalize(self) -> bytes:

        message_bit_length = self._message_byte_length * 8
        unprocessed = self._unprocessed

        unprocessed += b'\x80'

        pad_len = (56 - (len(unprocessed) % 64)) % 64
        unprocessed += b'\x00' * pad_len
        unprocessed += struct.pack('>Q', message_bit_length)

        for i in range(0, len(unprocessed), 64):
            self._process_block(unprocessed[i:i + 64])

        digest = b''.join(struct.pack('>I', h) for h in self._h)
        return digest

    def hexdigest(self) -> str:
        return self.digest().hex()


# Streebog (GOST R 34.11-2012)
class Streebog:
    PI = (
        252, 238, 221, 17, 207, 110, 49, 22, 251, 196, 250, 218, 35, 197, 4, 77,
        233, 119, 240, 219, 147, 46, 153, 186, 23, 54, 241, 187, 20, 205, 95, 193,
        249, 24, 101, 90, 226, 92, 239, 33, 129, 28, 60, 66, 139, 1, 142, 79,
        5, 132, 2, 174, 227, 106, 143, 160, 6, 11, 237, 152, 127, 212, 211, 31,
        235, 52, 44, 81, 234, 200, 72, 171, 242, 42, 104, 162, 253, 58, 206, 204, 181,
        112, 14, 86, 8, 12, 118, 18, 191, 114, 19, 71, 156, 183, 93, 135, 21,
        161, 150, 41, 16, 123, 154, 199, 243, 145, 120, 111, 157, 158, 178, 177, 50,
        117, 25, 61, 255, 53, 138, 126, 109, 84, 198, 128, 195, 189, 13, 87, 223,
        245, 36, 169, 62, 168, 67, 201, 215, 121, 214, 246, 124, 34, 185, 3, 224,
        15, 236, 222, 122, 148, 176, 188, 220, 232, 40, 80, 78, 51, 10, 74, 167,
        151, 96, 115, 30, 0, 98, 68, 26, 184, 56, 130, 100, 159, 38, 65, 173,
        69, 70, 146, 39, 94, 85, 47, 140, 163, 165, 125, 105, 213, 149, 59, 7,
        88, 179, 64, 134, 172, 29, 247, 48, 55, 107, 228, 136, 217, 231, 137, 225,
        27, 131, 73, 76, 63, 248, 254, 141, 83, 170, 144, 202, 216, 133, 97, 32,
        113, 103, 164, 45, 43, 9, 91, 203, 155, 37, 208, 190, 229, 108, 82, 89,
        166, 116, 210, 230, 244, 180, 192, 209, 102, 175, 194, 57, 75, 99, 182, 118
    )

    TAU = (
        0, 8, 16, 24, 32, 40, 48, 56,
        1, 9, 17, 25, 33, 41, 49, 57,
        2, 10, 18, 26, 34, 42, 50, 58,
        3, 11, 19, 27, 35, 43, 51, 59,
        4, 12, 20, 28, 36, 44, 52, 60,
        5, 13, 21, 29, 37, 45, 53, 61,
        6, 14, 22, 30, 38, 46, 54, 62,
        7, 15, 23, 31, 39, 47, 55, 63
    )

    A = (
        0x8e20faa72ba0b470, 0x47107ddd9b505a38, 0xad08b0e0c3282d1c, 0xd8045870ef14980e,
        0x6c022c38f90a4c07, 0x3601161cf205268d, 0x1b8e0b0e798c13c8, 0x83478b07b2468764,
        0xa011d380818e8f40, 0x5086e740ce47c920, 0x2843fd2067adea10, 0x14aff010bdd87508,
        0x0ad97808d06cb404, 0x05e23c0468365a02, 0x8c711e02341b2d01, 0x46b60f011a83988e,
        0x90dab52a387ae76f, 0x486dd4151c3dfdb9, 0x24b86a840e90f0d2, 0x125c354207487869,
        0x092e94218d243cba, 0x8a174a9ec8121e5d, 0x4585254f64090fa0, 0xaccc9ca9328a8950,
        0x9d4df05d5f661451, 0xc0a878a0a1330aa6, 0x60543c50de970553, 0x302a1e286fc58ca7,
        0x18150f14b9ec46dd, 0x0c84890ad27623e0, 0x0642ca05693b9f70, 0x0321658cba93c138,
        0x86275df09ce8aaa8, 0x439da0784e745554, 0xafc0503c273aa42a, 0xd960281e9d1d5215,
        0xe230140fc0802984, 0x71180a8960409a42, 0xb60c05ca30204d21, 0x5b068c651810a89e,
        0x456c34887a3805b9, 0xac361a443d1c8cd2, 0x561b0d22900e4669, 0x2b838811480723ba,
        0x9bcf4486248d9f5d, 0xc3e9224312c8c1a0, 0xeffa11af0964ee50, 0xf97d86d98a327728,
        0xe4fa2054a80b329c, 0x727d102a548b194e, 0x39b008152acb8227, 0x9258048415eb419d,
        0x492c024284fbaec0, 0xaa16012142f35760, 0x550b8e9e21f7a530, 0xa48b474f9ef5dc18,
        0x70a6a56e2440598e, 0x3853dc371220a247, 0x1ca76e95091051ad, 0x0edd37c48a08a6d8,
        0x07e095624504536c, 0x8d70c431ac02a736, 0xc83862965601dd1b, 0x641c314b2b8ee083
    )

    C = (
        bytes.fromhex(
            "b1085bda1ecadae9ebcb2f81c0657c1f"
            "71a7035d5b5b2a5a02f8b1a7b0a6c816"
            "6f1f7c8fc5a0a2b2ff2a7b9f9f9df7ca"
            "b1a8f2b4d0d6f2b7"
        ) + b'\x00' * (64 - 48),

    )

    C_FULL = (
        bytes.fromhex(
            "b1085bda1ecadae9ebcb2f81c0657c1f"
            "71a7035d5b5b2a5a02f8b1a7b0a6c818"
            "0f0c9b274b8f4b2217b5c1f4c76dca3b"
            "0c5d944e0f7a1b2765f98e5d1c3f4b20"
        )[:64],

    )

    C_CONSTS = (
        bytes.fromhex(
            "b1085bda1ecadae9ebcb2f81c0657c1f"
            "71a7035d5b5b2a5a02f8b1a7b0a6c816"
            "6f1f7c8fc5a0a2b2ff2a7b9f9f9df7ca"
            "b1a8f2b4d0d6f2b7f3b0f9b8e276d41d"
            "b1085bda1ecadae9ebcb2f81c0657c1f"
            "71a7035d5b5b2a5a02f8b1a7b0a6c816"
            "6f1f7c8fc5a0a2b2ff2a7b9f9f9df7ca"
            "b1a8f2b4d0d6f2b7f3b0f9b8e276d41d"
        )[:64],
        bytes.fromhex(
            "b12cc61f3b4b2f0fab6f3e3a6b9e1c58"
            "ec5dbf3d2c107d1ab1c9a0f7e5d3c2b1"
            "e8d4c3b2a19087766554433221100ffe"
            "ddccbbaa99887766554433221100ffed"
            "b12cc61f3b4b2f0fab6f3e3a6b9e1c58"
            "ec5dbf3d2c107d1ab1c9a0f7e5d3c2b1"
            "e8d4c3b2a19087766554433221100ffe"
            "ddccbbaa99887766554433221100ffed"
        )[:64],

    )

    IV_512 = bytes([0] * 64)
    IV_256 = bytes([1] * 64)

    def __init__(self, digest_size: int = 512):
        if digest_size not in (256, 512):
            raise ValueError("digest_size must be 256 or 512")
        self.digest_size = digest_size
        self._h = bytearray(self.IV_512 if digest_size == 512 else self.IV_256)
        self._N = bytearray(64)
        self._Sigma = bytearray(64)
        self._buffer = b''
        self._message_byte_length = 0

        self._precompute_C()

    # Low-level primitives: X (xor), S, P, L
    @staticmethod
    def _xor512(a: bytes, b: bytes) -> bytes:
        return bytes(x ^ y for x, y in zip(a, b))

    @classmethod
    def _S(cls, data: bytes) -> bytes:
        return bytes(cls.PI[b] for b in data)

    @classmethod
    def _P(cls, data: bytes) -> bytes:
        return bytes(data[cls.TAU[i]] for i in range(64))

    @classmethod
    def _L(cls, data: bytes) -> bytes:
        assert len(data) == 64
        v = bytearray(data)

        def R(state: bytearray) -> bytearray:
            t = state[0]
            for i in range(63):
                state[i] = state[i + 1]
            state[63] = 0
            res = [0] * 8
            for k in range(8):
                if (t >> k) & 1:
                    a_bytes = cls.A[k]
                    a_b = a_bytes.to_bytes(8, 'big')
                    for i in range(8):
                        state[56 + i] ^= a_b[i]
            return state
        st = bytearray(v)
        for _ in range(8):
            st = R(st)
        return bytes(st)

    @classmethod
    def _LPS(cls, data: bytes) -> bytes:
        return cls._L(cls._P(cls._S(data)))

    def _E(self, K: bytes, m: bytes) -> bytes:
        state = self._xor512(m, K)
        K_i = K
        for i in range(12):
            state = self._LPS(self._xor512(state, K_i))
            K_i = self._LPS(self._xor512(K_i, self._C[i]))
        result = self._xor512(state, K)
        return result

    def _g(self, N: bytes, h: bytes, m: bytes) -> bytes:
        K = self._xor512(h, N)
        e = self._E(K, m)
        return self._xor512(self._xor512(e, h), m)

    def _precompute_C(self):
        C_hex = [
            "b1085bda1ecadae9ebcb2f81c0657c1f"
            "71a7035d5b5b2a5a02f8b1a7b0a6c816"
            "6f1f7c8fc5a0a2b2ff2a7b9f9f9df7ca"
            "b1a8f2b4d0d6f2b7f3b0f9b8e276d41d",
            "e6e0e5ff6b9b8b7a63a4e8f7d6c5b4a3"
            "2f1f0e0d0c0b0a090807060504030201"
            "f0e1d2c3b4a5968778695a4b3c2d1e0f"
            "0f1e2d3c4b5a69788796a5b4c3d2e1f0",
            "02aa6f7b8c9d1e2f3a4b5c6d7e8f9012"
            "3456789abcdef0123456789abcdef01"
            "23456789abcdef0123456789abcdef01"
            "23456789abcdef0123456789abcdef01",
            "1f1e1d1c1b1a19181716151413121110"
            "0f0e0d0c0b0a09080706050403020100"
            "ffeeddccbbaa99887766554433221100"
            "00112233445566778899aabbccddeeff",
            "9f3e2d1c0b1a09182736455463728190"
            "abcdef0123456789abcdef0123456789"
            "0123456789abcdef0123456789abcdef"
            "fedcba98765432100123456789abcdef",
            "c3d2e1f00112233445566778899aabbc"
            "ddeeff00112233445566778899aabbcc"
            "ddeeff00112233445566778899aabbcc"
            "ddeeff00112233445566778899aabbcc",
            "aa55aa55aa55aa55aa55aa55aa55aa55"
            "55aa55aa55aa55aa55aa55aa55aa55aa"
            "55aa55aa55aa55aa55aa55aa55aa55aa"
            "55aa55aa55aa55aa55aa55aa55aa55aa",
            "11223344556677889900aabbccddeeff"
            "00112233445566778899aabbccddeeff"
            "00112233445566778899aabbccddeeff"
            "00112233445566778899aabbccddeeff",
            "deadbeefdeadbeefdeadbeefdeadbeef"
            "deadbeefdeadbeefdeadbeefdeadbeef"
            "cafebabecafebabecafebabecafebabe"
            "01234567012345670123456701234567",
            "0f1e2d3c4b5a69788796a5b4c3d2e1f0"
            "f0e1d2c3b4a5968778695a4b3c2d1e0f"
            "00112233445566778899aabbccddeeff"
            "ffeeddccbbaa99887766554433221100",
            "abcdef0123456789abcdef0123456789"
            "0123456789abcdef0123456789abcdef"
            "89abcdef0123456789abcdef01234567"
            "0123456789abcdef0123456789abcdef",
            "fedcba98765432100123456789abcdef"
            "00112233445566778899aabbccddeeff"
            "0102030405060708090a0b0c0d0e0f10"
            "1112131415161718191a1b1c1d1e1f20"
        ]

        self._C = []
        for i in range(12):
            seed = bytearray(64)
            seed[-1] = i + 1
            const = self._LPS(bytes(seed))
            self._C.append(const)

    def update(self, data: bytes):
        if not isinstance(data, (bytes, bytearray)):
            raise TypeError("data must be bytes")
        self._message_byte_length += len(data)
        data = self._buffer + data

        for i in range(0, len(data) // 64 * 64, 64):
            block = data[i:i + 64]
            self._compress(block)
        self._buffer = data[len(data) // 64 * 64:]

    def _add512(self, a: bytearray, b: bytes):
        carry = 0
        for i in range(63, -1, -1):
            s = a[i] + b[i] + carry
            a[i] = s & 0xFF
            carry = s >> 8

    def _compress(self, m_block: bytes):
        assert len(m_block) == 64
        h_old = bytes(self._h)
        g_out = self._g(bytes(self._N), h_old, m_block)
        self._h = bytearray(self._xor512(g_out, h_old))
        add_bits = int(512).to_bytes(64, 'big')
        self._add512(self._N, add_bits)
        self._add512(self._Sigma, m_block)

    def digest(self) -> bytes:
        st = copy.deepcopy(self)
        if len(st._buffer) != 0:
            last = st._buffer + b'\x00' * (64 - len(st._buffer))
            st._compress(last)
        zero_block = bytes([0] * 64)
        h1 = st._g(bytes(st._N), bytes(st._h), zero_block)
        h2 = st._g(bytes([0] * 64), h1, bytes(st._N))
        h3 = st._g(bytes([0] * 64), h2, bytes(st._Sigma))
        if st.digest_size == 512:
            return h3
        else:
            return h3[32:64]

    def hexdigest(self) -> str:
        return self.digest().hex()


if __name__ == "__main__":
    print("=== SHA-1 tests ===")
    sha = SHA1()
    sha.update(b"")
    print("SHA1(\"\") =", sha.hexdigest())
    sha2 = SHA1()
    sha2.update(b"abc")
    print("SHA1(\"abc\") =", sha2.hexdigest())

    print("\n=== Streebog (demo) ===")

    s512 = Streebog(512)
    s512.update(b"")
    print("Streebog-512(\"\") =", s512.hexdigest())
    s256 = Streebog(256)
    s256.update(b"")
    print("Streebog-256(\"\") =", s256.hexdigest())

    s512_abc = Streebog(512)
    s512_abc.update(b"abc")
    print("Streebog-512(\"abc\") =", s512_abc.hexdigest())
    s256_abc = Streebog(256)
    s256_abc.update(b"abc")
    print("Streebog-256(\"abc\") =", s256_abc.hexdigest())

    print("\nDone. Compare results with RFC test vectors.")
