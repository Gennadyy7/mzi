import copy
from struct import pack, unpack


def _rol32(x: int, n: int) -> int:
    return ((x << n) & 0xFFFFFFFF) | (x >> (32 - n))


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
        self._message_byte_length += len(data)
        data = self._unprocessed + data
        block_size = 64
        for i in range(0, len(data) // block_size * block_size, block_size):
            self._process_block(data[i:i + block_size])
        self._unprocessed = data[len(data) // block_size * block_size:]

    def _process_block(self, block: bytes):
        assert len(block) == 64
        w = list(unpack('>16I', block))
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
        unprocessed += pack('>Q', message_bit_length)

        for i in range(0, len(unprocessed), 64):
            self._process_block(unprocessed[i:i + 64])

        digest = b''.join(pack('>I', h) for h in self._h)
        return digest

    def hexdigest(self) -> str:
        return self.digest().hex()


def strxor(a: bytes, b: bytes) -> bytes:
    mlen = min(len(a), len(b))
    a_bytes = memoryview(a)
    b_bytes = memoryview(b)
    out = bytearray(mlen)
    for i in range(mlen):
        out[i] = a_bytes[i] ^ b_bytes[i]
    return bytes(out)


def modinvert(a: int, n: int) -> int:
    if a < 0:
        return n - modinvert(-a, n)
    t, newt = 0, 1
    r, newr = n, a
    while newr != 0:
        quotinent = r // newr
        t, newt = newt, t - quotinent * newt
        r, newr = newr, r - quotinent * newr
    if r > 1:
        return -1
    if t < 0:
        t = t + n
    return t


BLOCKSIZE = 64

Pi = bytearray((
    252, 238, 221, 17, 207, 110, 49, 22, 251, 196, 250,
    218, 35, 197, 4, 77, 233, 119, 240, 219, 147, 46,
    153, 186, 23, 54, 241, 187, 20, 205, 95, 193, 249,
    24, 101, 90, 226, 92, 239, 33, 129, 28, 60, 66,
    139, 1, 142, 79, 5, 132, 2, 174, 227, 106, 143,
    160, 6, 11, 237, 152, 127, 212, 211, 31, 235, 52,
    44, 81, 234, 200, 72, 171, 242, 42, 104, 162, 253,
    58, 206, 204, 181, 112, 14, 86, 8, 12, 118, 18,
    191, 114, 19, 71, 156, 183, 93, 135, 21, 161, 150,
    41, 16, 123, 154, 199, 243, 145, 120, 111, 157, 158,
    178, 177, 50, 117, 25, 61, 255, 53, 138, 126, 109,
    84, 198, 128, 195, 189, 13, 87, 223, 245, 36, 169,
    62, 168, 67, 201, 215, 121, 214, 246, 124, 34, 185,
    3, 224, 15, 236, 222, 122, 148, 176, 188, 220, 232,
    40, 80, 78, 51, 10, 74, 167, 151, 96, 115, 30,
    0, 98, 68, 26, 184, 56, 130, 100, 159, 38, 65,
    173, 69, 70, 146, 39, 94, 85, 47, 140, 163, 165,
    125, 105, 213, 149, 59, 7, 88, 179, 64, 134, 172,
    29, 247, 48, 55, 107, 228, 136, 217, 231, 137, 225,
    27, 131, 73, 76, 63, 248, 254, 141, 83, 170, 144,
    202, 216, 133, 97, 32, 113, 103, 164, 45, 43, 9,
    91, 203, 155, 37, 208, 190, 229, 108, 82, 89, 166,
    116, 210, 230, 244, 180, 192, 209, 102, 175, 194, 57,
    75, 99, 182,
))

A = [unpack(">Q", bytes.fromhex(s))[0] for s in (
    "8e20faa72ba0b470", "47107ddd9b505a38", "ad08b0e0c3282d1c", "d8045870ef14980e",
    "6c022c38f90a4c07", "3601161cf205268d", "1b8e0b0e798c13c8", "83478b07b2468764",
    "a011d380818e8f40", "5086e740ce47c920", "2843fd2067adea10", "14aff010bdd87508",
    "0ad97808d06cb404", "05e23c0468365a02", "8c711e02341b2d01", "46b60f011a83988e",
    "90dab52a387ae76f", "486dd4151c3dfdb9", "24b86a840e90f0d2", "125c354207487869",
    "092e94218d243cba", "8a174a9ec8121e5d", "4585254f64090fa0", "accc9ca9328a8950",
    "9d4df05d5f661451", "c0a878a0a1330aa6", "60543c50de970553", "302a1e286fc58ca7",
    "18150f14b9ec46dd", "0c84890ad27623e0", "0642ca05693b9f70", "0321658cba93c138",
    "86275df09ce8aaa8", "439da0784e745554", "afc0503c273aa42a", "d960281e9d1d5215",
    "e230140fc0802984", "71180a8960409a42", "b60c05ca30204d21", "5b068c651810a89e",
    "456c34887a3805b9", "ac361a443d1c8cd2", "561b0d22900e4669", "2b838811480723ba",
    "9bcf4486248d9f5d", "c3e9224312c8c1a0", "effa11af0964ee50", "f97d86d98a327728",
    "e4fa2054a80b329c", "727d102a548b194e", "39b008152acb8227", "9258048415eb419d",
    "492c024284fbaec0", "aa16012142f35760", "550b8e9e21f7a530", "a48b474f9ef5dc18",
    "70a6a56e2440598e", "3853dc371220a247", "1ca76e95091051ad", "0edd37c48a08a6d8",
    "07e095624504536c", "8d70c431ac02a736", "c83862965601dd1b", "641c314b2b8ee083",
)]

Tau = (
    0, 8, 16, 24, 32, 40, 48, 56,
    1, 9, 17, 25, 33, 41, 49, 57,
    2, 10, 18, 26, 34, 42, 50, 58,
    3, 11, 19, 27, 35, 43, 51, 59,
    4, 12, 20, 28, 36, 44, 52, 60,
    5, 13, 21, 29, 37, 45, 53, 61,
    6, 14, 22, 30, 38, 46, 54, 62,
    7, 15, 23, 31, 39, 47, 55, 63,
)

C = [bytes.fromhex("".join(s))[::-1] for s in (
    (
        "b1085bda1ecadae9ebcb2f81c0657c1f",
        "2f6a76432e45d016714eb88d7585c4fc",
        "4b7ce09192676901a2422a08a460d315",
        "05767436cc744d23dd806559f2a64507",
    ),
    (
        "6fa3b58aa99d2f1a4fe39d460f70b5d7",
        "f3feea720a232b9861d55e0f16b50131",
        "9ab5176b12d699585cb561c2db0aa7ca",
        "55dda21bd7cbcd56e679047021b19bb7",
    ),
    (
        "f574dcac2bce2fc70a39fc286a3d8435",
        "06f15e5f529c1f8bf2ea7514b1297b7b",
        "d3e20fe490359eb1c1c93a376062db09",
        "c2b6f443867adb31991e96f50aba0ab2",
    ),
    (
        "ef1fdfb3e81566d2f948e1a05d71e4dd",
        "488e857e335c3c7d9d721cad685e353f",
        "a9d72c82ed03d675d8b71333935203be",
        "3453eaa193e837f1220cbebc84e3d12e",
    ),
    (
        "4bea6bacad4747999a3f410c6ca92363",
        "7f151c1f1686104a359e35d7800fffbd",
        "bfcd1747253af5a3dfff00b723271a16",
        "7a56a27ea9ea63f5601758fd7c6cfe57",
    ),
    (
        "ae4faeae1d3ad3d96fa4c33b7a3039c0",
        "2d66c4f95142a46c187f9ab49af08ec6",
        "cffaa6b71c9ab7b40af21f66c2bec6b6",
        "bf71c57236904f35fa68407a46647d6e",
    ),
    (
        "f4c70e16eeaac5ec51ac86febf240954",
        "399ec6c7e6bf87c9d3473e33197a93c9",
        "0992abc52d822c3706476983284a0504",
        "3517454ca23c4af38886564d3a14d493",
    ),
    (
        "9b1f5b424d93c9a703e7aa020c6e4141",
        "4eb7f8719c36de1e89b4443b4ddbc49a",
        "f4892bcb929b069069d18d2bd1a5c42f",
        "36acc2355951a8d9a47f0dd4bf02e71e",
    ),
    (
        "378f5a541631229b944c9ad8ec165fde",
        "3a7d3a1b258942243cd955b7e00d0984",
        "800a440bdbb2ceb17b2b8a9aa6079c54",
        "0e38dc92cb1f2a607261445183235adb",
    ),
    (
        "abbedea680056f52382ae548b2e4f3f3",
        "8941e71cff8a78db1fffe18a1b336103",
        "9fe76702af69334b7a1e6c303b7652f4",
        "3698fad1153bb6c374b4c7fb98459ced",
    ),
    (
        "7bcd9ed0efc889fb3002c6cd635afe94",
        "d8fa6bbbebab07612001802114846679",
        "8a1d71efea48b9caefbacd1d7d476e98",
        "dea2594ac06fd85d6bcaa4cd81f32d1b",
    ),
    (
        "378ee767f11631bad21380b00449b17a",
        "cda43c32bcdf1d77f82012d430219f9b",
        "5d80ef9d1891cc86e71da4aa88e12852",
        "faf417d5d9b21b9948bc924af11bd720",
    ),
)]


def add512bit(a: bytes, b: bytes) -> bytes:
    a_arr = bytearray(a)
    b_arr = bytearray(b)
    cb = 0
    res = bytearray(64)
    for i in range(64):
        cb = a_arr[i] + b_arr[i] + (cb >> 8)
        res[i] = cb & 0xff
    return bytes(res)


def PS(data: bytes) -> bytes:
    res = bytearray(BLOCKSIZE)
    for i in range(BLOCKSIZE):
        res[Tau[i]] = Pi[data[i]]
    return bytes(res)


def L(data: bytes) -> bytes:
    res_parts = []

    for i in range(8):
        val = unpack("<Q", data[i * 8:i * 8 + 8])[0]
        res64 = 0
        for j in range(BLOCKSIZE):
            if val & 0x8000000000000000:
                res64 ^= A[j]
            val <<= 1
        res_parts.append(pack("<Q", res64))
    return b"".join(res_parts)


def LPS(data: bytes) -> bytes:
    return L(PS(data))


def E(k: bytes, msg: bytes) -> bytes:
    for i in range(12):
        msg = LPS(strxor(k, msg))
        k = LPS(strxor(k, C[i]))
    return strxor(k, msg)


def g(n: int, hsh: bytes, msg: bytes) -> bytes:
    res = E(LPS(strxor(hsh[:8], pack("<Q", n)) + hsh[8:]), msg)
    return strxor(strxor(res, hsh), msg)


class GOST34112012:
    block_size = BLOCKSIZE

    def __init__(self, digest_bits: int = 256, data: bytes = b""):
        if digest_bits not in (256, 512):
            raise ValueError("digest_bits must be 256 or 512")
        self._digest_bits = digest_bits
        self._digest_size_bytes = 32 if digest_bits == 256 else 64

        self._buffer = data

    def _compute_hash(self, data: bytes) -> bytes:
        hsh = BLOCKSIZE * (b"\x01" if self._digest_size_bytes == 32 else b"\x00")
        chk = bytes(BLOCKSIZE)
        n = 0

        for i in range(0, len(data) // BLOCKSIZE * BLOCKSIZE, BLOCKSIZE):
            block = data[i:i + BLOCKSIZE]
            hsh = g(n, hsh, block)
            chk = add512bit(chk, block)
            n += 512

        padblock_size = len(data) * 8 - n

        data_tail = data[len(data) // BLOCKSIZE * BLOCKSIZE:]
        tail = data_tail + b"\x01"
        padlen = BLOCKSIZE - len(tail) % BLOCKSIZE
        if padlen != BLOCKSIZE:
            tail = tail + (b"\x00" * padlen)

        last_block = tail[-BLOCKSIZE:]
        hsh = g(n, hsh, last_block)
        n += padblock_size
        chk = add512bit(chk, last_block)

        hsh = g(0, hsh, pack("<Q", n) + 56 * b"\x00")
        hsh = g(0, hsh, chk)
        return hsh

    def digest(self) -> bytes:
        full = self._compute_hash(self._buffer)

        return full[-self._digest_size_bytes:]

    def hexdigest(self) -> str:
        return self.digest().hex()


if __name__ == "__main__":
    print("=== SHA-1 tests ===")
    sha = SHA1()
    sha.update(b"")
    print("SHA1(\"\") =", res1 := sha.hexdigest())
    assert res1 == 'da39a3ee5e6b4b0d3255bfef95601890afd80709'
    sha2 = SHA1()
    sha2.update(b"abc")
    print("SHA1(\"abc\") =", res2 := sha2.hexdigest())
    assert res2 == 'a9993e364706816aba3e25717850c26c9cd0d89d'

    print("=== Streebog tests ===")
    for digest_bits in (256, 512):
        for data in (b'', b'abc'):
            print(f'Streebog({digest_bits=}, {data=}) = {GOST34112012(digest_bits=digest_bits, data=data).hexdigest()}')
    assert (GOST34112012(digest_bits=512, data=b'test data').hexdigest() ==
            'ac6ea199422d1cdd07602be57daf13973e147821d690226ea16ff74ad6dd99'
            'b7804d922299107a79fa89bf97f01d9d406cdb87d37507710a41ba1f0d7d2a224c')
