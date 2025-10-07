import numpy as np
import random
from dataclasses import dataclass


def bytes_to_bits(data: bytes) -> list[int]:
    bits = []
    for b in data:
        for i in range(8):
            bits.append((b >> (7 - i)) & 1)
    return bits


def bits_to_bytes(bits: list[int]) -> bytes:
    extra = (-len(bits)) % 8
    if extra:
        bits = bits + [0] * extra
    bts = bytearray()
    for i in range(0, len(bits), 8):
        byte = 0
        for j in range(8):
            byte = (byte << 1) | bits[i + j]
        bts.append(byte)
    return bytes(bts)


def random_error_vector(n: int, t: int) -> np.ndarray:
    # w = random.randint(0, t)
    w = t
    pos = random.sample(range(n), w)
    vec = np.zeros(n, dtype=np.uint8)
    for p in pos:
        vec[p] = 1
    return vec


class LinearCode:
    def __init__(self, n: int, k: int, t: int):
        self.n = n
        self.k = k
        self.t = t

    def generator_matrix(self) -> np.ndarray:
        raise NotImplementedError

    def decode(self, received: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
        raise NotImplementedError


class Hamming74(LinearCode):
    def __init__(self):
        super().__init__(n=7, k=4, t=1)
        self._G = np.array([
            [1, 0, 0, 0, 1, 1, 1],
            [0, 1, 0, 0, 1, 1, 0],
            [0, 0, 1, 0, 1, 0, 1],
            [0, 0, 0, 1, 0, 1, 1],
        ], dtype=np.uint8)
        self._H = np.array([
            [1, 1, 1, 0, 1, 0, 0],
            [1, 1, 0, 1, 0, 1, 0],
            [1, 0, 1, 1, 0, 0, 1],
        ], dtype=np.uint8)
        self._syndrome_table = {}
        for pos in range(self.n):
            e = np.zeros(self.n, dtype=np.uint8)
            e[pos] = 1
            s = tuple((self._H @ e) % 2)
            self._syndrome_table[s] = pos

    def generator_matrix(self):
        return self._G.copy()

    def decode(self, received: np.ndarray):
        s = tuple((self._H @ received) % 2)
        err = np.zeros(self.n, dtype=np.uint8)
        if s != (0,) * (self.n - self.k):
            pos = self._syndrome_table.get(s)
            if pos is not None:
                err[pos] = 1
        corrected = (received + err) % 2
        G = self._G
        for candidate in range(1 << self.k):  # поиск сообщения m такого, что m * G mod 2 = corrected (просто так решить относительно m не выйдет из-за необратимой матрицы G)
            m_bits = np.array([(candidate >> (self.k - 1 - i)) & 1 for i in range(self.k)], dtype=np.uint8)  # Преобразует целое число candidate в двоичный вектор длиной k=4. Например, для candidate = 5 (двоичное 0101) получается массив [0, 1, 0, 1].
            if np.array_equal((m_bits @ G) % 2, corrected):
                return m_bits, err
        return np.zeros(self.k, dtype=np.uint8), err


@dataclass
class KeyPair:
    S: np.ndarray
    G: np.ndarray
    P: np.ndarray
    Gpub: np.ndarray
    t: int


class McEliece:
    def __init__(self, code: LinearCode):
        self.code = code
        self.n = code.n
        self.k = code.k
        self.t = code.t

    @staticmethod
    def _random_invertible_matrix(k: int) -> np.ndarray:
        while True:
            M = np.random.randint(0, 2, size=(k, k), dtype=np.uint8)
            try:
                _ = McEliece._inverse_matrix_mod2(M)  # в поле GF(2) - Галуа Field порядка 2
                return M
            except ValueError:
                continue

    @staticmethod
    def _random_permutation_matrix(n: int) -> np.ndarray:
        perm = list(range(n))
        random.shuffle(perm)
        P = np.zeros((n, n), dtype=np.uint8)
        for i, p in enumerate(perm):
            P[i, p] = 1
        return P

    @staticmethod
    def _matrix_mod2(A: np.ndarray) -> np.ndarray:
        return (A % 2).astype(np.uint8)

    def keygen(self) -> KeyPair:
        G = self.code.generator_matrix()
        S = self._random_invertible_matrix(self.k)
        P = self._random_permutation_matrix(self.n)
        G1 = self._matrix_mod2(S @ G @ P)
        return KeyPair(S=S, G=G, P=P, Gpub=G1, t=self.t)

    def encrypt_block(self, M_bits: np.ndarray, Gpub: np.ndarray) -> np.ndarray:
        codeword = (M_bits @ Gpub) % 2
        z = random_error_vector(self.n, self.t)
        C = (codeword + z) % 2
        return C

    def decrypt_block(self, C: np.ndarray, keypair: KeyPair) -> np.ndarray:
        P_inv = keypair.P.T
        C1 = (C @ P_inv) % 2
        m1_bits, err = self.code.decode(C1)
        S = keypair.S
        S_inv = self._inverse_matrix_mod2(S)
        M = (m1_bits @ S_inv) % 2
        return M

    @staticmethod
    def _inverse_matrix_mod2(A: np.ndarray) -> np.ndarray:  # метод Гаусса–Жордана
        k = A.shape[0]
        M = np.concatenate([A.copy().astype(np.uint8), np.eye(k, dtype=np.uint8)], axis=1)
        row = 0
        for col in range(k):
            sel = None
            for r in range(row, k):
                if M[r, col] == 1:
                    sel = r
                    break
            if sel is None:
                continue
            if sel != row:
                M[[sel, row]] = M[[row, sel]]
            for r in range(k):
                if r != row and M[r, col] == 1:
                    M[r] ^= M[row]
            row += 1
            if row == k:
                break
        left = M[:, :k]
        right = M[:, k:]
        if not np.array_equal(left, np.eye(k, dtype=np.uint8)):
            raise ValueError("Matrix not invertible over GF(2)")
        return right % 2

    def encrypt_file(self, infile: str, outfile: str, Gpub: np.ndarray):
        with open(infile, "rb") as f:
            data = f.read()
        orig_len = len(data)
        bits = bytes_to_bits(data)
        k = self.k
        n = self.n
        blocks = []
        for i in range(0, len(bits), k):
            block = bits[i:i + k]
            if len(block) < k:
                block = block + [0] * (k - len(block))
            blocks.append(np.array(block, dtype=np.uint8))
        cipher_bits = []
        for m in blocks:
            c = self.encrypt_block(m, Gpub)
            cipher_bits.extend(int(x) for x in c)
        header = orig_len.to_bytes(8, byteorder="big") + n.to_bytes(2, "big") + k.to_bytes(2, "big") + self.t.to_bytes(
            2, "big")
        out_bytes = header + bits_to_bytes(cipher_bits)
        with open(outfile, "wb") as f:
            f.write(out_bytes)

    def decrypt_file(self, infile: str, outfile: str, keypair: KeyPair):
        with open(infile, "rb") as f:
            all_bytes = f.read()
        orig_len = int.from_bytes(all_bytes[:8], "big")
        n = int.from_bytes(all_bytes[8:10], "big")
        cipher_bytes = all_bytes[14:]
        cipher_bits = bytes_to_bits(cipher_bytes)
        blocks = []
        for i in range(0, len(cipher_bits), n):
            block = cipher_bits[i:i + n]
            if len(block) < n:
                block = block + [0] * (n - len(block))
            blocks.append(np.array(block, dtype=np.uint8))
        recovered_bits = []
        for c in blocks:
            m = self.decrypt_block(c, keypair)
            recovered_bits.extend(int(x) for x in m)
        recovered_bytes = bits_to_bytes(recovered_bits)
        recovered_bytes = recovered_bytes[:orig_len]
        with open(outfile, "wb") as f:
            f.write(recovered_bytes)


def demo_hamming_file_roundtrip():
    code = Hamming74()
    mc = McEliece(code)
    kp = mc.keygen()
    inp = "demo_input.txt"
    mid = "demo_enc.bin"
    out = "demo_out.txt"
    sample = "Привет, McEliece! This is a test.".encode('utf-8')
    with open(inp, "wb") as f:
        f.write(sample)
    print("Key params:", code.n, code.k, code.t)
    mc.encrypt_file(inp, mid, kp.Gpub)
    mc.decrypt_file(mid, out, kp)
    with open(out, "rb") as f:
        res = f.read()
    print("Original:", sample.decode('utf-8'))
    print("Recovered:", res.decode('utf-8'))
    assert res == sample
    print("Roundtrip OK")


if __name__ == "__main__":
    demo_hamming_file_roundtrip()
