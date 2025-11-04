import os

import jpegio as jio  # type: ignore
import numpy as np


def zigzag_indices(n: int = 8) -> list[tuple[int, int]]:
    inds: list[tuple[int, int]] = []
    for s in range(2 * n - 1):
        if s % 2 == 0:
            for i in range(s + 1):
                j = s - i
                if i < n and j < n:
                    inds.append((i, j))
        else:
            for j in range(s + 1):
                i = s - j
                if i < n and j < n:
                    inds.append((i, j))
    return inds


_ZIGZAG = zigzag_indices(8)


class JPEGSteganography:
    def __init__(self, path: str) -> None:
        self.path = path

    @staticmethod
    def _message_to_bits(message: str) -> list[int]:
        data = message.encode('utf-8')
        length = len(data)
        bits: list[int] = []
        bits.extend([(length >> i) & 1 for i in range(31, -1, -1)])
        for b in data:
            bits.extend([(b >> i) & 1 for i in range(7, -1, -1)])
        return bits

    @staticmethod
    def _bits_to_message(bits: list[int]) -> str:
        if len(bits) < 32:
            return ''
        length = 0
        for b in bits[:32]:
            length = (length << 1) | b
        total = 32 + length * 8
        if len(bits) < total:
            return ''
        data = bytearray()
        for i in range(length):
            byte = 0
            for j in range(8):
                byte = (byte << 1) | bits[32 + i * 8 + j]
            data.append(byte)
        return data.decode('utf-8', errors='replace')

    @staticmethod
    def _iter_coef_positions(coef_array: np.ndarray):
        h, w = coef_array.shape
        blocks_y = h // 8
        blocks_x = w // 8
        for by in range(blocks_y):
            for bx in range(blocks_x):
                base_y, base_x = by * 8, bx * 8
                for (i, j) in _ZIGZAG[1:]:
                    yield base_y + i, base_x + j

    @staticmethod
    def get_capacity_bits(jpeg_obj) -> int:
        coef = jpeg_obj.coef_arrays[0]
        h, w = coef.shape
        blocks = (h // 8) * (w // 8)
        return blocks * (8 * 8 - 1)

    def encode(self, out_path: str, message: str, verbose: bool = True) -> None:
        jpg = jio.read(self.path)
        coef = jpg.coef_arrays[0]
        bits = self._message_to_bits(message)
        cap = self.get_capacity_bits(jpg)
        if len(bits) > cap:
            raise ValueError(f"Сообщение слишком велико ({len(bits)} бит), вместимость {cap} бит.")
        bit_idx = 0
        for (y, x) in self._iter_coef_positions(coef):
            if bit_idx >= len(bits):
                break
            val = int(coef[y, x])
            desired = bits[bit_idx]
            if (val & 1) != desired:
                if val >= 0:
                    val += 1
                else:
                    val -= 1
                coef[y, x] = val
            bit_idx += 1
        jpg.coef_arrays[0] = coef
        jio.write(jpg, out_path)
        if verbose:
            print(f"Embedded {len(message.encode('utf-8'))} bytes -> {len(bits)} bits into {out_path}")

    def decode(self) -> str:
        jpg = jio.read(self.path)
        coef = jpg.coef_arrays[0]
        bits: list[int] = []
        for (y, x) in self._iter_coef_positions(coef):
            val = int(coef[y, x])
            bits.append(val & 1)
        return self._bits_to_message(bits)


def main() -> None:
    cover_path = "input.jpg"
    out_path = "stego.jpg"

    if not os.path.exists(cover_path):
        print(f"Файл {cover_path} не найден. Помести JPEG рядом с программой.")
        return

    message = (
            "Привет, это реальное сообщение, спрятанное в фотографии!"
            # * 18**3
    )

    steg = JPEGSteganography(cover_path)
    steg.encode(out_path, message)
    print(f"Сообщение внедрено в {out_path}")

    steg_reader = JPEGSteganography(out_path)
    decoded = steg_reader.decode()

    print("\nПроверка:")
    print("Исходное сообщение:", message)
    print("Извлечённое сообщение:", decoded)
    assert decoded == message, "Decoded message does not match original!"
    print("✅ ASSERT OK — сообщение восстановлено без ошибок.")


if __name__ == "__main__":
    main()
