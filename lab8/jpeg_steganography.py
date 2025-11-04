import numpy as np
from PIL import Image
from scipy.fftpack import dct, idct


class JPEGSteganography:
    BLOCK_SIZE: int = 8
    MAX_MESSAGE_LENGTH: int = 65535

    def __init__(self) -> None:
        pass

    def hide_message(self, input_path: str, message: str, output_path: str) -> None:
        if not message:
            raise ValueError("Сообщение не может быть пустым")
        if len(message.encode('utf-8')) > self.MAX_MESSAGE_LENGTH:
            raise ValueError(f"Сообщение слишком длинное (максимум {self.MAX_MESSAGE_LENGTH} байт в UTF-8)")

        image = Image.open(input_path).convert('L')
        img_array = np.array(image).astype(np.float32)

        message_bytes = message.encode('utf-8')
        header = len(message_bytes).to_bytes(2, byteorder='big')
        data_to_embed = header + message_bytes
        bits = self._bytes_to_bits(data_to_embed)

        dct_coeffs = self._apply_dct_to_image(img_array)

        available_bits = self._count_available_dct_positions(dct_coeffs)
        if len(bits) > available_bits:
            raise ValueError(
                f"Сообщение не помещается. Требуется {len(bits)} бит, доступно {available_bits}. "
                "Попробуйте использовать изображение большего размера."
            )

        modified_dct = self._embed_bits_in_dct(dct_coeffs, bits)

        reconstructed = self._apply_idct_to_image(modified_dct)
        reconstructed = np.clip(reconstructed, 0, 255).astype(np.uint8)
        output_image = Image.fromarray(reconstructed, mode='L')

        output_image.save(output_path, 'PNG')

    def extract_message(self, image_path: str) -> str:
        image = Image.open(image_path).convert('L')
        img_array = np.array(image).astype(np.float32)

        dct_coeffs = self._apply_dct_to_image(img_array)

        length_bits = self._extract_bits_from_dct(dct_coeffs, 16)
        if len(length_bits) < 16:
            raise ValueError("Невозможно извлечь длину сообщения")

        length_bytes = self._bits_to_bytes(length_bits)
        message_length = int.from_bytes(length_bytes, byteorder='big')

        if not (1 <= message_length <= self.MAX_MESSAGE_LENGTH):
            raise ValueError("Некорректная длина сообщения")

        total_bits_needed = 16 + message_length * 8
        all_bits = self._extract_bits_from_dct(dct_coeffs, total_bits_needed)
        if len(all_bits) < total_bits_needed:
            raise ValueError("Недостаточно данных для извлечения полного сообщения")

        message_bytes = self._bits_to_bytes(all_bits[16:])
        return message_bytes.decode('utf-8')

    @staticmethod
    def _bytes_to_bits(data: bytes) -> list[int]:
        bits = []
        for byte in data:
            for i in range(7, -1, -1):
                bits.append((byte >> i) & 1)
        return bits

    @staticmethod
    def _bits_to_bytes(bits: list[int]) -> bytes:
        if len(bits) % 8 != 0:
            raise ValueError("Количество битов должно быть кратно 8")
        bytes_list = []
        for i in range(0, len(bits), 8):
            byte = 0
            for j in range(8):
                byte = (byte << 1) | bits[i + j]
            bytes_list.append(byte)
        return bytes(bytes_list)

    def _apply_dct_to_image(self, img: np.ndarray) -> np.ndarray:
        h, w = img.shape
        new_h = ((h + self.BLOCK_SIZE - 1) // self.BLOCK_SIZE) * self.BLOCK_SIZE
        new_w = ((w + self.BLOCK_SIZE - 1) // self.BLOCK_SIZE) * self.BLOCK_SIZE
        padded = np.zeros((new_h, new_w), dtype=np.float32)
        padded[:h, :w] = img

        dct_coeffs = np.zeros_like(padded)
        for i in range(0, new_h, self.BLOCK_SIZE):
            for j in range(0, new_w, self.BLOCK_SIZE):
                block = padded[i:i + self.BLOCK_SIZE, j:j + self.BLOCK_SIZE]
                dct_block = dct(dct(block, axis=0, norm='ortho'), axis=1, norm='ortho')
                dct_coeffs[i:i + self.BLOCK_SIZE, j:j + self.BLOCK_SIZE] = dct_block
        return dct_coeffs

    def _apply_idct_to_image(self, dct_coeffs: np.ndarray) -> np.ndarray:
        h, w = dct_coeffs.shape
        img_recon = np.zeros_like(dct_coeffs)
        for i in range(0, h, self.BLOCK_SIZE):
            for j in range(0, w, self.BLOCK_SIZE):
                block = dct_coeffs[i:i + self.BLOCK_SIZE, j:j + self.BLOCK_SIZE]
                idct_block = idct(idct(block, axis=0, norm='ortho'), axis=1, norm='ortho')
                img_recon[i:i + self.BLOCK_SIZE, j:j + self.BLOCK_SIZE] = idct_block
        return img_recon

    def _count_available_dct_positions(self, dct_coeffs: np.ndarray) -> int:
        count = 0
        h, w = dct_coeffs.shape
        for i in range(0, h, self.BLOCK_SIZE):
            for j in range(0, w, self.BLOCK_SIZE):
                block = dct_coeffs[i:i + self.BLOCK_SIZE, j:j + self.BLOCK_SIZE]
                for u in range(self.BLOCK_SIZE):
                    for v in range(self.BLOCK_SIZE):
                        if u == 0 and v == 0:
                            continue
                        coeff = block[u, v]
                        if abs(coeff) >= 2:
                            count += 1
        return count

    def _embed_bits_in_dct(self, dct_coeffs: np.ndarray, bits: list[int]) -> np.ndarray:
        dct_copy = dct_coeffs.copy()
        bit_index = 0
        h, w = dct_copy.shape

        for i in range(0, h, self.BLOCK_SIZE):
            for j in range(0, w, self.BLOCK_SIZE):
                if bit_index >= len(bits):
                    return dct_copy
                block = dct_copy[i:i + self.BLOCK_SIZE, j:j + self.BLOCK_SIZE]
                for u in range(self.BLOCK_SIZE):
                    for v in range(self.BLOCK_SIZE):
                        if bit_index >= len(bits):
                            return dct_copy
                        if u == 0 and v == 0:
                            continue
                        coeff = block[u, v]
                        if abs(coeff) < 2:
                            continue

                        int_coeff = int(round(coeff.item()))
                        if bits[bit_index] == 0:
                            int_coeff = int_coeff - (int_coeff & 1)
                        else:
                            int_coeff = int_coeff | 1
                        block[u, v] = float(int_coeff)
                        bit_index += 1

                dct_copy[i:i + self.BLOCK_SIZE, j:j + self.BLOCK_SIZE] = block

        if bit_index < len(bits):
            raise RuntimeError("Не удалось внедрить все биты — внутренняя ошибка")
        return dct_copy

    def _extract_bits_from_dct(self, dct_coeffs: np.ndarray, num_bits: int) -> list[int]:
        bits = []
        h, w = dct_coeffs.shape

        for i in range(0, h, self.BLOCK_SIZE):
            for j in range(0, w, self.BLOCK_SIZE):
                if len(bits) >= num_bits:
                    return bits[:num_bits]
                block = dct_coeffs[i:i + self.BLOCK_SIZE, j:j + self.BLOCK_SIZE]
                for u in range(self.BLOCK_SIZE):
                    for v in range(self.BLOCK_SIZE):
                        if len(bits) >= num_bits:
                            return bits[:num_bits]
                        if u == 0 and v == 0:
                            continue
                        coeff = block[u, v]
                        if abs(coeff) < 2:
                            continue
                        int_coeff = int(round(coeff.item()))
                        bits.append(int_coeff & 1)

        return bits[:num_bits]
