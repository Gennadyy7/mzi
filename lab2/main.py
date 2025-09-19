import logging
from abc import ABC, abstractmethod

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("cipher.log", encoding='utf-8'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


class BelCipher:
    _H_TABLE = [
        0xFC, 0xEE, 0xDD, 0x11, 0xCF, 0x6E, 0x31, 0x16, 0xFB, 0xC4, 0xFA, 0xDA, 0x23, 0xC5, 0x04, 0x4D,
        0xE9, 0x77, 0xF0, 0xDB, 0x93, 0x2E, 0x99, 0xBA, 0x17, 0x36, 0xF1, 0xBB, 0x14, 0xCD, 0x5F, 0xC1,
        0xF9, 0x18, 0x65, 0x5A, 0xE2, 0x5C, 0xEF, 0x21, 0x81, 0x1C, 0x3C, 0x42, 0x8B, 0x01, 0x8E, 0x4F,
        0x05, 0x84, 0x02, 0xAE, 0xE3, 0x6A, 0x8F, 0xA0, 0x06, 0x0B, 0xED, 0x98, 0x7F, 0xD4, 0xD3, 0x1F,
        0xEB, 0x34, 0x2C, 0x51, 0xEA, 0xC8, 0x48, 0xAB, 0xF2, 0x2A, 0x68, 0xA2, 0xFD, 0x3A, 0xCE, 0xCC,
        0xB5, 0x70, 0x0E, 0x56, 0x08, 0x0C, 0x76, 0x12, 0xBF, 0x72, 0x13, 0x47, 0x9C, 0xB7, 0x5D, 0x87,
        0x15, 0xA1, 0x96, 0x29, 0x10, 0x7B, 0x9A, 0xC7, 0xF3, 0x91, 0x78, 0x6F, 0x9D, 0x9E, 0xB2, 0xB1,
        0x32, 0x75, 0x19, 0x3D, 0xFF, 0x35, 0x8A, 0x7E, 0x6D, 0x54, 0xC6, 0x80, 0xC3, 0xBD, 0x0D, 0x57,
        0xDF, 0xF5, 0x24, 0xA9, 0x3E, 0xA8, 0x43, 0xC9, 0xD7, 0x79, 0xD6, 0xF6, 0x7C, 0x22, 0xB9, 0x03,
        0xE0, 0x0F, 0xEC, 0xDE, 0x7A, 0x94, 0xB0, 0xBC, 0xDC, 0xE8, 0x28, 0x50, 0x4E, 0x33, 0x0A, 0x4A,
        0xA7, 0x97, 0x60, 0x73, 0x1E, 0x00, 0x62, 0x44, 0x1A, 0xB8, 0x38, 0x82, 0x64, 0x9F, 0x26, 0x41,
        0xAD, 0x45, 0x46, 0x92, 0x27, 0x5E, 0x55, 0x2F, 0x8C, 0xA3, 0xA5, 0x7D, 0x69, 0xD5, 0x95, 0x3B,
        0x07, 0x58, 0xB3, 0x40, 0x86, 0xAC, 0x1D, 0xF7, 0x30, 0x37, 0x6B, 0xE4, 0x88, 0xD9, 0xE7, 0x89,
        0xE1, 0x1B, 0x83, 0x49, 0x4C, 0x3F, 0xF8, 0xFE, 0x8D, 0x53, 0xAA, 0x90, 0xCA, 0xD8, 0x85, 0x61,
        0x20, 0x71, 0x67, 0xA4, 0x2D, 0x2B, 0x09, 0x5B, 0xCB, 0x9B, 0x25, 0xD0, 0xBE, 0xE5, 0x6C, 0x52,
        0x59, 0xA6, 0x74, 0xD2, 0xE6, 0xF4, 0xB4, 0xC0, 0xD1, 0x66, 0xAF, 0xC2, 0x39, 0x63, 0x19, 0x00
    ]

    def __init__(self, key: bytes):
        if len(key) != 32:
            raise ValueError("Ключ должен быть длиной 256 бит (32 байта).")
        self._key = key
        self._round_keys = self._generate_round_keys()
        logger.info("Инициализация BelCipher завершена. Ключ установлен.")

    def _generate_round_keys(self) -> list[int]:
        round_keys = []
        for i in range(8):
            start = i * 4
            k_i = int.from_bytes(self._key[start:start + 4], byteorder='big')
            round_keys.append(k_i)
        logger.debug(f"Сгенерировано 8 раундовых ключей: {[hex(k) for k in round_keys]}")
        return round_keys

    @staticmethod
    def _h_transform(byte_val: int) -> int:
        return BelCipher._H_TABLE[byte_val & 0xFF]

    @staticmethod
    def _g_transform(word: int) -> int:
        a_rot8 = ((word << 8) | (word >> 24)) & 0xFFFFFFFF
        h_result = 0
        for i in range(4):
            byte = (a_rot8 >> (8 * i)) & 0xFF
            h_byte = BelCipher._h_transform(byte)
            h_result |= (h_byte << (8 * i))
        g_result = ((h_result << 11) | (h_result >> 21)) & 0xFFFFFFFF
        return g_result

    @staticmethod
    def _add_mod32(a: int, b: int) -> int:
        return (a + b) & 0xFFFFFFFF

    @staticmethod
    def _sub_mod32(a: int, b: int) -> int:
        return (a - b) & 0xFFFFFFFF

    def encrypt_block(self, block: bytes) -> bytes:
        if len(block) != 16:
            raise ValueError("Блок должен быть длиной 128 бит (16 байт).")

        a = int.from_bytes(block[0:4], byteorder='big')
        b = int.from_bytes(block[4:8], byteorder='big')
        c = int.from_bytes(block[8:12], byteorder='big')
        d = int.from_bytes(block[12:16], byteorder='big')
        logger.debug(f"Начало шифрования блока. a={a:08X}, b={b:08X}, c={c:08X}, d={d:08X}")

        for i in range(8):
            ki = self._round_keys[i]
            logger.debug(f"Раунд {i + 1}: K{i + 1}={ki:08X}")

            f = self._add_mod32(self._g_transform(self._add_mod32(a, ki)), i + 1)

            a_new = self._add_mod32(b, f)
            b_new = c
            c_new = d
            d_new = f

            a, b, c, d = a_new, b_new, c_new, d_new
            logger.debug(f"После раунда {i + 1}: a={a:08X}, b={b:08X}, c={c:08X}, d={d:08X}")

        y_bytes = (b.to_bytes(4, byteorder='big') +
                   d.to_bytes(4, byteorder='big') +
                   a.to_bytes(4, byteorder='big') +
                   c.to_bytes(4, byteorder='big'))
        logger.debug(f"Блок зашифрован. Результат: {y_bytes.hex().upper()}")

        return y_bytes

    def decrypt_block(self, block: bytes) -> bytes:
        if len(block) != 16:
            raise ValueError("Блок должен быть длиной 128 бит (16 байт).")

        a = int.from_bytes(block[0:4], byteorder='big')
        b = int.from_bytes(block[4:8], byteorder='big')
        c = int.from_bytes(block[8:12], byteorder='big')
        d = int.from_bytes(block[12:16], byteorder='big')
        logger.debug(f"Начало расшифрования блока. a={a:08X}, b={b:08X}, c={c:08X}, d={d:08X}")

        for i in range(8, 0, -1):
            ki = self._round_keys[i - 1]
            logger.debug(f"Раунд {i}: K{i}={ki:08X}")

            f = d

            d_prev = c
            c_prev = b
            b_prev = self._sub_mod32(a, f)

            g_inv_input = self._sub_mod32(f, i)
            a_prev_plus_ki = self._g_inverse(g_inv_input)
            a_prev = self._sub_mod32(a_prev_plus_ki, ki)

            a, b, c, d = a_prev, b_prev, c_prev, d_prev
            logger.debug(f"После раунда {i}: a={a:08X}, b={b:08X}, c={c:08X}, d={d:08X}")

        y_bytes = (c.to_bytes(4, byteorder='big') +
                   a.to_bytes(4, byteorder='big') +
                   d.to_bytes(4, byteorder='big') +
                   b.to_bytes(4, byteorder='big'))
        logger.debug(f"Блок расшифрован. Результат: {y_bytes.hex().upper()}")

        return y_bytes

    def _g_inverse(self, word: int) -> int:
        if not hasattr(self, '_H_INV_TABLE'):
            self._H_INV_TABLE = [0] * 256
            for idx, val in enumerate(self._H_TABLE):
                self._H_INV_TABLE[val] = idx

        b_rot11r = ((word >> 11) | (word << 21)) & 0xFFFFFFFF
        h_inv_result = 0
        for i in range(4):
            byte = (b_rot11r >> (8 * i)) & 0xFF
            h_inv_byte = self._H_INV_TABLE[byte]
            h_inv_result |= (h_inv_byte << (8 * i))
        g_inv_result = ((h_inv_result >> 8) | (h_inv_result << 24)) & 0xFFFFFFFF
        return g_inv_result


class CipherMode(ABC):
    def __init__(self, cipher: BelCipher):
        self.cipher = cipher

    @abstractmethod
    def encrypt_file(self, input_path: str, output_path: str, iv: bytes | None = None):
        pass

    @abstractmethod
    def decrypt_file(self, input_path: str, output_path: str, iv: bytes | None = None):
        pass


class ECBMode(CipherMode):
    @staticmethod
    def _pad_data(data: bytes) -> bytes:
        pad_len = 16 - (len(data) % 16)
        padding = bytes([pad_len] * pad_len)
        return data + padding

    @staticmethod
    def _unpad_data(data: bytes) -> bytes:
        pad_len = data[-1]
        if pad_len < 1 or pad_len > 16:
            raise ValueError("Некорректный паддинг.")
        if data[-pad_len:] != bytes([pad_len] * pad_len):
            raise ValueError("Некорректный паддинг.")
        return data[:-pad_len]

    def encrypt_file(self, input_path: str, output_path: str, iv: bytes | None = None):
        logger.info(f"Начало шифрования файла '{input_path}' в режиме ECB.")
        with open(input_path, 'rb') as f_in:
            plaintext = f_in.read()

        padded_plaintext = self._pad_data(plaintext)
        logger.debug(
            f"Длина исходных данных: {len(plaintext)} байт. "
            f"Длина после дополнения: {len(padded_plaintext)} байт."
        )

        ciphertext = b''
        for i in range(0, len(padded_plaintext), 16):
            block = padded_plaintext[i:i + 16]
            encrypted_block = self.cipher.encrypt_block(block)
            ciphertext += encrypted_block

        with open(output_path, 'wb') as f_out:
            f_out.write(ciphertext)

        logger.info(f"Шифрование завершено. Результат записан в '{output_path}'.")

    def decrypt_file(self, input_path: str, output_path: str, iv: bytes | None = None):
        logger.info(f"Начало расшифрования файла '{input_path}' в режиме ECB.")
        with open(input_path, 'rb') as f_in:
            ciphertext = f_in.read()

        if len(ciphertext) % 16 != 0:
            raise ValueError("Длина шифротекста должна быть кратна 16 байтам.")

        plaintext_padded = b''
        for i in range(0, len(ciphertext), 16):
            block = ciphertext[i:i + 16]
            decrypted_block = self.cipher.decrypt_block(block)
            plaintext_padded += decrypted_block

        plaintext = self._unpad_data(plaintext_padded)

        with open(output_path, 'wb') as f_out:
            f_out.write(plaintext)

        logger.info(f"Расшифрование завершено. Результат записан в '{output_path}'.")


class CFBMode(CipherMode):
    def encrypt_file(self, input_path: str, output_path: str, iv: bytes | None = None):
        if iv is None:
            raise ValueError("Для режима CFB требуется синхропосылка (IV).")
        if len(iv) != 16:
            raise ValueError("Синхропосылка (IV) должна быть длиной 128 бит (16 байт).")

        logger.info(f"Начало шифрования файла '{input_path}' в режиме CFB.")
        with open(input_path, 'rb') as f_in:
            plaintext = f_in.read()

        ciphertext = b''
        prev_block = iv

        for i in range(0, len(plaintext), 16):
            plaintext_block = plaintext[i:i + 16]
            block_size = len(plaintext_block)

            encrypted_prev = self.cipher.encrypt_block(prev_block)
            gamma = encrypted_prev[:block_size]

            ciphertext_block = bytes([p ^ g for p, g in zip(plaintext_block, gamma)])
            ciphertext += ciphertext_block

            if block_size == 16:
                prev_block = ciphertext_block
            else:
                prev_block = ciphertext_block + bytes(16 - block_size)

            logger.debug(f"Обработан блок {i // 16 + 1}. Размер: {block_size} байт.")

        with open(output_path, 'wb') as f_out:
            f_out.write(ciphertext)

        logger.info(f"Шифрование завершено. Результат записан в '{output_path}'.")

    def decrypt_file(self, input_path: str, output_path: str, iv: bytes | None = None):
        if iv is None:
            raise ValueError("Для режима CFB требуется синхропосылка (IV).")
        if len(iv) != 16:
            raise ValueError("Синхропосылка (IV) должна быть длиной 128 бит (16 байт).")

        logger.info(f"Начало расшифрования файла '{input_path}' в режиме CFB.")
        with open(input_path, 'rb') as f_in:
            ciphertext = f_in.read()

        plaintext = b''
        prev_block = iv

        for i in range(0, len(ciphertext), 16):
            ciphertext_block = ciphertext[i:i + 16]
            block_size = len(ciphertext_block)

            encrypted_prev = self.cipher.encrypt_block(prev_block)
            gamma = encrypted_prev[:block_size]

            plaintext_block = bytes([c ^ g for c, g in zip(ciphertext_block, gamma)])
            plaintext += plaintext_block

            if block_size == 16:
                prev_block = ciphertext_block
            else:
                prev_block = ciphertext_block + bytes(16 - block_size)

            logger.debug(f"Обработан блок {i // 16 + 1}. Размер: {block_size} байт.")

        with open(output_path, 'wb') as f_out:
            f_out.write(plaintext)

        logger.info(f"Расшифрование завершено. Результат записан в '{output_path}'.")


def main():
    key = bytes.fromhex("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F")
    iv = bytes.fromhex("FEDCBA98765432100123456789ABCDEF")

    cipher = BelCipher(key)

    ecb_mode = ECBMode(cipher)
    cfb_mode = CFBMode(cipher)

    test_content = b"Hello, World! This is a test for Belarusian cipher.\nLine 2.\nLine 3 with some more text."
    input_file = "test_input.txt"
    with open(input_file, 'wb') as f:
        f.write(test_content)

    print("=== Тестирование режима ECB (Простая замена) ===")
    ecb_encrypted = "test_ecb_encrypted.bin"
    ecb_decrypted = "test_ecb_decrypted.txt"

    ecb_mode.encrypt_file(input_file, ecb_encrypted)
    ecb_mode.decrypt_file(ecb_encrypted, ecb_decrypted)

    with open(ecb_decrypted, 'rb') as f:
        result = f.read()
    print(f"ECB: Исходный текст совпадает с расшифрованным: {test_content == result}")
    print(f"Длина исходного: {len(test_content)}, длина расшифрованного: {len(result)}\n")

    print("=== Тестирование режима CFB (Гаммирование с обратной связью) ===")
    cfb_encrypted = "test_cfb_encrypted.bin"
    cfb_decrypted = "test_cfb_decrypted.txt"

    cfb_mode.encrypt_file(input_file, cfb_encrypted, iv)
    cfb_mode.decrypt_file(cfb_encrypted, cfb_decrypted, iv)

    with open(cfb_decrypted, 'rb') as f:
        result = f.read()
    print(f"CFB: Исходный текст совпадает с расшифрованным: {test_content == result}")
    print(f"Длина исходного: {len(test_content)}, длина расшифрованного: {len(result)}\n")

    print("Тестирование завершено. Проверьте файлы и лог 'cipher.log'.")


if __name__ == "__main__":
    main()
