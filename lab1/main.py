import logging
import struct
from typing import List, Tuple
import os

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class GOST28147_89:
    DEFAULT_SBOX = [
        [4, 10, 9, 2, 13, 8, 0, 14, 6, 11, 1, 12, 7, 15, 5, 3],
        [14, 11, 4, 12, 6, 13, 15, 10, 2, 3, 8, 1, 0, 7, 5, 9],
        [5, 8, 1, 13, 10, 3, 4, 2, 14, 15, 12, 7, 6, 0, 9, 11],
        [7, 13, 10, 1, 0, 8, 9, 15, 14, 4, 6, 12, 11, 2, 5, 3],
        [6, 12, 7, 1, 5, 15, 13, 8, 4, 10, 9, 14, 0, 3, 11, 2],
        [4, 11, 10, 0, 7, 2, 1, 13, 3, 6, 8, 5, 9, 12, 15, 14],
        [13, 11, 4, 1, 3, 15, 5, 9, 0, 10, 14, 7, 6, 8, 2, 12],
        [1, 15, 13, 0, 5, 7, 10, 4, 9, 2, 3, 14, 6, 11, 8, 12]
    ]

    def __init__(self, key: bytes, sbox: List[List[int]] = None):
        if len(key) != 32:
            logger.error("Неверная длина ключа. Ожидается 32 байта.")
            raise ValueError("Ключ должен быть длиной 32 байта (256 бит).")

        self.key = key
        self.sbox = sbox if sbox is not None else self.DEFAULT_SBOX
        self.subkeys = self._generate_subkeys()
        logger.debug("Инициализирован объект GOST28147_89.")

    def _generate_subkeys(self) -> List[int]:
        subkeys = []
        for i in range(8):
            k_i = struct.unpack('<I', self.key[i * 4:(i + 1) * 4])[0]
            subkeys.append(k_i)
        logger.debug(f"Сгенерированы подключи: {[hex(k) for k in subkeys]}")
        return subkeys

    def _sbox_substitution(self, value: int) -> int:
        result = 0
        for i in range(8):
            nibble = value & 0xF
            substituted_nibble = self.sbox[7 - i][nibble]
            result |= (substituted_nibble << (i * 4))
            value >>= 4
        logger.debug(f"S-Box подстановка: {hex(value >> 32)} -> {hex(result)}")
        return result

    def _feistel_round(self, n1: int, n2: int, round_key: int) -> Tuple[int, int]:
        sum_mod = (n2 + round_key) & 0xFFFFFFFF
        logger.debug(f"  Сложение по mod 2^32: {hex(n2)} + {hex(round_key)} = {hex(sum_mod)}")

        substituted = self._sbox_substitution(sum_mod)
        logger.debug(f"  Подстановка: {hex(sum_mod)} -> {hex(substituted)}")

        shifted = ((substituted << 11) | (substituted >> 21)) & 0xFFFFFFFF
        logger.debug(f"  Циклический сдвиг влево на 11: {hex(substituted)} -> {hex(shifted)}")

        new_n1 = n1 ^ shifted
        logger.debug(f"  XOR с левой половиной: {hex(n1)} ^ {hex(shifted)} = {hex(new_n1)}")

        return n2, new_n1

    def encrypt_block(self, block: bytes) -> bytes:
        if len(block) != 8:
            logger.error("Неверная длина блока для шифрования. Ожидается 8 байт.")
            raise ValueError("Блок должен быть длиной 8 байт (64 бита).")

        logger.debug(f"Шифрование блока: {block.hex()}")

        n1, n2 = struct.unpack('<II', block)
        logger.debug(f"Начальные значения N1: {hex(n1)}, N2: {hex(n2)}")

        key_order = [0, 1, 2, 3, 4, 5, 6, 7, 0, 1, 2, 3, 4, 5, 6, 7,
                     0, 1, 2, 3, 4, 5, 6, 7, 7, 6, 5, 4, 3, 2, 1, 0]

        for i in range(32):
            k_index = key_order[i]
            round_key = self.subkeys[k_index]
            logger.debug(f"Раунд {i + 1}, подключ K{k_index} ({hex(round_key)})")
            n1, n2 = self._feistel_round(n1, n2, round_key)

        encrypted_block = struct.pack('<II', n1, n2)
        logger.debug(f"Зашифрованный блок: {encrypted_block.hex()}")
        return encrypted_block

    def decrypt_block(self, block: bytes) -> bytes:
        if len(block) != 8:
            logger.error("Неверная длина блока для расшифрования. Ожидается 8 байт.")
            raise ValueError("Блок должен быть длиной 8 байт (64 бита).")

        logger.debug(f"Расшифрование блока: {block.hex()}")

        n2, n1 = struct.unpack('<II', block)
        logger.debug(f"Начальные значения для расшифровки N1: {hex(n1)}, N2: {hex(n2)}")

        key_order = [0, 1, 2, 3, 4, 5, 6, 7, 7, 6, 5, 4, 3, 2, 1, 0,
                     0, 1, 2, 3, 4, 5, 6, 7, 0, 1, 2, 3, 4, 5, 6, 7]

        for i in range(32):
            k_index = key_order[i]
            round_key = self.subkeys[k_index]
            logger.debug(f"Раунд расшифровки {i + 1}, подключ K{k_index} ({hex(round_key)})")
            n1, n2 = self._feistel_round(n1, n2, round_key)

        decrypted_block = struct.pack('<II', n1, n2)
        logger.debug(f"Расшифрованный блок: {decrypted_block.hex()}")
        return decrypted_block


class GOSTGammaMode:
    def __init__(self, cipher: GOST28147_89):
        self.cipher = cipher
        logger.debug("Инициализирован режим гаммирования.")

    def encrypt(self, plaintext: bytes, iv: bytes) -> bytes:
        if len(iv) != 8:
            logger.error("Неверная длина синхропосылки. Ожидается 8 байт.")
            raise ValueError("Синхропосылка должна быть длиной 8 байт (64 бита).")

        logger.info("Начало шифрования в режиме гаммирования.")
        logger.debug(f"Открытый текст: {plaintext}")
        logger.debug(f"Синхропосылка: {iv.hex()}")

        ciphertext = bytearray()
        gamma_register = bytearray(iv)

        padding_length = (8 - len(plaintext) % 8) % 8
        padded_plaintext = plaintext + b'\x00' * padding_length
        logger.debug(f"Дополненный открытый текст: {padded_plaintext} (длина: {len(padded_plaintext)})")

        for i in range(0, len(padded_plaintext), 8):
            block = padded_plaintext[i:i + 8]
            logger.debug(f"Обработка блока {i // 8 + 1}: {block.hex()}")

            gamma_block = self.cipher.encrypt_block(bytes(gamma_register))
            logger.debug(f"  Гамма-блок: {gamma_block.hex()}")

            encrypted_block = bytes(a ^ b for a, b in zip(block, gamma_block))
            ciphertext.extend(encrypted_block)
            logger.debug(f"  Зашифрованный блок: {encrypted_block.hex()}")

            gamma_int = struct.unpack('<Q', gamma_register)[0]
            gamma_int = (gamma_int + 1) & 0xFFFFFFFFFFFFFFFF
            gamma_register = bytearray(struct.pack('<Q', gamma_int))
            logger.debug(f"  Новый регистр гаммы: {bytes(gamma_register).hex()}")

        result = bytes(ciphertext[:len(plaintext)])
        logger.info("Шифрование в режиме гаммирования завершено.")
        logger.debug(f"Итоговый зашифрованный текст: {result}")
        return result

    def decrypt(self, ciphertext: bytes, iv: bytes) -> bytes:
        logger.info("Начало расшифрования в режиме гаммирования (идентично шифрованию).")
        return self.encrypt(ciphertext, iv)


def main():
    logger.info("Запуск лабораторной работы №1. Вариант 2: Режим гаммирования.")

    key = os.urandom(32)
    logger.info(f"Сгенерированный ключ: {key.hex()}")

    cipher = GOST28147_89(key)

    gamma_mode = GOSTGammaMode(cipher)

    plaintext = "Это секретное сообщение для лабораторной работы по МЗИ!".encode('utf-8')
    logger.info(f"Исходный текст: {plaintext.decode('utf-8')}")

    iv = b'\x00\x01\x02\x03\x04\x05\x06\x07'
    logger.info(f"Синхропосылка: {iv.hex()}")

    try:
        ciphertext = gamma_mode.encrypt(plaintext, iv)
        logger.info(f"Зашифрованный текст: {ciphertext.hex()}")

        decrypted_text = gamma_mode.decrypt(ciphertext, iv)
        logger.info(f"Расшифрованный текст: {decrypted_text.decode('utf-8')}")

        if plaintext == decrypted_text:
            logger.info("Проверка пройдена: исходный текст совпадает с расшифрованным!")
        else:
            logger.error("Ошибка: исходный текст НЕ совпадает с расшифрованным!")

    except Exception as e:
        logger.error(f"Произошла ошибка: {e}")


if __name__ == "__main__":
    main()
