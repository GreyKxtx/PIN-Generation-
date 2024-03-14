from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import algorithms, Cipher, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
import secrets

def encrypt_3des(key, data):
    cipher = Cipher(algorithms.TripleDES(key), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()

    # Вирівнювання даних перед шифруванням
    padder = padding.PKCS7(algorithms.TripleDES.block_size).padder()
    padded_data = padder.update(data) + padder.finalize()

    return encryptor.update(padded_data) + encryptor.finalize()

def decimalization(pin_block, decimalization_table):
    return [decimalization_table[int(digit, 16)] for digit in pin_block if digit.isdigit()]

def generate_pin_3624(card_number, pin_generation_key, decimalization_table, pin_offset):
    pan = card_number[-16:]  # Отримати 16 цифр номера картки (останні 16 цифр)

    # Процедура генерації ключа за допомогою PBKDF2HMAC
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=24,
        salt=secrets.token_bytes(16),
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(pin_generation_key)

    # Шифрування за допомогою TripleDES
    pin_block = encrypt_3des(key, pan.encode())
    pin_block_hex = pin_block.hex().upper()  # Перетворення в шістнадцятковий формат

    # Процедура децимілізації
    pin_digits = decimalization(pin_block_hex, decimalization_table)

    # Вибрати 4 цифри з певних позицій
    pin_natural = [pin_digits[i] for i in [1, 5, 9, 13]]

    # Застосувати PIN–Offset
    pin_code = [(pin_natural[i] + pin_offset[i]) % 10 for i in range(4)]

    return ''.join(map(str, pin_code))

# Приклад використання
card_number = "1234567890123456"  # Приклад номеру картки
pin_generation_key = secrets.token_bytes(16)  # Випадковий ключ для генерації ПІН-коду
decimalization_table = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9]  # Таблиця децимілізації
pin_offset = [1, 2, 3, 4]  # Випадковий PIN–Offset

pin_code = generate_pin_3624(card_number, pin_generation_key, decimalization_table, pin_offset)
print(f"Generated IBM 3624 PIN: {pin_code}")
