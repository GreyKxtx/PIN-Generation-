from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import secrets

def generate_visa_pvv(card_number, pin, pvki):
    # Обчислюємо TSP = PAN11 + PVKI + PIN
    pan11 = format(int(card_number[-11:], 10), '011b')  # двійкове представлення останніх 11 цифр номера картки
    pvki_binary = format(pvki, '04b')  # двійкове представлення PVKI
    pin_binary = format(pin, '04b')  # двійкове представлення PIN
    tsp = pan11 + pvki_binary + pin_binary

    # Convert tsp to bytes
    tsp_bytes = bytes(tsp, 'utf-8')

    # Витягаємо пару ключів Key A, Key B
    key_a, key_b = generate_keys(pvki)

    # Обчислюємо Result = EncryptDES(Key A, DecryptDES(Key B, EncryptDES(Key A, TSP)))
    encrypted_tsp = encrypt_des(key_a, tsp_bytes)
    decrypted_tsp = decrypt_des(key_b, bytes.fromhex(encrypted_tsp))
    result = encrypt_des(key_a, decrypted_tsp)

    # Двопрохідна децимілізація значення Result
    result_digits = []
    for digit in result:
        result_digits.extend(divmod(int(digit, 16), 10))  # Remove subtraction of 10

    # Значення PVV дорівнює чотирьом лівим цифрам отриманого результату
    pvv = ''.join(map(str, result_digits[:4]))

    return pvv



def generate_keys(pvki):
    # Випадковим чином генеруємо ключі Key A, Key B
    key_a = secrets.token_bytes(8)
    key_b = secrets.token_bytes(8)

    return key_a, key_b

def encrypt_des(key, data):
    cipher = Cipher(algorithms.TripleDES(key), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()

    # Вирівнювання даних перед шифруванням
    padder = padding.PKCS7(algorithms.TripleDES.block_size).padder()
    padded_data = padder.update(data) + padder.finalize()

    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
    return encrypted_data.hex().upper()

def decrypt_des(key, data):
    cipher = Cipher(algorithms.TripleDES(key), modes.ECB(), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(data) + decryptor.finalize()
    return decrypted_data

# Приклад використання
card_number = "1234567890123445"  # Приклад номеру картки
pin = 9090  # Приклад PIN-коду
pvki = 1  # Приклад PVKI

pvv = generate_visa_pvv(card_number, pin, pvki)
print(f"Generated VISA PVV: {pvv}")
