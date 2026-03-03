"""
des_cipher.py - Implementación DES en modo ECB con padding PKCS#7 manual (Laboratorio 1.1)

Incluye:
- Clave segura (se genera en utils.py)
- Padding PKCS#7 manual (utils.pkcs7_pad / utils.pkcs7_unpad)
- Mensajes de cualquier longitud
- Funciones de cifrado y descifrado
"""

from __future__ import annotations

from Crypto.Cipher import DES

from utils import pkcs7_pad, pkcs7_unpad, generate_des_key

DES_BLOCK_SIZE = 8  # bytes


def encrypt_des_ecb(plaintext: bytes, key: bytes) -> bytes:
    """
    Cifra usando DES en modo ECB.
    - Aplica PKCS#7 manual antes de cifrar.
    """
    if not isinstance(plaintext, (bytes, bytearray)):
        raise TypeError("plaintext debe ser bytes o bytearray")
    if not isinstance(key, (bytes, bytearray)):
        raise TypeError("key debe ser bytes o bytearray")

    key_bytes = bytes(key)
    if len(key_bytes) != DES_BLOCK_SIZE:
        raise ValueError("La clave DES debe ser de 8 bytes")

    pt = bytes(plaintext)
    padded = pkcs7_pad(pt, DES_BLOCK_SIZE)

    cipher = DES.new(key_bytes, DES.MODE_ECB)
    return cipher.encrypt(padded)


def decrypt_des_ecb(ciphertext: bytes, key: bytes) -> bytes:
    """
    Descifra usando DES en modo ECB.
    - Elimina PKCS#7 manual después de descifrar.
    """
    if not isinstance(ciphertext, (bytes, bytearray)):
        raise TypeError("ciphertext debe ser bytes o bytearray")
    if not isinstance(key, (bytes, bytearray)):
        raise TypeError("key debe ser bytes o bytearray")

    key_bytes = bytes(key)
    if len(key_bytes) != DES_BLOCK_SIZE:
        raise ValueError("La clave DES debe ser de 8 bytes")

    ct = bytes(ciphertext)
    if len(ct) == 0 or (len(ct) % DES_BLOCK_SIZE) != 0:
        raise ValueError("Ciphertext inválido: longitud no es múltiplo de 8 bytes")

    cipher = DES.new(key_bytes, DES.MODE_ECB)
    padded_plaintext = cipher.decrypt(ct)

    return pkcs7_unpad(padded_plaintext, DES_BLOCK_SIZE)


# ---------------------------
# Demo
# ---------------------------
if __name__ == "__main__":

    key = generate_des_key()
    msg = b"Hola, DES ECB con padding manual!"

    ct = encrypt_des_ecb(msg, key)
    pt = decrypt_des_ecb(ct, key)

    print("Key (hex):", key.hex())
    print("CT  (hex):", ct.hex())
    print("PT:", pt)
    print("OK:", pt == msg)