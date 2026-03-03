"""
tripledes_cipher.py - Implementación 3DES en modo CBC (Laboratorio 1.2)

Requisitos cubiertos:
- Claves 3DES seguras (16 o 24 bytes)
- IV aleatorio por cada cifrado (8 bytes)
- Padding usando Crypto.Util.Padding (NO manual)
- IV concatenado al inicio del ciphertext (IV + CT)
"""

from __future__ import annotations

from Crypto.Cipher import DES3
from Crypto.Util.Padding import pad, unpad

from utils import generate_3des_key, generate_iv

BLOCK_SIZE_3DES = 8  # bytes


def _validate_3des_key(key: bytes) -> bytes:
    """
    Ajusta paridad y valida que no sea una clave débil.
    (PyCryptodome puede rechazar claves inválidas o débiles.)
    """
    if not isinstance(key, (bytes, bytearray)):
        raise TypeError("key debe ser bytes o bytearray")

    key_bytes = bytes(key)
    if len(key_bytes) not in (16, 24):
        raise ValueError("La clave 3DES debe ser de 16 o 24 bytes")

    # Ajusta bits de paridad; puede lanzar ValueError si es débil/incorrecta
    return DES3.adjust_key_parity(key_bytes)


def encrypt_3des_cbc(plaintext: bytes, key: bytes) -> bytes:
    """
    Cifra usando 3DES-CBC.
    Retorna: IV + ciphertext
    """
    if not isinstance(plaintext, (bytes, bytearray)):
        raise TypeError("plaintext debe ser bytes o bytearray")

    key_ok = _validate_3des_key(key)
    iv = generate_iv(BLOCK_SIZE_3DES)

    cipher = DES3.new(key_ok, DES3.MODE_CBC, iv=iv)
    padded = pad(bytes(plaintext), BLOCK_SIZE_3DES)
    ct = cipher.encrypt(padded)

    return iv + ct


def decrypt_3des_cbc(ciphertext: bytes, key: bytes) -> bytes:
    """
    Descifra usando 3DES-CBC.
    Espera input en formato: IV + ciphertext
    """
    if not isinstance(ciphertext, (bytes, bytearray)):
        raise TypeError("ciphertext debe ser bytes o bytearray")

    ct_bytes = bytes(ciphertext)
    if len(ct_bytes) < BLOCK_SIZE_3DES:
        raise ValueError("Ciphertext inválido: no contiene IV completo")
    if (len(ct_bytes) - BLOCK_SIZE_3DES) % BLOCK_SIZE_3DES != 0:
        raise ValueError("Ciphertext inválido: longitud (sin IV) no es múltiplo del bloque")

    key_ok = _validate_3des_key(key)
    iv = ct_bytes[:BLOCK_SIZE_3DES]
    actual_ct = ct_bytes[BLOCK_SIZE_3DES:]

    cipher = DES3.new(key_ok, DES3.MODE_CBC, iv=iv)
    padded_pt = cipher.decrypt(actual_ct)

    return unpad(padded_pt, BLOCK_SIZE_3DES)


if __name__ == "__main__":
    # Demo rápida
    key_2k = generate_3des_key(2)  # 16 bytes (2-key)
    key_3k = generate_3des_key(3)  # 24 bytes (3-key)

    msg = b"Hola, 3DES CBC! Probando IV + padding..."

    ct1 = encrypt_3des_cbc(msg, key_3k)
    pt1 = decrypt_3des_cbc(ct1, key_3k)

    # Probar que IV cambia cada vez
    ct2 = encrypt_3des_cbc(msg, key_3k)

    print("Key 2-key len:", len(key_2k), "bytes")
    print("Key 3-key len:", len(key_3k), "bytes")
    print("CT1 (hex):", ct1.hex())
    print("PT1:", pt1)
    print("OK:", pt1 == msg)
    print("IV diferente cada vez?:", ct1[:8] != ct2[:8])