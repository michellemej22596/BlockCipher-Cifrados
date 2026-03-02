"""
utils.py - Funciones auxiliares para el laboratorio de Block Ciphers.

Incluye:
- Generación segura de claves (DES, 3DES, AES)
- Generación de IV
- Padding PKCS#7 manual (para DES-ECB en 1.1)
"""

from __future__ import annotations

import secrets
import random


# =========================
# PKCS#7 Padding (manual)
# =========================
def pkcs7_pad(data: bytes, block_size: int) -> bytes:
    """
    Implementa padding PKCS#7 manual.

    Regla:
    - Si faltan N bytes para completar el bloque, agregar N bytes con valor N.
    - Si data ya es múltiplo exacto del bloque, se agrega un bloque completo.

    block_size en bytes (DES=8, AES=16).
    """
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("data debe ser bytes o bytearray")
    if not isinstance(block_size, int):
        raise TypeError("block_size debe ser int")
    if block_size <= 0 or block_size > 255:
        # PKCS#7 usa 1 byte para N, así que N ∈ [1, 255]
        raise ValueError("block_size debe estar entre 1 y 255")

    data_bytes = bytes(data)
    pad_len = block_size - (len(data_bytes) % block_size)
    if pad_len == 0:
        pad_len = block_size  # bloque completo si ya era múltiplo exacto

    return data_bytes + bytes([pad_len]) * pad_len


def pkcs7_unpad(data: bytes, block_size: int) -> bytes:
    """
    Elimina padding PKCS#7 y valida que sea correcto.

    Valida:
    - longitud múltiplo del block_size
    - último byte indica pad_len válido
    - los últimos pad_len bytes son todos iguales a pad_len
    """
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("data debe ser bytes o bytearray")
    if not isinstance(block_size, int):
        raise TypeError("block_size debe ser int")
    if block_size <= 0 or block_size > 255:
        raise ValueError("block_size debe estar entre 1 y 255")

    data_bytes = bytes(data)
    if len(data_bytes) == 0:
        raise ValueError("No se puede unpad un mensaje vacío")
    if len(data_bytes) % block_size != 0:
        raise ValueError("Padding inválido: longitud no es múltiplo del block_size")

    pad_len = data_bytes[-1]
    if pad_len < 1 or pad_len > block_size:
        raise ValueError("Padding inválido: pad_len fuera de rango")

    if data_bytes[-pad_len:] != bytes([pad_len]) * pad_len:
        raise ValueError("Padding inválido: bytes de padding incorrectos")

    return data_bytes[:-pad_len]


# =========================
# Key & IV generation
# =========================
def generate_des_key() -> bytes:
    """
    Genera una clave DES de 8 bytes (64 bits).
    Nota: DES usa efectivamente 56 bits (los otros son de paridad).
    """
    return secrets.token_bytes(8)


def generate_3des_key(key_option: int = 3) -> bytes:
    """
    Genera una clave 3DES:
      - key_option=2 -> 16 bytes (2-key 3DES)
      - key_option=3 -> 24 bytes (3-key 3DES)

    Si key_option no es 2 o 3, se elige aleatoriamente entre 2 y 3
    (random solo para elección, NO para generar la clave).
    """
    if key_option not in (2, 3):
        key_option = random.choice([2, 3])

    key_len = 16 if key_option == 2 else 24
    return secrets.token_bytes(key_len)


def generate_aes_key(key_size_bits: int = 256) -> bytes:
    """
    Genera una clave AES aleatoria.

    key_size_bits:
      - 128, 192, 256
    """
    if key_size_bits not in (128, 192, 256):
        raise ValueError("key_size_bits debe ser 128, 192 o 256")

    return secrets.token_bytes(key_size_bits // 8)


def generate_iv(block_size: int) -> bytes:
    """
    Genera un IV aleatorio (nonce) del tamaño del bloque (en bytes).
    Ej:
      - DES/3DES: 8
      - AES: 16
    """
    if not isinstance(block_size, int):
        raise TypeError("block_size debe ser int")
    if block_size <= 0:
        raise ValueError("block_size debe ser > 0")

    return secrets.token_bytes(block_size)