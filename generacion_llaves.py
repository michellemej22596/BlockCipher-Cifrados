"""
Generador de claves criptográficamente seguras.
"""
from __future__ import annotations

import secrets
import random


def generate_des_key() -> bytes:
    """
    Genera una clave DES aleatoria de 8 bytes (64 bits).

    Nota: DES usa efectivamente 56 bits (los otros 8 son de paridad),
    pero la clave se representa como 8 bytes.
    """
    return secrets.token_bytes(8)


def generate_3des_key(key_option: int = 2) -> bytes:
    """
    Genera una clave 3DES aleatoria.

    key_option:
        2 -> 16 bytes (2-key 3DES)
        3 -> 24 bytes (3-key 3DES)

    Si key_option no es 2 o 3, se elige aleatoriamente entre 2 y 3
    (uso de `random` solo para decisión no-criptográfica).
    """
    if key_option not in (2, 3):
        key_option = random.choice([2, 3])

    key_len = 16 if key_option == 2 else 24
    return secrets.token_bytes(key_len)


def generate_aes_key(key_size: int = 256) -> bytes:
    """
    Genera una clave AES aleatoria.

    key_size (bits):
        128, 192, 256
    """
    if key_size not in (128, 192, 256):
        raise ValueError("key_size debe ser 128, 192 o 256 bits")

    return secrets.token_bytes(key_size // 8)


def generate_iv(block_size: int = 8) -> bytes:
    """
    Genera un vector de inicialización (IV) aleatorio.

    block_size se expresa en bytes (por ejemplo: DES=8, AES=16).
    """
    if not isinstance(block_size, int):
        raise TypeError("block_size debe ser int")
    if block_size <= 0:
        raise ValueError("block_size debe ser > 0")

    return secrets.token_bytes(block_size)