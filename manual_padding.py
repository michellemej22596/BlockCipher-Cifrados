"""
Módulo de padding PKCS#7 para cifrados de bloque.
Implementación manual sin usar bibliotecas externas.
"""

from __future__ import annotations


def pkcs7_pad(data: bytes, block_size: int = 8) -> bytes:
    """
    Implementa padding PKCS#7.

    Regla: Si faltan N bytes para completar el bloque,
    agregar N bytes, cada uno con el valor N.

    Importante: Si el mensaje es múltiplo exacto del tamaño
    de bloque, se agrega un bloque completo de padding.

    Examples:
        >>> pkcs7_pad(b"HOLA", 8).hex()
        '484f4c4104040404'

        >>> pkcs7_pad(b"12345678", 8).hex()
        '31323334353637380808080808080808'
    """
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("data debe ser bytes o bytearray")
    if not isinstance(block_size, int):
        raise TypeError("block_size debe ser int")
    if block_size <= 0 or block_size > 255:
        # PKCS#7 usa un byte para representar N, así que N ∈ [1, 255]
        raise ValueError("block_size debe estar entre 1 y 255")

    data_bytes = bytes(data)
    pad_len = block_size - (len(data_bytes) % block_size)
    if pad_len == 0:
        pad_len = block_size

    padding = bytes([pad_len]) * pad_len
    return data_bytes + padding


def pkcs7_unpad(data: bytes, block_size: int = 8) -> bytes:
    """
    Elimina padding PKCS#7 de los datos.

    Valida que:
    - data tenga longitud múltiplo de block_size
    - el último byte indique un pad_len válido
    - los últimos pad_len bytes sean todos iguales a pad_len
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