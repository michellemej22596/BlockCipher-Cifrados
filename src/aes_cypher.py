"""
aes_cipher.py - AES ECB/CBC + cifrado de imágenes (BMP) para comparación visual (Laboratorio 1.3)

Requisitos cubiertos:
- AES-256 (32 bytes)
- Modo ECB y CBC
- IV aleatorio para CBC
- Padding con Crypto.Util.Padding (NO manual)
- Mantener header BMP intacto (solo cifrar datos de pixeles)
- Guardar imagen cifrada para comparación visual
"""

from __future__ import annotations

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

from utils import generate_aes_key, generate_iv

AES_BLOCK_SIZE = 16  # bytes


# =========================
# AES para bytes (texto/archivos)
# =========================
def encrypt_aes_ecb(data: bytes, key: bytes) -> bytes:
    if len(key) != 32:
        raise ValueError("AES-256 requiere key de 32 bytes")
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(pad(data, AES_BLOCK_SIZE))


def decrypt_aes_ecb(ciphertext: bytes, key: bytes) -> bytes:
    if len(key) != 32:
        raise ValueError("AES-256 requiere key de 32 bytes")
    if len(ciphertext) == 0 or len(ciphertext) % AES_BLOCK_SIZE != 0:
        raise ValueError("Ciphertext inválido para AES (no múltiplo de 16)")
    cipher = AES.new(key, AES.MODE_ECB)
    return unpad(cipher.decrypt(ciphertext), AES_BLOCK_SIZE)


def encrypt_aes_cbc(data: bytes, key: bytes) -> bytes:
    """
    Retorna: IV + CT
    """
    if len(key) != 32:
        raise ValueError("AES-256 requiere key de 32 bytes")
    iv = generate_iv(AES_BLOCK_SIZE)
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    ct = cipher.encrypt(pad(data, AES_BLOCK_SIZE))
    return iv + ct


def decrypt_aes_cbc(iv_and_ct: bytes, key: bytes) -> bytes:
    if len(key) != 32:
        raise ValueError("AES-256 requiere key de 32 bytes")
    if len(iv_and_ct) < AES_BLOCK_SIZE:
        raise ValueError("Ciphertext inválido: falta IV")
    iv = iv_and_ct[:AES_BLOCK_SIZE]
    ct = iv_and_ct[AES_BLOCK_SIZE:]
    if len(ct) == 0 or len(ct) % AES_BLOCK_SIZE != 0:
        raise ValueError("Ciphertext inválido para AES-CBC")
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    return unpad(cipher.decrypt(ct), AES_BLOCK_SIZE)


# =========================
# AES para imágenes BMP
# =========================
def _read_bmp(path: str) -> tuple[bytes, bytes]:
    """
    Lee BMP y separa:
    - header (hasta pixel array offset)
    - pixel_data (datos de pixeles)

    Nota: BMP tiene en el byte 10-13 (little-endian) el offset donde empiezan los pixeles.
    """
    with open(path, "rb") as f:
        raw = f.read()

    if len(raw) < 54 or raw[:2] != b"BM":
        raise ValueError("El archivo no parece ser BMP válido (falta 'BM')")

    pixel_offset = int.from_bytes(raw[10:14], byteorder="little")
    if pixel_offset <= 0 or pixel_offset > len(raw):
        raise ValueError("BMP inválido: pixel offset fuera de rango")

    header = raw[:pixel_offset]
    pixel_data = raw[pixel_offset:]
    return header, pixel_data


def _write_bmp(path: str, header: bytes, pixel_data: bytes) -> None:
    with open(path, "wb") as f:
        f.write(header + pixel_data)


def encrypt_bmp_aes_ecb(in_path: str, out_path: str, key: bytes) -> None:
    """
    Cifra SOLO los pixeles de un BMP con AES-ECB, preservando el header.
    (ECB filtra patrones, se verá “la silueta”)
    """
    header, pixels = _read_bmp(in_path)

    ct_pixels = encrypt_aes_ecb(pixels, key)
    _write_bmp(out_path, header, ct_pixels)


def encrypt_bmp_aes_cbc(in_path: str, out_path: str, key: bytes) -> None:
    """
    Cifra SOLO los pixeles de un BMP con AES-CBC, preservando el header.
    Guarda IV dentro del pixel_data como prefijo: IV + pixeles_cifrados.
    Esto NO es “formato BMP estándar” perfecto, pero funciona para el lab porque:
    - lo importante es la comparación visual
    - CBC rompe patrones

    Si te preocupa el formato, puedo darte una variante que NO inserta el IV en los pixeles
    y lo guarda en un .iv aparte.
    """
    header, pixels = _read_bmp(in_path)

    iv = generate_iv(AES_BLOCK_SIZE)
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    ct_pixels = cipher.encrypt(pad(pixels, AES_BLOCK_SIZE))

    # Guardamos IV + CT en la zona de pixeles
    _write_bmp(out_path, header, iv + ct_pixels)


if __name__ == "__main__":
    # Demo: cifra una imagen BMP en ECB y CBC y guarda resultados.
    # Coloca tu imagen como: images/original.bmp
    key = generate_aes_key(256)

    in_img = "../images/original.bmp"
    out_ecb = "../images/aes_ecb.bmp"
    out_cbc = "../images/aes_cbc.bmp"

    encrypt_bmp_aes_ecb(in_img, out_ecb, key)
    encrypt_bmp_aes_cbc(in_img, out_cbc, key)

    print("AES key len:", len(key), "bytes (AES-256)")
    print("Generadas:")
    print("-", out_ecb)
    print("-", out_cbc)