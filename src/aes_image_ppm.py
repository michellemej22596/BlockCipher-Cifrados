from Crypto.Cipher import AES
from utils import generate_aes_key, generate_iv

AES_BLOCK = 16

def _encrypt_full_blocks_ecb(data: bytes, key: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_ECB)
    n = (len(data) // AES_BLOCK) * AES_BLOCK
    return cipher.encrypt(data[:n]) + data[n:]  # deja sobrante intacto

def _encrypt_full_blocks_cbc(data: bytes, key: bytes, iv: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    n = (len(data) // AES_BLOCK) * AES_BLOCK
    return cipher.encrypt(data[:n]) + data[n:]  # deja sobrante intacto

def build_ppm(out_path: str, header: bytes, body: bytes) -> None:
    with open(out_path, "wb") as f:
        f.write(header + body)

if __name__ == "__main__":
    header_path = "header.ppm"
    body_path = "body.ppm"

    with open(header_path, "rb") as f:
        header = f.read()
    with open(body_path, "rb") as f:
        body = f.read()

    key = generate_aes_key(256)

    # ECB
    body_ecb = _encrypt_full_blocks_ecb(body, key)
    build_ppm("aes_ecb.ppm", header, body_ecb)

    # CBC
    iv = generate_iv(AES_BLOCK)
    body_cbc = _encrypt_full_blocks_cbc(body, key, iv)
    build_ppm("aes_cbc.ppm", header, body_cbc)

    # guardar IV aparte (no lo metas dentro del body, porque cambia tamaño)
    with open("aes_cbc.iv", "wb") as f:
        f.write(iv)

    print("AES-256 key length:", len(key), "bytes")
    print("Generado: aes_ecb.ppm")
    print("Generado: aes_cbc.ppm")
    print("Guardado IV CBC en: aes_cbc.iv")
    print("Nota: Se cifraron solo bloques completos (sin padding) para mantener el tamaño del PPM.")