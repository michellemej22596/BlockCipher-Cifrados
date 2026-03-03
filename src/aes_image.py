from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from utils import generate_aes_key, generate_iv

AES_BLOCK = 16

def encrypt_body_ecb(body: bytes, key: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(pad(body, AES_BLOCK))

def encrypt_body_cbc(body: bytes, key: bytes) -> bytes:
    iv = generate_iv(AES_BLOCK)
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    ct = cipher.encrypt(pad(body, AES_BLOCK))
    return iv + ct  # guardo IV pegado para que sea reproducible

def build_png(out_path: str, header: bytes, body: bytes) -> None:
    with open(out_path, "wb") as f:
        f.write(header + body)

if __name__ == "__main__":
    # input/output (ajusta según tus nombres)
    header_path = "../images/header.bin"
    body_path = "../images/body.bin"

    with open(header_path, "rb") as f:
        header = f.read()
    with open(body_path, "rb") as f:
        body = f.read()

    key = generate_aes_key(256)

    ecb_body = encrypt_body_ecb(body, key)
    cbc_body = encrypt_body_cbc(body, key)

    build_png("../images/pic_aes.png", header, ecb_body)
    build_png("../images/pic_des.png", header, cbc_body)

    print("Key len:", len(key), "bytes")
    print("Listo: pic_aes.png (ECB) y pic_des.png (CBC)")