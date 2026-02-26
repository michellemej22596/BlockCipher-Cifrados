from Crypto.Cipher import DES3
from Crypto.Util.Padding import pad, unpad
import secrets

BLOCK_SIZE = 8  # Tamaño de bloque para 3DES


# -------------------------------------------------
# Generación segura de clave 3DES
# -------------------------------------------------
def generate_3des_key(key_size: int = 24) -> bytes:
    """
    Genera una clave 3DES segura.
    
    key_size:
        16 -> 2-key 3DES
        24 -> 3-key 3DES
    """
    if key_size not in (16, 24):
        raise ValueError("La clave debe ser de 16 o 24 bytes.")

    while True:
        key = secrets.token_bytes(key_size)
        try:
            return DES3.adjust_key_parity(key)
        except ValueError:
            # Si la clave es inválida o débil, generar otra
            continue


# -------------------------------------------------
# Cifrado 3DES CBC
# -------------------------------------------------
def encrypt_3des_cbc(plaintext: bytes, key: bytes) -> bytes:
    """
    Cifra datos usando 3DES en modo CBC.
    
    - Genera IV aleatorio automáticamente.
    - Retorna: IV + ciphertext
    """

    if len(key) not in (16, 24):
        raise ValueError("La clave 3DES debe ser de 16 o 24 bytes.")

    # Generar IV aleatorio por cada operación
    iv = secrets.token_bytes(BLOCK_SIZE)

    cipher = DES3.new(key, DES3.MODE_CBC, iv=iv)

    padded_data = pad(plaintext, BLOCK_SIZE)
    ciphertext = cipher.encrypt(padded_data)

    # Retornamos IV concatenado con el ciphertext
    return iv + ciphertext


# -------------------------------------------------
# Descifrado 3DES CBC
# -------------------------------------------------
def decrypt_3des_cbc(ciphertext: bytes, key: bytes) -> bytes:
    """
    Descifra datos usando 3DES en modo CBC.
    
    - Extrae el IV automáticamente.
    """

    if len(key) not in (16, 24):
        raise ValueError("La clave 3DES debe ser de 16 o 24 bytes.")

    if len(ciphertext) < BLOCK_SIZE:
        raise ValueError("Ciphertext inválido.")

    # Extraer IV (primeros 8 bytes)
    iv = ciphertext[:BLOCK_SIZE]
    actual_ciphertext = ciphertext[BLOCK_SIZE:]

    cipher = DES3.new(key, DES3.MODE_CBC, iv=iv)

    padded_data = cipher.decrypt(actual_ciphertext)
    plaintext = unpad(padded_data, BLOCK_SIZE)

    return plaintext


# -------------------------------------------------
# Ejemplo de uso (dummy)
# -------------------------------------------------
if __name__ == "__main__":
    key = generate_3des_key(24)

    mensaje = b"DATOS_DE_PRUEBA_LAB_3DES"

    print("Clave generada:", key)

    ciphertext = encrypt_3des_cbc(mensaje, key)
    print("Ciphertext:", ciphertext)

    decrypted = decrypt_3des_cbc(ciphertext, key)
    print("Descifrado:", decrypted)
