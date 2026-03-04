"""
test_ciphers.py

Pruebas básicas para validar la implementación de:
- DES ECB
- 3DES CBC
- AES ECB
- AES CBC
- Padding PKCS#7

Estas pruebas verifican que:
decrypt(encrypt(data)) == data
"""

from utils import (
    generate_des_key,
    generate_3des_key,
    generate_aes_key,
    pkcs7_pad,
    pkcs7_unpad,
)

from des_cipher import encrypt_des_ecb, decrypt_des_ecb
from tripledes_cipher import encrypt_3des_cbc, decrypt_3des_cbc
from aes_cipher import encrypt_aes_ecb, decrypt_aes_ecb, encrypt_aes_cbc, decrypt_aes_cbc


def test_des_ecb():
    print("Testing DES ECB")

    key = generate_des_key()
    message = b"Mensaje de prueba para DES"

    ct = encrypt_des_ecb(message, key)
    pt = decrypt_des_ecb(ct, key)

    assert pt == message
    print("DES ECB OK")


def test_3des_cbc():
    print("Testing 3DES CBC")

    key = generate_3des_key(3)
    message = b"Mensaje de prueba para 3DES CBC"

    ct = encrypt_3des_cbc(message, key)
    pt = decrypt_3des_cbc(ct, key)

    assert pt == message
    print("3DES CBC OK")


def test_aes_ecb():
    print("Testing AES ECB")

    key = generate_aes_key(256)
    message = b"Mensaje de prueba para AES ECB"

    ct = encrypt_aes_ecb(message, key)
    pt = decrypt_aes_ecb(ct, key)

    assert pt == message
    print("AES ECB OK")


def test_aes_cbc():
    print("Testing AES CBC")

    key = generate_aes_key(256)
    message = b"Mensaje de prueba para AES CBC"

    ct = encrypt_aes_cbc(message, key)
    pt = decrypt_aes_cbc(ct, key)

    assert pt == message
    print("AES CBC OK")


def test_padding():
    print("Testing PKCS7 Padding")

    msg1 = b"HELLO"
    msg2 = b"12345678"
    msg3 = b"HELLOWORLD"

    p1 = pkcs7_pad(msg1, 8)
    p2 = pkcs7_pad(msg2, 8)
    p3 = pkcs7_pad(msg3, 8)

    assert pkcs7_unpad(p1, 8) == msg1
    assert pkcs7_unpad(p2, 8) == msg2
    assert pkcs7_unpad(p3, 8) == msg3

    print("Padding OK")


if __name__ == "__main__":

    print("Running cipher tests\n")

    test_des_ecb()
    test_3des_cbc()
    test_aes_ecb()
    test_aes_cbc()
    test_padding()

    print("\nAll tests passed successfully")