
from Crypto.Cipher import DES3
from Crypto.Util.Padding import pad, unpad
from utils import *

BLOCK_SIZE = 8 

def encrypt_3des_cbc(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
    """
    Example:
    >>> key = generate_3des_key(2)
    >>> iv = generate_iv(8)
    >>> plaintext = b"Mensaje secreto para 3DES"
    >>> ciphertext = encrypt_3des_cbc(plaintext, key, iv)
    >>> len(ciphertext) % 8
    0 # Debe ser múltiplo de 8 (tamaño de bloque de DES)
    """
    if len(key) not in (16, 24):
        raise ValueError("La clave 3DES debe ser de 16 o 24 bytes")
    if len(iv) != BLOCK_SIZE:
        raise ValueError("El IV debe ser de 8 bytes")
    key = DES3.adjust_key_parity(key)
    cipher = DES3.new(key, DES3.MODE_CBC, iv=iv)
    padded = pkcs7_pad(plaintext, BLOCK_SIZE)
    return cipher.encrypt(padded)
  
def decrypt_3des_cbc(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    """
    Example:
    >>> key = generate_3des_key(2)
    >>> iv = generate_iv(8)
    >>> plaintext = b"Mensaje secreto"
    >>> ciphertext = encrypt_3des_cbc(plaintext, key, iv)
    >>> decrypted = decrypt_3des_cbc(ciphertext, key, iv)
    >>> decrypted == plaintext
    True
    """
    # TODO: Implementar
    # 1. Validar longitud de clave y IV
    # 2. Crear cipher: DES3.new(key, DES3.MODE_CBC, iv=iv)
    # 3. Descifrar
    # 4. Eliminar padding usando unpad() de Crypto.Util.Padding
    # 5. Retornar

    if len(key) not in (16, 24):
        raise ValueError("La clave 3DES debe ser de 16 o 24 bytes")
    if len(iv) != BLOCK_SIZE:
        raise ValueError("El IV debe ser de 8 bytes")
    key = DES3.adjust_key_parity(key)
    cipher = DES3.new(key, DES3.MODE_CBC, iv=iv)
    padded_plaintext = cipher.decrypt(ciphertext)

    return pkcs7_unpad(padded_plaintext)


key = generate_3des_key(2)
iv = generate_iv(8)

mensaje = b"Mensaje secreto para 3DES"

ciphertext = encrypt_3des_cbc(mensaje, key, iv)
plaintext = decrypt_3des_cbc(ciphertext, key, iv)

print("Original:", mensaje)
print("Cifrado:", ciphertext.hex())
print("Descifrado:", plaintext)