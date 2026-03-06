
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

if __name__ == '__main__':

    print('=== 3DES CBC ===')

    while True:
        print('\nOpciones:')
        print('1 - Cifrar')
        print('2 - Descifrar')
        print('Ctrl+C para salir')

        opcion = input('Seleccione una opción: ')

        if opcion == '1':
            mensaje = input('Ingrese mensaje: ').encode('utf-8')

            key = generate_3des_key(2)
            iv = generate_iv(8)
            print(f'Clave generada (hex): {key.hex()}')
            print(f'IV generado (hex): {iv.hex()}')

            ciphertext = encrypt_3des_cbc(mensaje, key, iv)
            print(f'Ciphertext (hex): {ciphertext.hex()}')

        elif opcion == '2':
            try:
                key_hex = input('Ingrese la clave en hex: ')
                key = bytes.fromhex(key_hex)

                iv_hex = input('Ingrese el IV en hex: ')
                iv = bytes.fromhex(iv_hex)

                ciphertext_hex = input('Ingrese el ciphertext en hex: ')
                ciphertext = bytes.fromhex(ciphertext_hex)

                plaintext = decrypt_3des_cbc(ciphertext, key, iv)
                print(f'Mensaje descifrado: {plaintext.decode("utf-8")}')

            except Exception as e:
                print(f'Error: {e}')

        else:
            print('Opción inválida')