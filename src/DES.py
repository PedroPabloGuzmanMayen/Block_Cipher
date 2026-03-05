from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad
from utils import *

def des_cipher(message: bytes, key: bytes) -> bytes:
    """
    Cifra un mensaje usando DES en modo ECB
    Args:
        message (bytes): El mensaje que queremos cifrar en bytes
        key (str): la llave que vamos a uar para cifrar en bytes
    Returns:
        Retorna el mensaje cifrado

    """
    message = pkcs7_pad(message, 8)
    cipher = DES.new(key, DES.MODE_ECB)
    return cipher.encrypt(message)

def des_decipher(message: bytes, key: bytes) -> bytes:
    """
    Decifra un mensaje usando DES en modo ECB
    Args:
        message (bytes): El mensaje que queremos decifrar en bytes
        key (str): la llave que vamos a uar para decifrar en bytes
    Returns:
        Retorna el mensaje decifrado
    """
    cipher = DES.new(key, DES.MODE_ECB)
    decrypted = cipher.decrypt(message)
    return pkcs7_unpad(decrypted)

from Crypto.Cipher import DES
from utils import *

if __name__ == '__main__':

    print('=== DES ECB ===')

    while True:
        print('\nOpciones:')
        print('1 - Cifrar')
        print('2 - Descifrar')
        print('Ctrl+C para salir')

        opcion = input('Seleccione una opción: ')

        if opcion == '1':
            mensaje = input('Ingrese mensaje: ').encode('utf-8')

            key = generate_des_key()
            print(f'Clave generada (hex): {key.hex()}')

            ciphertext = des_cipher(mensaje, key)
            print(f'Ciphertext (hex): {ciphertext.hex()}')

        elif opcion == '2':
            try:
                key_hex = input('Ingrese la clave en hex: ')
                key = bytes.fromhex(key_hex)

                ciphertext_hex = input('Ingrese el ciphertext en hex: ')
                ciphertext = bytes.fromhex(ciphertext_hex)

                plaintext = des_decipher(ciphertext, key)
                print(f'Mensaje descifrado: {plaintext.decode("utf-8")}')

            except Exception as e:
                print(f'Error: {e}')

        else:
            print('Opción inválida')