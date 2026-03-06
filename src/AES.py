from Crypto.Cipher import AES
from utils import *
import os

def aes_cipher_ebc(message: bytes, key: bytes) -> bytes:
    """
    Cifra un mensaje usando AES en modo ECB
    Args:
        message (bytes): El mensaje que queremos cifrar en bytes
        key (str): la llave que vamos a uar para cifrar en bytes
    Returns:
        Retorna el mensaje cifrado
    """
    message = pkcs7_pad(message, 16) 
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(message)
    

def aes_decipher_ebc(message: bytes, key: bytes) -> bytes:
    """
    Decifra un mensaje usando EES en modo ECB
    Args:
        message (bytes): El mensaje que queremos decifrar en bytes
        key (str): la llave que vamos a uar para decifrar en bytes
    Returns:
        Retorna el mensaje decifrado
    """
    cipher = AES.new(key, AES.MODE_ECB)
    decrypted = cipher.decrypt(message)
    return pkcs7_unpad(decrypted)

def aes_cipher_cbc(message: bytes, key: bytes, iv: bytes ) -> bytes:
    """
    Cifra un mensaje usando DES en modo CCB
    Args:
        message (bytes): El mensaje que queremos cifrar en bytes
        key (bytes): la llave que vamos a uar para cifrar en bytes
        iv: el vector inicial que vamos a usar para cifrar
    Returns:
        Retorna el mensaje cifrado
    """
    message = pkcs7_pad(message, 16) 
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.encrypt(message)

def aes_decipher_cbc(message: bytes, key: bytes, iv: bytes) -> bytes:
    """
    Cifra un mensaje usando DES en modo CCB
    Args:
        message (bytes): El mensaje que queremos cifrar en bytes
        key (str): la llave que vamos a uar para cifrar en bytes
        iv: el vector inicial que vamos a usar para cifrar
    Returns:
        Retorna el mensaje cifrado
    """
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted = cipher.decrypt(message)
    return pkcs7_unpad(decrypted)
    
if __name__ == '__main__':

    image_path = input("Ingrese la ruta de la imagen PNG: ").strip()

    if not os.path.exists(image_path):
        print("La ruta no existe.")
        exit(1)

    base_name = os.path.splitext(os.path.basename(image_path))[0]

    temp_ppm = "temp.ppm"

    print("Convirtiendo PNG a PPM...")
    png_to_ppm(image_path, temp_ppm)

    header, body = split_ppm(temp_ppm)
    original_size = len(body)  

    print(f"Body size: {original_size} bytes")

    key = generate_aes_key()
    iv = generate_iv(16)

    encrypted_ecb = aes_cipher_ebc(body, key)
    build_ppm(header, encrypted_ecb[:original_size], "ecb_encrypted.ppm") 
    ppm_to_png("ecb_encrypted.ppm", f"{base_name}_ecb.png")

    decrypted_ecb = aes_decipher_ebc(encrypted_ecb, key)
    build_ppm(header, decrypted_ecb[:original_size], "ecb_decrypted.ppm") 
    ppm_to_png("ecb_decrypted.ppm", f"{base_name}_ecb_decrypted.png")

    print("ECB procesado.")

    encrypted_cbc = aes_cipher_cbc(body, key, iv)
    build_ppm(header, encrypted_cbc[:original_size], "cbc_encrypted.ppm") 
    ppm_to_png("cbc_encrypted.ppm", f"{base_name}_cbc.png")

    decrypted_cbc = aes_decipher_cbc(encrypted_cbc, key, iv)
    build_ppm(header, decrypted_cbc[:original_size], "cbc_decrypted.ppm")  
    ppm_to_png("cbc_decrypted.ppm", f"{base_name}_cbc_decrypted.png")

    print("CBC procesado.")

    os.remove(temp_ppm)

    print("\nProceso terminado correctamente.")
    print("Archivos generados:")
    print(f"- {base_name}_ecb.png")
    print(f"- {base_name}_cbc.png")
    print(f"- {base_name}_ecb_decrypted.png")
    print(f"- {base_name}_cbc_decrypted.png")