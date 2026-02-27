
"""
Módulo de padding PKCS#7 para cifrados de bloque.
Implementación manual sin usar bibliotecas externas.
"""
def pkcs7_pad(data: bytes, block_size: int = 8):
    """
    Implementa padding PKCS#7 según RFC 5652.
    Regla: Si faltan N bytes para completar el bloque,
    agregar N bytes, cada uno con el valor N (recuerden seguir la regla de pkcs#7).
    Importante: Si el mensaje es múltiplo exacto del tamaño
    de bloque, se agrega un bloque completo de padding.
    Examples:
    >>> pkcs7_pad(b"HOLA", 8).hex()
    '484f4c4104040404' # HOLA + 4 bytes con valor 0x04
    >>> pkcs7_pad(b"12345678", 8).hex() # Exactamente 8 bytes
    '31323334353637380808080808080808' # + bloque completo
    """
    padding_length = block_size - (len(data) % block_size)

    if padding_length == 0:
        padding_length = block_size

    padding = bytes([padding_length]) * padding_length
    return data + padding

    return True
def pkcs7_unpad(data: bytes) -> bytes:
    """
    Elimina padding PKCS#7 de los datos.
    Examples:
    >>> padded = pkcs7_pad(b"HOLA", 8)
    >>> pkcs7_unpad(padded)
    b'HOLA'
    """
    if len(data) == 0:
        raise ValueError("Input vacío")

    padding_length = data[-1]

    # Validar rango
    if padding_length == 0 or padding_length > len(data):
        raise ValueError("Padding inválido")

    # Verificar que todos los bytes finales sean correctos
    if data[-padding_length:] != bytes([padding_length]) * padding_length:
        raise ValueError("Padding inválido")

    return data[:-padding_length]


"""
Generador de claves criptográficamente seguras.
"""
import secrets
def generate_des_key():
    """
    Genera una clave DES aleatoria de 8 bytes (64 bits).
    Nota: DES usa efectivamente 56 bits (los otros 8 son de paridad),
    pero la clave es de 8 bytes.
    """
    return secrets.token_bytes(8)
def generate_3des_key(key_option: int = 2):
    """
    Genera una clave 3DES aleatoria.
    """
    if key_option == 2:
        return secrets.token_bytes(16)
    elif key_option == 3:
        return secrets.token_bytes(24)
    else:
        raise ValueError("key_option debe ser 2 o 3")

def generate_aes_key(key_size: int = 256):
    """
    Genera una clave AES aleatoria.
    """
    # TODO: Implementar
    # Convertir bits a bytes: key_size // 8
    if key_size not in (128, 192, 256):
        raise ValueError("AES solo permite 128, 192 o 256 bits")
    
    return secrets.token_bytes(key_size // 8)
def generate_iv(block_size: int = 8) -> bytes:
    """
    Genera un vector de inicialización (IV) aleatorio.
    """
    # TODO: Implementar
    return secrets.token_bytes(block_size)
