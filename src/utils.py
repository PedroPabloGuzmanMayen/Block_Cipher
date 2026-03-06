from PIL import Image
import secrets
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
    padding_length = len(data) % block_size
    if padding_length == 0:
        padding_length = block_size
    else:
        padding_length = block_size - padding_length

    padding = bytes([padding_length]) * padding_length
    return data + padding

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
    if key_size not in (128, 192, 256):
        raise ValueError("AES solo permite 128, 192 o 256 bits")
    
    return secrets.token_bytes(key_size // 8)

def generate_iv(block_size: int = 8) -> bytes:
    """
    Genera un vector de inicialización (IV) aleatorio.
    """
    # TODO: Implementar
    return secrets.token_bytes(block_size)

def png_to_ppm(png_path: str, ppm_path: str):
    """
    Convierte imagen png a ppm
    """
    img = Image.open(png_path)
    img = img.convert("RGB")
    img.save(ppm_path, format="PPM")

def ppm_to_png(ppm_path: str, png_path: str):
    """
    Convierte imagen ppm a png
    """
    img = Image.open(ppm_path)
    img.save(png_path, format="PNG")

def split_ppm(ppm_path: str):
    """
    Separa header y body ppm
    """
    with open(ppm_path, "rb") as f:
        lines = f.readlines()

    header = lines[:3]
    body = b"".join(lines[3:])

    return header, body

def build_ppm(header: bytes, body: bytes, output_path: str):
    """
    Guarda y construye imágenes ppgm
    """
    with open(output_path, "wb") as f:
        f.writelines(header)
        f.write(body)

if __name__ == '__main__':

    def analizar_padding(mensaje: bytes, block_size: int = 8):
        padded = pkcs7_pad(mensaje, block_size)
        padding_length = padded[-1]
        padding_bytes = padded[len(mensaje):]
        recovered = pkcs7_unpad(padded)

        print(f"  Mensaje original : {mensaje} ({len(mensaje)} bytes)")
        print(f"  Hex original     : {mensaje.hex()}")
        print(f"  Bytes faltantes  : {block_size} - ({len(mensaje)} % {block_size}) = {padding_length}")
        print(f"  Padding agregado : {padding_length} × 0x{padding_length:02x} → {padding_bytes.hex()}")
        print(f"  Resultado padded : {padded.hex()}")
        print(f"  Desglose         : [{mensaje.hex()}] + [{padding_bytes.hex()}]")
        print(f"  pkcs7_unpad      : {recovered} ✅ == original: {recovered == mensaje}")
        print()

    print("=" * 60)
    print("DEMOSTRACIÓN PKCS#7 — block_size = 8")
    print("=" * 60)

    print("\n Caso 1: Mensaje de 5 bytes → b'HOLA!'")
    analizar_padding(b"HOLA!")

    print(" Caso 2: Mensaje de 8 bytes → b'12345678'")
    analizar_padding(b"12345678")

    print(" Caso 3: Mensaje de 10 bytes → b'CRIPTOGRAF'")
    analizar_padding(b"CRIPTOGRAF")