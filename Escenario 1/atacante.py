import math
import time  # Importar el módulo time
import hashlib
from Crypto.Cipher import Salsa20

def baby_step_giant_step(g, y, p):
    m = math.ceil(math.sqrt(p - 1))  # m es la raíz cuadrada de p-1

    # Paso pequeño: calcular g^j mod p
    baby_steps = {pow(g, j, p): j for j in range(m)}

    # Paso grande: calcular g^(-m) mod p
    g_m_inverse = pow(g, p - 1 - m, p)

    # Paso grande: buscar coincidencias
    for i in range(m):
        # Calcular y * g^(-m * i) mod p
        giant_step = (y * pow(g_m_inverse, i, p)) % p
        if giant_step in baby_steps:
            # Encontrar el logaritmo discreto
            return i * m + baby_steps[giant_step]

    return None  # No se encontró el logaritmo discreto

# Ejemplo de uso
g = 4460925131279825939  # Base
y = 7650024083995982416  # Valor objetivo
p = 13926985804350796967  # Módulo

# Iniciar contador de tiempo
start_time = time.time()

result = baby_step_giant_step(g, y, p)

# Calcular el tiempo transcurrido
end_time = time.time()
elapsed_time = end_time - start_time


data = b'\xb9\x48\xf0\x98\x6b\xf7\xa7\xc8\x70\xf7\x98\x70'
if result is not None:
    print(f"El logaritmo discreto es: {result}")
    simetricKey = pow(7699722660401095229, result, p)
    key = hashlib.sha256(simetricKey.to_bytes(2, byteorder='big')).digest()

    nonceU = data[:8]
    cipherTextU = data[8:]
    decipher = Salsa20.new(key=key, nonce=nonceU)
    text = decipher.decrypt(cipherTextU).decode()
    print(f"Texto: {text}")
else:
    print("No se encontró el logaritmo discreto.")

print(f"Tiempo transcurrido: {elapsed_time:.6f} segundos")
