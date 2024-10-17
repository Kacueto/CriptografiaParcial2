from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

# Generar claves RSA
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)

# Serializar y guardar clave privada
with open("server_private_key.pem", "wb") as f:
    f.write(private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ))

# Serializar y guardar clave pública
public_key = private_key.public_key()
with open("server_public_key.pem", "wb") as f:
    f.write(public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ))

print("Claves del servidor generadas y guardadas.")