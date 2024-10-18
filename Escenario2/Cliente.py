import socket
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os

def generate_keys():
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()
    return private_key, public_key

def serialize_key(key):
    return key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

def deserialize_key(pem_key):
    return serialization.load_pem_public_key(pem_key)

def derive_shared_key(private_key, peer_public_key):
    shared_key = private_key.exchange(ec.ECDH(), peer_public_key)
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'handshake data'
    ).derive(shared_key)
    return derived_key

def encrypt_message(key, message):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padded_message = message + b' ' * (16 - len(message) % 16)  # Padding
    encrypted_message = encryptor.update(padded_message) + encryptor.finalize()
    return iv + encrypted_message

def decrypt_message(key, encrypted_message):
    iv = encrypted_message[:16]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_message = decryptor.update(encrypted_message[16:]) + decryptor.finalize()
    return decrypted_message.rstrip(b' ')  # Remove padding

def client_communication():
    private_key, public_key = generate_keys()
    serialized_public_key = serialize_key(public_key)

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(('192.168.1.240', 65431))  # Ajusta el host y puerto según sea necesario

    # Send client's public key
    client_socket.sendall(serialized_public_key)

    # Receive server's public key
    server_public_key_pem = client_socket.recv(1024)
    server_public_key = deserialize_key(server_public_key_pem)

    # Derive shared key
    shared_key = derive_shared_key(private_key, server_public_key)
    print("Shared key:", shared_key)

    # Communication loop
    while True:
        message = input("Enter message to send: ").encode()
        encrypted_message = encrypt_message(shared_key, message)
        client_socket.sendall(encrypted_message)

        encrypted_response = client_socket.recv(4096)
        response = decrypt_message(shared_key, encrypted_response)
        print("Server response:", response.decode())

    client_socket.close()

if __name__ == "__main__":
    client_communication()
