import socket
import threading
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization

# Cargar la clave privada del servidor
with open("server_private_key.pem", "rb") as f:
    server_private_key = serialization.load_pem_private_key(
        f.read(),
        password=None
    )

def rsa_encrypt(message, public_key):
    max_chunk_size = 190  # Tamaño máximo para cifrar con una clave RSA de 2048 bits y OAEP
    encrypted_chunks = []
    for i in range(0, len(message), max_chunk_size):
        chunk = message[i:i + max_chunk_size]
        encrypted_chunk = public_key.encrypt(
            chunk,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        encrypted_chunks.append(encrypted_chunk)
    return b''.join(encrypted_chunks)

def rsa_decrypt(encrypted_message, private_key):
    max_chunk_size = 256  # Tamaño de bloque cifrado con una clave RSA de 2048 bits
    decrypted_chunks = []
    for i in range(0, len(encrypted_message), max_chunk_size):
        chunk = encrypted_message[i:i + max_chunk_size]
        decrypted_chunk = private_key.decrypt(
            chunk,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        decrypted_chunks.append(decrypted_chunk)
    return b''.join(decrypted_chunks)

def handle_client(client_socket):
    try:
        # Enviar la clave pública del servidor al cliente
        with open("server_public_key.pem", "rb") as f:
            server_public_key_pem = f.read()
        client_socket.sendall(server_public_key_pem)

        # Recibir la clave pública del cliente
        client_public_key_pem = client_socket.recv(4096)
        client_public_key = serialization.load_pem_public_key(client_public_key_pem)

        while True:
            # Recibir mensaje cifrado del cliente
            encrypted_message = client_socket.recv(4096)
            if not encrypted_message:
                break

            # Descifrar el mensaje con la clave privada del servidor
            decrypted_message = rsa_decrypt(encrypted_message, server_private_key)
            print(f"Cliente: {decrypted_message.decode()}")

            # Pedir al usuario que introduzca una respuesta
            response = input("Tu respuesta: ").encode()

            # Cifrar la respuesta con la clave pública del cliente
            encrypted_response = rsa_encrypt(response, client_public_key)

            # Enviar la respuesta cifrada al cliente
            client_socket.sendall(encrypted_response)

    except Exception as e:
        print(f"Error: {e}")
    finally:
        client_socket.close()

def start_server(host='192.168.1.131', port=12345):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))
    server_socket.listen(5)
    print(f"Esperando conexión en {host}:{port}...")

    while True:
        client_socket, client_address = server_socket.accept()
        print(f"Conectado a {client_address}")

        client_handler = threading.Thread(target=handle_client, args=(client_socket,))
        client_handler.start()

if __name__ == "__main__":
    start_server()
