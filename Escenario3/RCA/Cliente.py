import socket
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization

# Cargar la clave privada del cliente
with open("client_private_key.pem", "rb") as f:
    client_private_key = serialization.load_pem_private_key(
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

def start_client(server_ip='192.168.1.131', server_port=12345):
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((server_ip, server_port))

    try:
        # Recibir la clave pública del servidor
        server_public_key_pem = client_socket.recv(4096)
        server_public_key = serialization.load_pem_public_key(server_public_key_pem)

        # Enviar la clave pública del cliente al servidor
        with open("client_public_key.pem", "rb") as f:
            client_public_key_pem = f.read()
        client_socket.sendall(client_public_key_pem)

        while True:
            # Pedir al usuario que introduzca un mensaje
            message = input("Tu mensaje: ").encode()

            # Cifrar el mensaje con la clave pública del servidor
            encrypted_message = rsa_encrypt(message, server_public_key)

            # Enviar el mensaje cifrado al servidor
            client_socket.sendall(encrypted_message)

            # Recibir respuesta cifrada del servidor
            encrypted_response = client_socket.recv(4096)

            # Descifrar la respuesta con la clave privada del cliente
            decrypted_response = rsa_decrypt(encrypted_response, client_private_key)
            print(f"Servidor: {decrypted_response.decode()}")

    except Exception as e:
        print(f"Error en el cliente: {e}")
    finally:
        client_socket.close()

if __name__ == "__main__":
    start_client()
