import socket
import threading
from Crypto.PublicKey import ElGamal
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

KEY_FILE_PRIVATE = 'elgamal_private.pem'
KEY_FILE_PUBLIC = 'elgamal_public.pem'

def load_key(file_path):
    with open(file_path, 'rb') as f:
        key = f.read()
    return key

def elgamal_encrypt(public_key, message):
    elgamal_key = ElGamal.import_key(public_key)
    cipher_elgamal = PKCS1_OAEP.new(elgamal_key)
    return cipher_elgamal.encrypt(message)

def elgamal_decrypt(private_key, ciphertext):
    elgamal_key = ElGamal.import_key(private_key)
    cipher_elgamal = PKCS1_OAEP.new(elgamal_key)
    return cipher_elgamal.decrypt(ciphertext)

def handle_client(client_socket, server_private_key, server_public_key):
    try:
        # Enviar clave pública del servidor al cliente
        client_socket.sendall(server_public_key)

        # Recibir clave pública del cliente
        client_public_key = client_socket.recv(2048)

        while True:
            # Recibir datos cifrados del cliente
            encrypted_message = client_socket.recv(4096)
            if not encrypted_message:
                break

            # Desencriptar el mensaje con la clave privada del servidor
            decrypted_message = elgamal_decrypt(server_private_key, encrypted_message)
            print(f"Cliente: {decrypted_message.decode()}")

            # Pedir al usuario que introduzca una respuesta
            response = input("Tu respuesta: ").encode()

            # Encriptar la respuesta con la clave pública del cliente
            encrypted_response = elgamal_encrypt(client_public_key, response)

            # Enviar la respuesta cifrada al cliente
            client_socket.sendall(encrypted_response)

    except Exception as e:
        print(f"Error: {e}")
    finally:
        client_socket.close()

def start_server(host='0.0.0.0', port=65432):
    server_private_key = load_key(KEY_FILE_PRIVATE)
    server_public_key = load_key(KEY_FILE_PUBLIC)

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))
    server_socket.listen(1)
    print(f"Esperando conexión en {host}:{port}...")

    while True:
        client_socket, client_address = server_socket.accept()
        print(f"Conectado a {client_address}")
        client_handler = threading.Thread(target=handle_client, args=(client_socket, server_private_key, server_public_key))
        client_handler.start()

if __name__ == "__main__":
    start_server()
