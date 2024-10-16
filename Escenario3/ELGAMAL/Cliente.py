import socket
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

def client_program():
    client_private_key = load_key(KEY_FILE_PRIVATE)
    client_public_key = load_key(KEY_FILE_PUBLIC)

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(('127.0.0.1', 65432))

    try:
        # Recibir la clave pública del servidor
        server_public_key = client_socket.recv(2048)

        # Enviar la clave pública del cliente al servidor
        client_socket.sendall(client_public_key)

        while True:
            # Pedir al usuario que introduzca un mensaje
            message = input("Tu mensaje: ").encode()

            # Encriptar el mensaje con la clave pública del servidor
            encrypted_message = elgamal_encrypt(server_public_key, message)

            # Enviar el mensaje cifrado al servidor
            client_socket.sendall(encrypted_message)

            # Recibir la respuesta cifrada del servidor
            encrypted_response = client_socket.recv(4096)

            # Desencriptar la respuesta con la clave privada del cliente
            decrypted_response = elgamal_decrypt(client_private_key, encrypted_response)
            print(f"Servidor: {decrypted_response.decode()}")

    except Exception as e:
        print(f"Error: {e}")
    finally:
        client_socket.close()

if __name__ == "__main__":
    client_program()
