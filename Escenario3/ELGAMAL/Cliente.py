import socket
from Crypto.PublicKey import ElGamal
from Crypto.Util import number
from typing import Tuple

KEY_FILE_PRIVATE = 'elgamal_private.pem'
KEY_FILE_PUBLIC = 'elgamal_public.pem'

def load_key(file_path):
    with open(file_path, 'rb') as f:
        lines = f.read().split(b'\n')
    key_components = {}
    for line in lines:
        if b": " in line:
            k, v = line.split(b": ")
            key_components[k.strip()] = int.from_bytes(v, 'big')
    return key_components

def elgamal_encrypt(public_key_components, message):
    p = public_key_components[b'p']
    g = public_key_components[b'g']
    y = public_key_components[b'y']
    elgamal_key = ElGamal.construct((p, g, y))
    k = number.getRandomRange(2, elgamal_key.p - 1)
    a, b = elgamal_key._encrypt(message, k)
    return (a, b)

def elgamal_decrypt(private_key_components, ciphertext):
    p = private_key_components[b'p']
    g = private_key_components[b'g']
    y = private_key_components[b'y']
    x = private_key_components[b'x']
    elgamal_key = ElGamal.construct((p, g, y, x))
    plaintext = elgamal_key._decrypt(ciphertext)
    return plaintext

def client_program():
    client_private_key = load_key(KEY_FILE_PRIVATE)
    client_public_key = load_key(KEY_FILE_PUBLIC)

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(('192.168.1.250', 65432))

    try:
        # Recibir la clave pública del servidor
        server_public_key_data = client_socket.recv(2048)
        server_public_key_lines = server_public_key_data.split(b'\n')
        server_public_key = {}
        for line in server_public_key_lines:
            if b": " in line:
                k, v = line.split(b": ")
                server_public_key[k.strip()] = int.from_bytes(v, 'big')

        # Enviar la clave pública del cliente al servidor
        with open(KEY_FILE_PUBLIC, 'rb') as f:
            client_socket.sendall(f.read())

        while True:
            # Pedir al usuario que introduzca un mensaje
            message = input("Tu mensaje: ").encode()

            # Encriptar el mensaje con la clave pública del servidor
            encrypted_message = elgamal_encrypt(server_public_key, message)

            # Convertir los componentes cifrados a bytes y enviar al servidor
            a_bytes = encrypted_message[0].to_bytes((encrypted_message[0].bit_length() + 7) // 8, 'big')
            b_bytes = encrypted_message[1].to_bytes((encrypted_message[1].bit_length() + 7) // 8, 'big')
            client_socket.sendall(a_bytes + b_bytes)

            # Recibir la respuesta cifrada del servidor
            encrypted_response_data = client_socket.recv(4096)
            encrypted_response = (
                int.from_bytes(encrypted_response_data[:len(encrypted_response_data)//2], 'big'),
                int.from_bytes(encrypted_response_data[len(encrypted_response_data)//2:], 'big')
            )

            # Desencriptar la respuesta con la clave privada del cliente
            decrypted_response = elgamal_decrypt(client_private_key, encrypted_response)
            print(f"Servidor: {decrypted_response.decode()}")

    except Exception as e:
        print(f"Error: {e}")
    finally:
        client_socket.close()

if __name__ == "__main__":
    client_program()
