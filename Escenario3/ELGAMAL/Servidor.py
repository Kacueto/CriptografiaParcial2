import socket
import threading
from Crypto.Util import number
from typing import Tuple
import gensafeprime

class Parameters:
    def __init__(self, n_bits: int) -> None:
        p = gensafeprime.generate(n_bits)
        q = (p - 1) // 2
        g = number. (n_bits) % p
        while (pow(g, 2, p) == 1 or pow(g, q, p) != 1):
            g = number.getRandomNBitInteger(n_bits) % p
        self.p: int = p
        self.q: int = q
        self.g: int = g

class DiffieHellmanFp:
    def __init__(self, parameters: Parameters) -> None:
        self.parameters = parameters
        self.x, self.y = self.__gen_keypair()

    def __gen_keypair(self) -> Tuple[int, int]:
        x = number.getRandomRange(2, self.parameters.q - 1)
        y = pow(self.parameters.g, x, self.parameters.p)
        return x, y

def elgamal_encrypt(elgamal_key, message):
    k = number.getRandomRange(2, elgamal_key.parameters.q - 1)
    a = pow(elgamal_key.parameters.g, k, elgamal_key.parameters.p)
    b = (pow(elgamal_key.y, k, elgamal_key.parameters.p) * int.from_bytes(message, 'big')) % elgamal_key.parameters.p
    return a, b

def elgamal_decrypt(elgamal_key, ciphertext):
    a, b = ciphertext
    s = pow(a, elgamal_key.x, elgamal_key.parameters.p)
    m = (b * pow(s, elgamal_key.parameters.p - 2, elgamal_key.parameters.p)) % elgamal_key.parameters.p
    return m.to_bytes((m.bit_length() + 7) // 8, 'big')

def handle_client(client_socket, server_key):
    try:
        # Enviar clave pública del servidor al cliente
        server_public_key_data = f"p: {server_key.parameters.p}\ng: {server_key.parameters.g}\ny: {server_key.y}\n"
        client_socket.sendall(server_public_key_data.encode())

        # Recibir clave pública del cliente
        client_public_key_data = client_socket.recv(2048)
        client_public_key_lines = client_public_key_data.decode().split('\n')
        client_public_key_components = {}
        for line in client_public_key_lines:
            if ": " in line:
                k, v = line.split(": ")
                client_public_key_components[k.strip()] = int(v)

        client_public_key = Parameters(2048)
        client_public_key.p = client_public_key_components['p']
        client_public_key.g = client_public_key_components['g']
        client_public_key.y = client_public_key_components['y']

        while True:
            # Recibir datos cifrados del cliente
            encrypted_message_data = client_socket.recv(4096)
            a_len = len(encrypted_message_data) // 2
            encrypted_message = (
                int.from_bytes(encrypted_message_data[:a_len], 'big'),
                int.from_bytes(encrypted_message_data[a_len:], 'big')
            )

            if not encrypted_message:
                break

            # Desencriptar el mensaje con la clave privada del servidor
            decrypted_message = elgamal_decrypt(server_key, encrypted_message)
            print(f"Cliente: {decrypted_message.decode()}")

            # Pedir al usuario que introduzca una respuesta
            response = input("Tu respuesta: ").encode()

            # Encriptar la respuesta con la clave pública del cliente
            encrypted_response = elgamal_encrypt(client_public_key, response)

            # Convertir los componentes cifrados a bytes y enviar al cliente
            a_bytes = encrypted_response[0].to_bytes((encrypted_response[0].bit_length() + 7) // 8, 'big')
            b_bytes = encrypted_response[1].to_bytes((encrypted_response[1].bit_length() + 7) // 8, 'big')
            client_socket.sendall(a_bytes + b_bytes)

    except Exception as e:
        print(f"Error: {e}")
    finally:
        client_socket.close()

def start_server(host='100.115.92.206', port=65432):
    # Generar claves ElGamal para el servidor
    parameters = Parameters(2048)
    server_key = DiffieHellmanFp(parameters)

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))
    server_socket.listen(1)
    print(f"Esperando conexión en {host}:{port}...")

    while True:
        client_socket, client_address = server_socket.accept()
        print(f"Conectado a {client_address}")
        client_handler = threading.Thread(target=handle_client, args=(client_socket, server_key))
        client_handler.start()

if __name__ == "__main__":
    start_server()
