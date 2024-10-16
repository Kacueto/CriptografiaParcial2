import socket
from Crypto.Util import number
from typing import Tuple
import gensafeprime

class Parameters:
    def __init__(self, n_bits: int) -> None:
        p = gensafeprime.generate(n_bits)
        q = (p - 1) // 2
        g = number.getRandomNBitInteger(n_bits) % p
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

def client_program():
    # Generar claves ElGamal para el cliente
    parameters = Parameters(2048)
    client_key = DiffieHellmanFp(parameters)

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(('100.115.92.206', 65432))

    try:
        # Recibir la clave pública del servidor
        server_public_key_data = client_socket.recv(2048)
        server_public_key_lines = server_public_key_data.decode().split('\n')
        server_public_key_components = {}
        for line in server_public_key_lines:
            if ": " in line:
                k, v = line.split(": ")
                server_public_key_components[k.strip()] = int(v)

        server_public_key = Parameters(2048)
        server_public_key.p = server_public_key_components['p']
        server_public_key.g = server_public_key_components['g']
        server_public_key.y = server_public_key_components['y']

        # Enviar la clave pública del cliente al servidor
        client_public_key_data = f"p: {client_key.parameters.p}\ng: {client_key.parameters.g}\ny: {client_key.y}\n"
        client_socket.sendall(client_public_key_data.encode())

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
            a_len = len(encrypted_response_data) // 2
            encrypted_response = (
                int.from_bytes(encrypted_response_data[:a_len], 'big'),
                int.from_bytes(encrypted_response_data[a_len:], 'big')
            )

            # Desencriptar la respuesta con la clave privada del cliente
            decrypted_response = elgamal_decrypt(client_key, encrypted_response)
            print(f"Servidor: {decrypted_response.decode()}")

    except Exception as e:
        print(f"Error: {e}")
    finally:
        client_socket.close()

if __name__ == "__main__":
    client_program()