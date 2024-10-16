from Crypto.PublicKey import ElGamal
from Crypto.Random import get_random_bytes
from Crypto.Util.number import long_to_bytes

def generate_elgamal_key_pair():
    key = ElGamal.generate(2048, get_random_bytes)
    
    # Extract the private and public key components
    p = key.p
    g = key.g
    y = key.y  # Public component
    x = key.x  # Private component
    
    # Save private key (including all components)
    with open("elgamal_private.pem", "wb") as f:
        f.write(b"Private key components:\n")
        f.write(b"p: " + long_to_bytes(p) + b"\n")
        f.write(b"g: " + long_to_bytes(g) + b"\n")
        f.write(b"y (public): " + long_to_bytes(y) + b"\n")
        f.write(b"x (private): " + long_to_bytes(x) + b"\n")
    
    # Save public key (only public components)
    with open("elgamal_public.pem", "wb") as f:
        f.write(b"Public key components:\n")
        f.write(b"p: " + long_to_bytes(p) + b"\n")
        f.write(b"g: " + long_to_bytes(g) + b"\n")
        f.write(b"y: " + long_to_bytes(y) + b"\n")
    
    print("ElGamal keys generated and saved.")

if __name__ == "__main__":
    generate_elgamal_key_pair()
