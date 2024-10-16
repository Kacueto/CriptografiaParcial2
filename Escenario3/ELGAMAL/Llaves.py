from Crypto.PublicKey import ElGamal
from Crypto.Random import get_random_bytes
from Crypto.Util import number
from typing import Tuple

import gensafeprime

class Parameters:

    def __init__(self,n_bits: int ) -> None:
        p = gensafeprime.generate(n_bits)
        q = (p-1) //2
        g=number.getRandomNBitInteger(n_bits) % p 
        while (pow(g,2,p) ==1 or pow(g,q,p) !=1):
            g=number.getRandomNBitInteger(n_bits) % p 
        self.p: int = p
        self.q: int = q
        self.g: int = g


class DiffieHellmanFp:

    def __init__(self,parameters: "Parameters") -> None:
        self.parameters = parameters
        self.x, self.y = self.__gen_keypair()
    def __gen_keypair(self) -> Tuple[int,int]:
        x = number.getRandomRange(2,self.parameters.q -1)
        y = pow(self.parameters.g,x,self.parameters.p)
        return(x,y)



parameters = Parameters(2048)
dh = DiffieHellmanFp(parameters)



# Save private key (including all components)
with open("elgamal_private2.pem", "wb") as f:
        f.write(b"Private key components:\n")
        f.write(b"p: " + number.long_to_bytes(dh.parameters.p) + b"\n")
        f.write(b"g: " + number.long_to_bytes(dh.parameters.g) + b"\n")
        f.write(b"y (public): " + number.long_to_bytes(dh.y) + b"\n")
        f.write(b"x (private): " + number.long_to_bytes(dh.x) + b"\n")
    
    # Save public key (only public components)
with open("elgamal_public2.pem", "wb") as f:
        f.write(b"p: " + number.long_to_bytes(dh.parameters.p) + b"\n")
        f.write(b"g: " + number.long_to_bytes(dh.parameters.g) + b"\n")
        f.write(b"y (public): " + number.long_to_bytes(dh.y) + b"\n")
    
print("ElGamal keys generated and saved.")
