# -*- coding: utf-8 -*-
"""
Created on Sun Nov 10 15:13:57 2024

@author: Sys
"""

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import random
from math import gcd
import uvicorn

app = FastAPI()

# Allow CORS for development (you can restrict origins in production)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allows all origins; for production, specify allowed domains
    allow_credentials=True,
    allow_methods=["*"],  # Allows all methods
    allow_headers=["*"],  # Allows all headers
)

# Helper function for modular exponentiation (base^exp % mod)
def mod_exp(base, exp, mod):
    return pow(base, exp, mod)

# Helper function to check if a number is prime (for Diffie-Hellman)
def is_prime(num):
    if num <= 1:
        return False
    for i in range(2, int(num**0.5) + 1):
        if num % i == 0:
            return False
    return True

# ---------- Diffie-Hellman Models and Endpoint ----------

class KeyExchangeRequest(BaseModel):
    p: int  # prime number
    g: int  # primitive root (generator)

class KeyExchangeResponse(BaseModel):
    alice_private_key: int
    bob_private_key: int
    alice_public_key: int
    bob_public_key: int
    alice_shared_key: int
    bob_shared_key: int
    exchange_status: str

@app.post("/diffie-hellman/", response_model=KeyExchangeResponse)
def diffie_hellman_key_exchange(request: KeyExchangeRequest):
    p = request.p
    g = request.g

    if not is_prime(p):
        raise HTTPException(status_code=400, detail="p should be a prime number.")

    # Generate private keys for Alice and Bob
    a = random.randint(2, p - 2)
    b = random.randint(2, p - 2)

    # Compute public keys for Alice and Bob
    A = mod_exp(g, a, p)
    B = mod_exp(g, b, p)

    # Compute the shared secret keys for Alice and Bob
    shared_key_alice = mod_exp(B, a, p)
    shared_key_bob = mod_exp(A, b, p)

    # Check if the key exchange was successful
    exchange_status = "Key exchange successful!" if shared_key_alice == shared_key_bob else "Key exchange failed!"

    return KeyExchangeResponse(
        alice_private_key=a,
        bob_private_key=b,
        alice_public_key=A,
        bob_public_key=B,
        alice_shared_key=shared_key_alice,
        bob_shared_key=shared_key_bob,
        exchange_status=exchange_status
    )

# ---------- RSA Models and Endpoints ----------

# Global variables for RSA keys
e = d = n = None

class RSAKeyRequest(BaseModel):
    p: int  # prime number
    q: int  # prime number

class RSAKeyResponse(BaseModel):
    public_key: tuple
    private_key: tuple

class MessageRequest(BaseModel):
    message: int

def mod_inverse(e, phi_n):
    for d in range(1, phi_n):
        if (e * d) % phi_n == 1:
            return d
    return None

@app.post("/rsa/generate-keys", response_model=RSAKeyResponse)
def generate_rsa_keys(request: RSAKeyRequest):
    global e, d, n
    p = request.p
    q = request.q
    n = p * q
    phi_n = (p - 1) * (q - 1)

    e = random.choice([i for i in range(2, phi_n) if gcd(i, phi_n) == 1])
    d = mod_inverse(e, phi_n)

    if d is None:
        raise HTTPException(status_code=500, detail="Failed to find modular inverse for e.")

    return RSAKeyResponse(public_key=(e, n), private_key=(d, n))

@app.post("/rsa/encrypt", response_model=dict)
def rsa_encrypt(request: MessageRequest):
    global e, n
    if e is None or n is None:
        raise HTTPException(status_code=400, detail="Keys are not generated. Generate keys first.")

    message = request.message
    cipher = mod_exp(message, e, n)
    return {"encrypted_message": cipher}

@app.post("/rsa/decrypt", response_model=dict)
def rsa_decrypt(request: MessageRequest):
    global d, n
    if d is None or n is None:
        raise HTTPException(status_code=400, detail="Keys are not generated. Generate keys first.")

    cipher = request.message
    decrypted_message = mod_exp(cipher, d, n)
    return {"decrypted_message": decrypted_message}

# ---------- Main Program Entry ----------

if __name__ == "__main__":
    uvicorn.run(app, host="localhost", port=8000)
