# pqc_utils.py

import oqs
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

def generate_kem_keypair(kem_alg="Kyber512"):
    """
    Generate a key encapsulation mechanism (KEM) key pair using the specified algorithm.
    
    Args:
        kem_alg (str): The PQC algorithm to use (e.g., "Kyber512").
        
    Returns:
        tuple: (kem_instance, public_key)
            - kem_instance: The oqs.KeyEncapsulation instance holding the private key.
            - public_key (bytes): The generated public key.
    """
    kem_instance = oqs.KeyEncapsulation(kem_alg)
    public_key = kem_instance.generate_keypair()
    return kem_instance, public_key

def encapsulate_key(public_key, kem_alg="Kyber512"):
    """
    Encapsulate a shared secret using the given public key and the specified KEM algorithm.
    
    Args:
        public_key (bytes): The public key from the receiving node.
        kem_alg (str): The PQC algorithm to use (e.g., "Kyber512").
        
    Returns:
        tuple: (ciphertext, shared_secret)
            - ciphertext (bytes): The encapsulated ciphertext.
            - shared_secret (bytes): The shared secret derived from encapsulation.
    """
    kem_instance = oqs.KeyEncapsulation(kem_alg)
    ciphertext, shared_secret = kem_instance.encapsulate(public_key)
    return ciphertext, shared_secret

def decapsulate_key(kem_instance, ciphertext):
    """
    Decapsulate the ciphertext using the provided KEM instance to retrieve the shared secret.
    
    Args:
        kem_instance: The oqs.KeyEncapsulation instance (holding the private key).
        ciphertext (bytes): The ciphertext received from the sender.
        
    Returns:
        bytes: The shared secret derived from decapsulation.
    """
    shared_secret = kem_instance.decapsulate(ciphertext)
    return shared_secret

def derive_symmetric_key(shared_secret, key_len=16, salt=None, info=b"pqc symmetric key"):
    """
    Derive a symmetric key from the shared secret using HKDF (with SHA-256).
    
    Args:
        shared_secret (bytes): The shared secret obtained from KEM operations.
        key_len (int): Desired length of the symmetric key in bytes (default: 16 for AES-128).
        salt (bytes, optional): A salt value for HKDF. If None, a random salt is generated.
        info (bytes): Context and application specific information (default: b"pqc symmetric key").
        
    Returns:
        tuple: (symmetric_key, salt)
            - symmetric_key (bytes): The derived symmetric key.
            - salt (bytes): The salt used during derivation (must be shared between parties).
    """
    if salt is None:
        salt = os.urandom(16)
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=key_len,
        salt=salt,
        info=info,
        backend=default_backend()
    )
    symmetric_key = hkdf.derive(shared_secret)
    return symmetric_key, salt

def symmetric_encrypt(key, plaintext):
    """
    Encrypt plaintext using AES-GCM symmetric encryption.
    
    Args:
        key (bytes): The symmetric key (e.g., 16 bytes for AES-128).
        plaintext (bytes): The message to encrypt.
        
    Returns:
        tuple: (iv, ciphertext, tag)
            - iv (bytes): The initialization vector used for encryption.
            - ciphertext (bytes): The encrypted data.
            - tag (bytes): The authentication tag for decryption.
    """
    iv = os.urandom(12)  # 96-bit nonce for AES-GCM
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    return iv, ciphertext, encryptor.tag

def symmetric_decrypt(key, iv, ciphertext, tag):
    """
    Decrypt ciphertext using AES-GCM symmetric decryption.
    
    Args:
        key (bytes): The symmetric key.
        iv (bytes): The initialization vector used during encryption.
        ciphertext (bytes): The encrypted message.
        tag (bytes): The authentication tag produced during encryption.
        
    Returns:
        bytes: The decrypted plaintext.
    """
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return plaintext
