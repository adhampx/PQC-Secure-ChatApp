from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP
import base64
import json
from typing import Tuple, Dict

class QuantumCrypto:
    def __init__(self, key_size: int = 2048):
        """
        Initialize the cryptography system.
        Args:
            key_size: The size of the RSA key in bits
        """
        self.key_size = key_size
        self.public_key = None
        self.private_key = None
        self.shared_secret = None
        
    def generate_keypair(self) -> Tuple[bytes, bytes]:
        """
        Generate a key pair.
        Returns:
            Tuple containing (public_key, private_key)
        """
        # Generate RSA key
        key = RSA.generate(self.key_size)
        self.private_key = key.export_key()
        self.public_key = key.publickey().export_key()
        return self.public_key, self.private_key
    
    def encapsulate(self, public_key: bytes) -> Tuple[bytes, bytes]:
        """
        Encapsulate a shared secret using the recipient's public key.
        Args:
            public_key: The recipient's public key
        Returns:
            Tuple containing (ciphertext, shared_secret)
        """
        # Generate a random shared secret
        self.shared_secret = get_random_bytes(32)  # 256-bit key
        
        # Encrypt the shared secret using the recipient's public key
        recipient_key = RSA.import_key(public_key)
        cipher_rsa = PKCS1_OAEP.new(recipient_key)
        ciphertext = cipher_rsa.encrypt(self.shared_secret)
        
        return ciphertext, self.shared_secret
    
    def decapsulate(self, ciphertext: bytes) -> bytes:
        """
        Decapsulate the shared secret using the recipient's private key.
        Args:
            ciphertext: The encrypted shared secret
        Returns:
            The decrypted shared secret
        """
        # Decrypt the shared secret using the private key
        key = RSA.import_key(self.private_key)
        cipher_rsa = PKCS1_OAEP.new(key)
        shared_secret = cipher_rsa.decrypt(ciphertext)
        return shared_secret
    
    def encrypt_message(self, message: str, recipient_public_key: bytes) -> Dict:
        """
        Encrypt a message using hybrid encryption.
        Args:
            message: The message to encrypt
            recipient_public_key: The recipient's public key
        Returns:
            Dictionary containing encrypted message data
        """
        # Convert message to bytes
        message_bytes = message.encode('utf-8')
        
        # Generate ciphertext and shared secret
        ciphertext, shared_secret = self.encapsulate(recipient_public_key)
        
        # Use shared secret as AES key to encrypt the message
        cipher_aes = AES.new(shared_secret, AES.MODE_GCM)
        cipher_text, tag = cipher_aes.encrypt_and_digest(message_bytes)
        
        # Encode data for transmission
        encrypted_data = {
            'ciphertext': base64.b64encode(ciphertext).decode('utf-8'),
            'encrypted_message': base64.b64encode(cipher_text).decode('utf-8'),
            'nonce': base64.b64encode(cipher_aes.nonce).decode('utf-8'),
            'tag': base64.b64encode(tag).decode('utf-8')
        }
        
        return encrypted_data
    
    def decrypt_message(self, encrypted_data: Dict) -> str:
        """
        Decrypt a message using hybrid encryption.
        Args:
            encrypted_data: Dictionary containing encrypted message data
        Returns:
            The decrypted message
        """
        # Decode the encrypted data
        ciphertext = base64.b64decode(encrypted_data['ciphertext'])
        encrypted_message = base64.b64decode(encrypted_data['encrypted_message'])
        nonce = base64.b64decode(encrypted_data['nonce'])
        tag = base64.b64decode(encrypted_data['tag'])
        
        # Decapsulate the shared secret
        shared_secret = self.decapsulate(ciphertext)
        
        # Decrypt the message using AES
        cipher_aes = AES.new(shared_secret, AES.MODE_GCM, nonce=nonce)
        decrypted_bytes = cipher_aes.decrypt_and_verify(encrypted_message, tag)
        
        return decrypted_bytes.decode('utf-8')

# Example usage
if __name__ == "__main__":
    # Create two instances for sender and receiver
    sender = QuantumCrypto()
    receiver = QuantumCrypto()
    
    # Generate key pairs
    sender_public_key, sender_private_key = sender.generate_keypair()
    receiver_public_key, receiver_private_key = receiver.generate_keypair()
    
    # Example message
    message = "Hello, this is an encrypted message!"
    
    # Encrypt message from sender to receiver
    encrypted_data = sender.encrypt_message(message, receiver_public_key)
    
    # Decrypt message on receiver's side
    decrypted_message = receiver.decrypt_message(encrypted_data)
    
    print(f"Original message: {message}")
    print(f"Decrypted message: {decrypted_message}")
    print(f"Encryption successful: {message == decrypted_message}") 