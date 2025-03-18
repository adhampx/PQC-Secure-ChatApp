from flask import Flask, request, jsonify
from flask_cors import CORS
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP
import base64

app = Flask(__name__)
CORS(app)

# Initialize RSA keys for both profiles
def generate_keypair():
    key = RSA.generate(2048)
    return key.publickey().export_key(), key.export_key()

# Generate key pairs for both profiles
profile1_public_key, profile1_private_key = generate_keypair()
profile2_public_key, profile2_private_key = generate_keypair()

def encrypt_message(message: str, recipient_public_key: bytes) -> dict:
    """
    Encrypt a message using hybrid encryption.
    """
    # Convert message to bytes
    message_bytes = message.encode('utf-8')
    
    # Generate a random shared secret
    shared_secret = get_random_bytes(32)  # 256-bit key
    
    # Encrypt the shared secret using the recipient's public key
    recipient_key = RSA.import_key(recipient_public_key)
    cipher_rsa = PKCS1_OAEP.new(recipient_key)
    ciphertext = cipher_rsa.encrypt(shared_secret)
    
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

def decrypt_message(encrypted_data: dict, private_key: bytes) -> str:
    """
    Decrypt a message using hybrid encryption.
    """
    # Decode the encrypted data
    ciphertext = base64.b64decode(encrypted_data['ciphertext'])
    encrypted_message = base64.b64decode(encrypted_data['encrypted_message'])
    nonce = base64.b64decode(encrypted_data['nonce'])
    tag = base64.b64decode(encrypted_data['tag'])
    
    # Decrypt the shared secret using the private key
    key = RSA.import_key(private_key)
    cipher_rsa = PKCS1_OAEP.new(key)
    shared_secret = cipher_rsa.decrypt(ciphertext)
    
    # Decrypt the message using AES
    cipher_aes = AES.new(shared_secret, AES.MODE_GCM, nonce=nonce)
    decrypted_bytes = cipher_aes.decrypt_and_verify(encrypted_message, tag)
    
    return decrypted_bytes.decode('utf-8')

@app.route('/encrypt', methods=['POST'])
def encrypt():
    data = request.json
    message = data.get('message')
    sender = data.get('sender')
    
    if sender == 'Profile 1':
        # Profile 1 sending to Profile 2
        encrypted_data = encrypt_message(message, profile2_public_key)
    else:
        # Profile 2 sending to Profile 1
        encrypted_data = encrypt_message(message, profile1_public_key)
    
    return jsonify(encrypted_data)

@app.route('/decrypt', methods=['POST'])
def decrypt():
    data = request.json
    encrypted_data = data.get('encrypted_data')
    receiver = data.get('receiver')
    
    if receiver == 'Profile 1':
        # Profile 1 receiving from Profile 2
        decrypted_message = decrypt_message(encrypted_data, profile1_private_key)
    else:
        # Profile 2 receiving from Profile 1
        decrypted_message = decrypt_message(encrypted_data, profile2_private_key)
    
    return jsonify({'message': decrypted_message})

if __name__ == '__main__':
    app.run(debug=True, port=5000) 