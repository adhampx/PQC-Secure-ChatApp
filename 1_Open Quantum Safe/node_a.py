# node_a.py

from flask import Flask, request, jsonify
import base64
from pqc_utils import (
    generate_kem_keypair,
    decapsulate_key,
    derive_symmetric_key,
    symmetric_encrypt,
    symmetric_decrypt
)

# Create the Flask app
app = Flask(__name__)

# Select the KEM algorithm (e.g., "Kyber512")
KEM_ALG = "Kyber512"

# Generate Node A's key pair at startup.
# kem_instance holds the private key needed for decapsulation.
kem_instance, public_key = generate_kem_keypair(KEM_ALG)
print("Node A KEM public key generated.")

# Endpoint to retrieve Node A's public key.
@app.route('/public_key', methods=['GET'])
def get_public_key():
    # Encode public key in base64 so it can be easily transmitted via JSON.
    pub_b64 = base64.b64encode(public_key).decode('utf-8')
    return jsonify({'public_key': pub_b64})

# Endpoint to receive an encrypted message from Node B.
@app.route('/message', methods=['POST'])
def receive_message():
    data = request.get_json()
    try:
        # Extract and decode the fields from the incoming JSON.
        ciphertext = base64.b64decode(data['ciphertext'])
        salt = base64.b64decode(data['salt'])
        iv = base64.b64decode(data['iv'])
        tag = base64.b64decode(data['tag'])
        encrypted_message = base64.b64decode(data['encrypted_message'])
        
        # Decapsulate to retrieve the shared secret.
        shared_secret = decapsulate_key(kem_instance, ciphertext)
        
        # Derive a symmetric key using the shared secret and provided salt.
        symmetric_key, _ = derive_symmetric_key(shared_secret, key_len=16, salt=salt)
        
        # Decrypt the incoming message using AES-GCM.
        plaintext = symmetric_decrypt(symmetric_key, iv, encrypted_message, tag)
        print("Received message from Node B:", plaintext.decode('utf-8'))
        
        # Prepare a reply message.
        reply_message = "Hello from Node A"
        iv_reply, encrypted_reply, tag_reply = symmetric_encrypt(symmetric_key, reply_message.encode('utf-8'))
        
        # Encode reply components in base64 for JSON transmission.
        response = {
            'iv': base64.b64encode(iv_reply).decode('utf-8'),
            'encrypted_message': base64.b64encode(encrypted_reply).decode('utf-8'),
            'tag': base64.b64encode(tag_reply).decode('utf-8')
        }
        return jsonify(response)
    
    except Exception as e:
        print("Error processing message:", str(e))
        return jsonify({'error': str(e)}), 400

# Run the Flask server on localhost.
if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5000, debug=True)
