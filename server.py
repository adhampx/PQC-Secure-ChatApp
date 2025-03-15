from flask import Flask, request, jsonify
from flask_cors import CORS
from quantum_crypto import QuantumCrypto
import base64

app = Flask(__name__)
CORS(app)

# Initialize crypto instances for both profiles
profile1_crypto = QuantumCrypto()
profile2_crypto = QuantumCrypto()

# Generate key pairs for both profiles
profile1_public_key, profile1_private_key = profile1_crypto.generate_keypair()
profile2_public_key, profile2_private_key = profile2_crypto.generate_keypair()

@app.route('/encrypt', methods=['POST'])
def encrypt_message():
    data = request.json
    message = data.get('message')
    sender = data.get('sender')
    
    if sender == 'Profile 1':
        # Profile 1 sending to Profile 2
        encrypted_data = profile1_crypto.encrypt_message(message, profile2_public_key)
    else:
        # Profile 2 sending to Profile 1
        encrypted_data = profile2_crypto.encrypt_message(message, profile1_public_key)
    
    return jsonify(encrypted_data)

@app.route('/decrypt', methods=['POST'])
def decrypt_message():
    data = request.json
    encrypted_data = data.get('encrypted_data')
    receiver = data.get('receiver')
    
    if receiver == 'Profile 1':
        # Profile 1 receiving from Profile 2
        decrypted_message = profile1_crypto.decrypt_message(encrypted_data)
    else:
        # Profile 2 receiving from Profile 1
        decrypted_message = profile2_crypto.decrypt_message(encrypted_data)
    
    return jsonify({'message': decrypted_message})

if __name__ == '__main__':
    app.run(debug=True, port=5000) 