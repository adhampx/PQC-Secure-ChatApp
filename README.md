# Secure Chat Application with Hybrid Encryption

## Overview

This project is a secure chat application that demonstrates the concept of hybrid encryption, similar to what would be used in post-quantum cryptography. The application allows two users to exchange encrypted messages through a web interface, with all communication protected using strong cryptographic techniques.

## Features

- **Secure Messaging**: All messages are encrypted using a hybrid cryptographic approach
- **Real-time Chat Interface**: Clean, modern UI for seamless messaging experience
- **Profile Switching**: Easily switch between two user profiles
- **Message Encryption Indicator**: Visual indicator showing when messages are encrypted
- **Message Timestamps**: Each message displays when it was sent

## Technology Stack

### Frontend
- HTML5, CSS3, JavaScript
- Modern UI with responsive design

### Backend
- Python 3.x
- Flask framework for API endpoints
- Flask-CORS for cross-origin resource sharing

### Cryptography
- PyCryptodome for cryptographic operations
- RSA for asymmetric key exchange (simulating post-quantum KEM)
- AES-GCM for symmetric message encryption
- Base64 encoding for data transmission

## Security Architecture

The application implements a hybrid encryption scheme similar to what would be used in quantum-resistant cryptography:

1. **Key Exchange**: Using RSA key pairs to securely exchange a symmetric key (simulating a quantum-resistant KEM)
2. **Message Encryption**: AES-GCM for encrypting the actual message contents
3. **Message Authentication**: GCM mode provides authentication tags to verify message integrity

## Installation and Setup

### Prerequisites
- Python 3.8 or higher
- A modern web browser

### Installation Steps

1. Clone the repository:
   ```
   git clone https://github.com/yourusername/secure-chat.git
   cd secure-chat
   ```

2. Install the required dependencies:
   ```
   pip install -r requirements.txt
   ```

3. Start the Flask server:
   ```
   python server.py
   ```

4. Open `index.html` in your web browser.

## Usage

1. The application opens with Profile 1 active by default.
2. Type a message in the input field and press Enter or click the send button.
3. The message will be encrypted and displayed in the chat area.
4. Switch between profiles using the buttons at the top of the chat window.
5. Each profile has its own keypair and can send/receive encrypted messages.

## How Encryption Works

1. When a user sends a message:
   - A random 256-bit AES key is generated
   - The AES key is encrypted with the recipient's public RSA key
   - The message is encrypted using the AES key in GCM mode
   - Both the encrypted key and the encrypted message are transmitted

2. When a user receives a message:
   - The encrypted AES key is decrypted using the recipient's private RSA key
   - The message is decrypted using the recovered AES key
   - The message integrity is verified using the GCM authentication tag

## Future Enhancements

- Implementation of true post-quantum algorithms (Kyber, Dilithium, etc.)
- Support for group chats with multi-party encryption
- Message persistence with secure storage
- User authentication and account management
- File sharing capabilities with encrypted file transfer

## Project Structure

- `index.html`: Main application HTML
- `styles.css`: CSS styling for the chat interface
- `script.js`: Frontend JavaScript for the chat functionality
- `server.py`: Flask server for handling encryption/decryption requests
- `quantum_crypto.py`: Implementation of the cryptographic operations
- `requirements.txt`: Python dependencies

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgements

This project was created to demonstrate hybrid encryption techniques and simulate post-quantum cryptographic concepts in a practical web application.

---

*Note: This application is designed for educational purposes and should not be used for sensitive communications without further security enhancements.*
 
