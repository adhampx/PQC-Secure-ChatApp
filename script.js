// Chat application state
let currentProfile = 'Profile 1';
let messages = [];

// DOM Elements
const profile1Btn = document.getElementById('profile1');
const profile2Btn = document.getElementById('profile2');
const currentProfileName = document.getElementById('current-profile-name');
const messageInput = document.getElementById('message-input');
const sendButton = document.getElementById('send-button');
const chatMessages = document.getElementById('chat-messages');

// API endpoints
const API_URL = 'http://localhost:5000';

// Profile switching functionality
profile1Btn.addEventListener('click', () => switchProfile('Profile 1'));
profile2Btn.addEventListener('click', () => switchProfile('Profile 2'));

function switchProfile(profile) {
    currentProfile = profile;
    currentProfileName.textContent = profile;
    
    // Update active button
    profile1Btn.classList.toggle('active', profile === 'Profile 1');
    profile2Btn.classList.toggle('active', profile === 'Profile 2');
    
    // Clear input
    messageInput.value = '';
    
    // Update messages display
    displayMessages();
}

// Message sending functionality
async function sendMessage() {
    const messageText = messageInput.value.trim();
    if (messageText) {
        try {
            // Encrypt the message
            const encryptedData = await encryptMessage(messageText);
            
            // Add encrypted message to chat
            const message = {
                text: messageText,
                sender: currentProfile,
                timestamp: new Date().toLocaleTimeString(),
                encrypted: true
            };
            
            messages.push(message);
            displayMessages();
            messageInput.value = '';
            
            // Simulate receiving a response from the other profile
            setTimeout(async () => {
                const otherProfile = currentProfile === 'Profile 1' ? 'Profile 2' : 'Profile 1';
                const response = {
                    text: `This is a response from ${otherProfile}`,
                    sender: otherProfile,
                    timestamp: new Date().toLocaleTimeString(),
                    encrypted: true
                };
                messages.push(response);
                displayMessages();
            }, 1000);
        } catch (error) {
            console.error('Error sending message:', error);
            alert('Error sending message. Please try again.');
        }
    }
}

// Encryption function
async function encryptMessage(message) {
    try {
        const response = await fetch(`${API_URL}/encrypt`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                message: message,
                sender: currentProfile
            })
        });
        
        if (!response.ok) {
            throw new Error('Encryption failed');
        }
        
        return await response.json();
    } catch (error) {
        console.error('Encryption error:', error);
        throw error;
    }
}

// Decryption function
async function decryptMessage(encryptedData) {
    try {
        const response = await fetch(`${API_URL}/decrypt`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                encrypted_data: encryptedData,
                receiver: currentProfile
            })
        });
        
        if (!response.ok) {
            throw new Error('Decryption failed');
        }
        
        const data = await response.json();
        return data.message;
    } catch (error) {
        console.error('Decryption error:', error);
        throw error;
    }
}

// Event listeners for sending messages
sendButton.addEventListener('click', sendMessage);
messageInput.addEventListener('keypress', (e) => {
    if (e.key === 'Enter') {
        sendMessage();
    }
});

// Display messages in the chat
function displayMessages() {
    chatMessages.innerHTML = '';
    messages.forEach(message => {
        const messageElement = document.createElement('div');
        messageElement.className = `message ${message.sender === currentProfile ? 'sent' : 'received'}`;
        
        const messageContent = document.createElement('div');
        messageContent.className = 'message-content';
        messageContent.textContent = message.text;
        
        const timestamp = document.createElement('div');
        timestamp.className = 'message-timestamp';
        timestamp.textContent = message.timestamp;
        
        const encryptionStatus = document.createElement('div');
        encryptionStatus.className = 'encryption-status';
        encryptionStatus.textContent = message.encrypted ? '🔒 Encrypted' : '🔓 Unencrypted';
        
        messageElement.appendChild(messageContent);
        messageElement.appendChild(timestamp);
        messageElement.appendChild(encryptionStatus);
        chatMessages.appendChild(messageElement);
    });
    
    // Scroll to bottom
    chatMessages.scrollTop = chatMessages.scrollHeight;
}

// Add some initial messages
messages = [
    {
        text: "Hello! Welcome to the quantum-safe chat application.",
        sender: "Profile 1",
        timestamp: new Date().toLocaleTimeString(),
        encrypted: true
    },
    {
        text: "Hi! This is a demo of the quantum-safe chat interface.",
        sender: "Profile 2",
        timestamp: new Date().toLocaleTimeString(),
        encrypted: true
    }
];

// Initial display
displayMessages(); 