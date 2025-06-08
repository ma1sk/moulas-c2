import os
import json
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

def generate_key(password: str, salt: bytes = None) -> tuple:
    """Generate an encryption key from a password"""
    if salt is None:
        salt = os.urandom(16)
    
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key, salt

def encrypt_message(message: dict, key: bytes) -> bytes:
    """Encrypt a message using Fernet"""
    f = Fernet(key)
    return f.encrypt(json.dumps(message).encode())

def decrypt_message(encrypted_message: bytes, key: bytes) -> dict:
    """Decrypt a message using Fernet"""
    f = Fernet(key)
    return json.loads(f.decrypt(encrypted_message).decode())

def generate_client_id() -> str:
    """Generate a unique client ID"""
    return base64.urlsafe_b64encode(os.urandom(16)).decode()

def validate_command(command: str) -> bool:
    """Validate if a command is allowed to be executed"""
    # Add your command validation logic here
    # This is a basic example that only allows certain commands
    allowed_commands = [
        'dir', 'ls', 'pwd', 'whoami', 'ipconfig', 'ifconfig',
        'netstat', 'tasklist', 'ps', 'systeminfo'
    ]
    
    # Check if the command starts with any of the allowed commands
    return any(command.strip().lower().startswith(cmd) for cmd in allowed_commands)

def format_command_output(output: dict) -> str:
    """Format command output for display"""
    result = []
    if output['stdout']:
        result.append("STDOUT:")
        result.append(output['stdout'])
    if output['stderr']:
        result.append("STDERR:")
        result.append(output['stderr'])
    if output['return_code'] != 0:
        result.append(f"Return code: {output['return_code']}")
    return "\n".join(result) 