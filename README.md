# C2 Framework

A Command and Control framework with a modern GUI interface.

## Setup

1. Create a virtual environment (recommended):
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

## Running the Application

1. Start the C2 server:
```bash
python main.py
```

2. The GUI will open with three main tabs:
   - Listeners: Start/stop C2 listeners
   - Payload Generator: Create and customize payloads
   - Sessions: Manage active connections

## Features

- Modern GUI interface with dark theme
- Payload generation with multiple obfuscation levels
- Real-time session management
- File transfer capabilities
- System information gathering
- Process management
- Network connection monitoring
- Multiple persistence methods

## Security Notice

This tool is for educational and authorized security testing purposes only. Always ensure you have proper authorization before using this tool on any system. 