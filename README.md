# C2 Framework

A Command and Control framework for educational and security research purposes.

## Project Structure
- `server/` - C2 server implementation
- `client/` - Client/agent implementation
- `common/` - Shared utilities and protocols
- `docs/` - Documentation

## Setup Instructions
1. Create a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

## Usage
1. Start the C2 server:
```bash
python server/main.py
```

2. Deploy the client agent on target systems.

## Security Notice
This framework is intended for educational purposes and security research only. Always obtain proper authorization before using this tool on any system.

## Features
- Secure communication channel
- Command execution
- File transfer capabilities
- Basic persistence mechanisms
- Modular architecture 