# OpenDatacenter

OpenDatacenter is a secure, multi-user platform for running isolated computational workloads. It provides a sandboxed environment where users can securely execute code, store encrypted data, and manage their own isolated instances.

## Key Features

- **User Isolation**: Each user gets their own isolated environment
- **Secure Execution**: QEMU-based sandboxing for all workloads
- **Data Encryption**: Individual encryption keys for each user
- **Automatic Scaling**: Dynamic instance management based on activity
- **Access Control**: Secure authentication and session management

## Requirements

- Linux environment
- Python 3.8+
- QEMU
- OpenSSL

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/OpenDatacenter.git
   cd OpenDatacenter
   ```

2. Run the setup script:
   ```bash
   chmod +x setup.sh
   ./setup.sh
   ```

3. Start the system:
   ```bash
   chmod +x main.sh
   ./main.sh
   ```

## Usage

### User Registration
```bash
curl -X POST https://localhost:8443/register \
  -H "Content-Type: application/json" \
  -d '{"username": "testuser", "password": "securepassword"}'
```

### User Login
```bash
curl -X POST https://localhost:8443/login \
  -H "Content-Type: application/json" \
  -d '{"username": "testuser", "password": "securepassword"}'
```

### File Upload
```bash
curl -X POST https://localhost:8443/upload \
  -H "X-User: testuser" \
  -H "X-Key: <encryption_key>" \
  -F "file=@/path/to/file"
```

### Script Execution
```bash
curl -X POST https://localhost:8443/execute \
  -H "X-User: testuser" \
  -H "X-Key: <encryption_key>" \
  -F "script=@/path/to/script"
```

## Security Features

- Individual encryption keys per user
- Secure password hashing with scrypt
- SSL/TLS encrypted communications
- Automatic session timeout
- Process isolation through QEMU
- Strict file permissions

## Maintenance

The system automatically:
- Creates new instances for active users
- Cleans up inactive sessions after 15 minutes
- Maintains activity logs in `instance_logs/`

## License

OpenDatacenter is released under the MIT License. See LICENSE file for details.

## Contributing

Contributions are welcome! Please read our [contribution guidelines](CONTRIBUTING.md) before submitting pull requests.

## Support

For support and questions, please open an issue in the GitHub repository.
