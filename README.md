<div align="center">

# 🔐 SecureVault DMS

### A Robust Secure Document Management System with Military-Grade Encryption

[![Python](https://img.shields.io/badge/Python-3.8+-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![SQLite](https://img.shields.io/badge/SQLite-Database-003B57?style=for-the-badge&logo=sqlite&logoColor=white)](https://sqlite.org/)
[![Cryptography](https://img.shields.io/badge/AES--256-Encrypted-00D084?style=for-the-badge&logo=letsencrypt&logoColor=white)](https://cryptography.io/)
[![RSA](https://img.shields.io/badge/RSA--2048-Secured-FF6B6B?style=for-the-badge&logo=security&logoColor=white)](https://en.wikipedia.org/wiki/RSA_(cryptosystem))

<p align="center">
  <em>Enterprise-grade document security with hybrid encryption, role-based access control, and secure file sharing — all from your command line.</em>
</p>

---

</div>

## 📋 Table of Contents

- [Overview](#-overview)
- [Features](#-features)
- [Security Architecture](#-security-architecture)
- [Installation](#-installation)
- [Usage](#-usage)
- [Project Structure](#-project-structure)
- [Technical Details](#-technical-details)
- [Screenshots](#-screenshots)
- [Contributing](#-contributing)
- [License](#-license)

---

## 🌟 Overview

**SecureVault DMS** is a command-line Secure Document Management System designed for information security applications. It implements a comprehensive security model combining symmetric and asymmetric encryption to provide confidentiality, integrity verification, and secure document sharing between users.

Built as a demonstration of modern cryptographic practices, this system showcases:
- **Hybrid Encryption** — AES-256 for data + RSA-2048 for key exchange
- **Zero-Knowledge Architecture** — Documents are encrypted client-side before storage
- **Integrity Verification** — SHA-256 hashing ensures document authenticity

---

## ✨ Features

### 🔒 Security Features
| Feature | Description |
|---------|-------------|
| **AES-256 Encryption** | Documents are encrypted using AES-256 in CBC mode with random IVs |
| **RSA-2048 Key Pairs** | Each user gets a unique RSA key pair for secure key exchange |
| **SHA-256 Hashing** | Password hashing and file integrity verification |
| **Hybrid Encryption** | Combines speed of symmetric encryption with security of asymmetric |

### 👥 User Management
| Feature | Description |
|---------|-------------|
| **User Registration** | Secure user registration with password hashing |
| **Authentication** | Session-based authentication system |
| **Role-Based Access** | User and Admin roles with different privileges |
| **RSA Key Generation** | Automatic key pair generation on registration |

### 📄 Document Management
| Feature | Description |
|---------|-------------|
| **Secure Upload** | Encrypt and upload any file type |
| **Secure Download** | Decrypt and verify file integrity on download |
| **Document Sharing** | Share encrypted documents with other users |
| **Integrity Verification** | Automatic hash verification on download |

### 🛡️ Admin Capabilities
- View all registered users
- View all documents in the system
- Delete any document (admin override)

---

## 🏗️ Security Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         SECUREVAULT DMS ARCHITECTURE                        │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌──────────────────┐     ┌──────────────────┐     ┌──────────────────┐    │
│  │   User Input     │────▶│  Authentication  │────▶│  Authorization   │    │
│  │  (CLI Interface) │     │  (SHA-256 Hash)  │     │  (RBAC System)   │    │
│  └──────────────────┘     └──────────────────┘     └──────────────────┘    │
│                                                              │              │
│                                                              ▼              │
│  ┌──────────────────────────────────────────────────────────────────────┐  │
│  │                        ENCRYPTION PIPELINE                           │  │
│  │  ┌─────────────┐     ┌─────────────┐     ┌─────────────────────────┐ │  │
│  │  │  Document   │────▶│  AES-256    │────▶│   RSA-2048 Encrypted   │ │  │
│  │  │  (Plaintext)│     │  Encryption │     │   AES Key + IV + Data  │ │  │
│  │  └─────────────┘     └─────────────┘     └─────────────────────────┘ │  │
│  └──────────────────────────────────────────────────────────────────────┘  │
│                                                              │              │
│                                                              ▼              │
│  ┌──────────────────┐     ┌──────────────────┐     ┌──────────────────┐    │
│  │  SQLite Database │◀────│  Metadata Store  │◀────│ Encrypted Files  │    │
│  │  (Users, Docs)   │     │  (Hashes, Keys)  │     │  (uploads/ dir)  │    │
│  └──────────────────┘     └──────────────────┘     └──────────────────┘    │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Encryption Flow

1. **Upload Process:**
   ```
   Document → Generate AES-256 Key → Encrypt with AES-CBC → 
   Encrypt AES Key with User's RSA Public Key → Store Encrypted Data + Metadata
   ```

2. **Download Process:**
   ```
   Retrieve Encrypted Data → Decrypt AES Key with RSA Private Key → 
   Decrypt Document with AES → Verify SHA-256 Hash → Output Decrypted File
   ```

3. **Sharing Process:**
   ```
   Decrypt AES Key (Owner's Private Key) → Re-encrypt AES Key (Target's Public Key) → 
   Create Share Record → Target User Can Now Decrypt
   ```

---

## 🚀 Installation

### Prerequisites
- Python 3.8 or higher
- pip (Python package manager)

### Quick Start

```bash
# Clone the repository
git clone https://github.com/khizer-flow/securevault-dms.git
cd securevault-dms

# Create virtual environment (recommended)
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install cryptography pycryptodome

# Run the application
python main.py
```

### Dependencies
```
cryptography==41.0.7
pycryptodome==3.19.0
```

---

## 💻 Usage

### Starting the Application
```bash
python main.py
```

### Main Menu (Unauthenticated)
```
==================================================
    SECURE DOCUMENT MANAGEMENT SYSTEM
==================================================
1. Register
2. Login
3. Exit
```

### Document Operations (Authenticated)
```
==================================================
    SECURE DOCUMENT MANAGEMENT SYSTEM
==================================================
Welcome, johndoe (user)

--- DOCUMENT MANAGEMENT ---
1. Upload Document
2. Download Document
3. List My Documents
4. List Shared Documents
5. Share Document
6. Delete Document

--- ACCOUNT ---
9. Logout
0. Exit
```

### Example Workflow

```bash
# 1. Register a new user
> Choose: 1 (Register)
> Username: alice
> Password: ********
> Register as admin? (y/N): n
✅ User registered successfully!

# 2. Login
> Choose: 2 (Login)
> Username: alice
> Password: ********
✅ Login successful! Welcome alice (user)

# 3. Upload a document
> Choose: 1 (Upload Document)
> Enter file path: /path/to/secret-report.pdf
✅ Document 'secret-report.pdf' uploaded and encrypted successfully!

# 4. Share with another user
> Choose: 5 (Share Document)
> Enter document ID: 1
> Enter target username: bob
✅ Document shared successfully with bob!
```

---

## 📁 Project Structure

```
securevault-dms/
├── 📄 main.py              # CLI interface and main application loop
├── 🔐 crypto.py            # Cryptographic operations (AES, RSA, SHA-256)
├── 👤 auth.py              # User authentication and session management
├── 📂 document_manager.py  # Document CRUD operations and sharing
├── 💾 database.py          # SQLite database initialization and queries
├── 📦 models.py            # Data models (User, Document)
├── 📋 requirements.txt     # Python dependencies
├── 📁 uploads/             # Encrypted document storage
└── 📖 README.md            # This file
```

### Module Responsibilities

| Module | Purpose |
|--------|---------|
| `main.py` | Entry point, CLI menu, user interaction handling |
| `crypto.py` | All cryptographic operations including encryption/decryption |
| `auth.py` | User registration, login, session management, RBAC |
| `document_manager.py` | File upload, download, sharing, and deletion |
| `database.py` | SQLite database schema and query operations |
| `models.py` | Dataclass definitions for User and Document entities |

---

## 🔧 Technical Details

### Cryptographic Specifications

| Algorithm | Purpose | Key Size |
|-----------|---------|----------|
| AES-256-CBC | Document encryption | 256-bit |
| RSA-OAEP | Key encryption/exchange | 2048-bit |
| SHA-256 | Password hashing, file integrity | 256-bit |

### Database Schema

```sql
-- Users Table
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'user',
    public_key TEXT NOT NULL,
    private_key TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Documents Table
CREATE TABLE documents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    filename TEXT NOT NULL,
    file_path TEXT NOT NULL,
    file_hash TEXT NOT NULL,
    encrypted_key TEXT NOT NULL,
    owner_id INTEGER NOT NULL,
    uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    is_encrypted BOOLEAN DEFAULT TRUE,
    FOREIGN KEY (owner_id) REFERENCES users(id)
);

-- Document Shares Table
CREATE TABLE document_shares (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    document_id INTEGER NOT NULL,
    shared_with_user_id INTEGER NOT NULL,
    shared_by_user_id INTEGER NOT NULL,
    shared_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (document_id) REFERENCES documents(id),
    UNIQUE (document_id, shared_with_user_id)
);
```

### Security Considerations

> ⚠️ **Note**: This is an educational/demonstration project. For production use, consider:
> - Storing private keys in a hardware security module (HSM)
> - Implementing proper key derivation functions (Argon2, bcrypt) instead of raw SHA-256 for passwords
> - Adding audit logging and rate limiting
> - Implementing secure key backup and recovery mechanisms

---

## 📸 Screenshots

### Registration & Login
```
🚀 Secure Document Management System Started!

==================================================
    SECURE DOCUMENT MANAGEMENT SYSTEM
==================================================
1. Register
2. Login
3. Exit

Enter your choice: 1

--- USER REGISTRATION ---
Username: alice
Password: ********
Confirm Password: ********
Register as admin? (y/N): n
✅ User registered successfully!
```

### Document Management
```
==================================================
    SECURE DOCUMENT MANAGEMENT SYSTEM
==================================================
Welcome, alice (user)

--- DOCUMENT MANAGEMENT ---
1. Upload Document
2. Download Document
3. List My Documents
4. List Shared Documents
5. Share Document
6. Delete Document

--- ACCOUNT ---
9. Logout
0. Exit

Enter your choice: 3

--- MY DOCUMENTS ---
ID: 1, Filename: confidential-report.pdf, Uploaded: 2024-12-17 00:00:00
ID: 2, Filename: project-plans.docx, Uploaded: 2024-12-17 00:05:00
```

---

## 🤝 Contributing

Contributions are welcome! Here's how you can help:

1. **Fork** the repository
2. **Create** a feature branch (`git checkout -b feature/amazing-feature`)
3. **Commit** your changes (`git commit -m 'Add amazing feature'`)
4. **Push** to the branch (`git push origin feature/amazing-feature`)
5. **Open** a Pull Request

### Ideas for Improvements
- [ ] Web-based interface (Flask/Django)
- [ ] Multi-factor authentication (TOTP)
- [ ] Document versioning
- [ ] Encrypted search functionality
- [ ] Audit logging system
- [ ] API for programmatic access

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 👨‍💻 Author

**Name**
- GitHub: [@khizer-flow](https://github.com/khizer-flow)

---

<div align="center">

### ⭐ Star this repository if you found it helpful!

<p>
  <strong>Built with 🔐 by security enthusiasts, for security enthusiasts</strong>
</p>

</div>
