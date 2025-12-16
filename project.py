#!/usr/bin/env python3
"""
SDMS - Secure Document Management System (CLI)
Features:
- Register/login (SHA-256 password hashing)
- RSA key pair generation (wrap AES keys using RSA-OAEP)
- AES-GCM for file encryption
- SHA-256 for integrity verification
- Role-based access control (Admin/User)
- SQLite storage
"""

import os
import sys
import getpass
import sqlite3
import base64
import hashlib
import argparse
from typing import Optional
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2

DB_FILE = "sdms.db"

# Constants for KDF
KDF_SALT_BYTES = 16
KDF_ITER = 200_000  # PBKDF2 iterations
AES_KEY_BYTES = 32  # 256-bit AES key

# Database helper
def get_conn():
    return sqlite3.connect(DB_FILE)

def init_db():
    conn = get_conn()
    cur = conn.cursor()
    # users: username primary key, password_hash (sha256 hex), role, pubkey_pem, priv_encrypted (base64), priv_kdf_salt (base64)
    cur.execute("""
    CREATE TABLE IF NOT EXISTS users (
        username TEXT PRIMARY KEY,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL,
        pubkey_pem TEXT NOT NULL,
        priv_encrypted BLOB NOT NULL,
        priv_salt BLOB NOT NULL
    )
    """)
    # documents: id, owner, filename, ciphertext (blob), aes_nonce, aes_tag, sha256_hash (hex)
    cur.execute("""
    CREATE TABLE IF NOT EXISTS documents (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        owner TEXT NOT NULL,
        filename TEXT NOT NULL,
        ciphertext BLOB NOT NULL,
        aes_nonce BLOB NOT NULL,
        aes_tag BLOB NOT NULL,
        sha256 TEXT NOT NULL,
        FOREIGN KEY(owner) REFERENCES users(username)
    )
    """)
    # doc_shares: doc_id, recipient, wrapped_key (blob)
    cur.execute("""
    CREATE TABLE IF NOT EXISTS doc_shares (
        doc_id INTEGER NOT NULL,
        recipient TEXT NOT NULL,
        wrapped_key BLOB NOT NULL,
        PRIMARY KEY (doc_id, recipient),
        FOREIGN KEY(doc_id) REFERENCES documents(id),
        FOREIGN KEY(recipient) REFERENCES users(username)
    )
    """)
    conn.commit()
    conn.close()

# Utilities
def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def hash_password_sha256(password: str) -> str:
    return hashlib.sha256(password.encode('utf-8')).hexdigest()

def derive_key_from_password(password: str, salt: bytes, dklen=AES_KEY_BYTES) -> bytes:
    # PBKDF2 with SHA-256 to derive AES key to encrypt private key
    return PBKDF2(password.encode('utf-8'), salt, dkLen=dklen, count=KDF_ITER, hmac_hash_module=hashlib.sha256)

def encrypt_private_key_pem(priv_pem: bytes, password: str):
    salt = get_random_bytes(KDF_SALT_BYTES)
    key = derive_key_from_password(password, salt)
    # AES-GCM encrypt private key bytes
    cipher = AES.new(key, AES.MODE_GCM)
    ct, tag = cipher.encrypt_and_digest(priv_pem)
    # store nonce + tag + ct
    packed = cipher.nonce + tag + ct
    return packed, salt

def decrypt_private_key_pem(packed: bytes, password: str, salt: bytes) -> Optional[bytes]:
    key = derive_key_from_password(password, salt)
    try:
        nonce = packed[0:16]
        tag = packed[16:32]
        ct = packed[32:]
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        priv_pem = cipher.decrypt_and_verify(ct, tag)
        return priv_pem
    except Exception as e:
        return None

# User operations
def register(username: str, role: str):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT username FROM users WHERE username = ?", (username,))
    if cur.fetchone():
        print("Username already exists.")
        conn.close()
        return
    password = getpass.getpass("Create password: ")
    password2 = getpass.getpass("Confirm password: ")
    if password != password2:
        print("Passwords do not match.")
        conn.close()
        return
    # Hash password with SHA-256 (requirement)
    pwd_hash = hash_password_sha256(password)
    # Generate RSA key pair
    rsa_key = RSA.generate(2048)
    priv_pem = rsa_key.export_key(format='PEM')
    pub_pem = rsa_key.publickey().export_key(format='PEM')
    # Encrypt private key with password-derived AES key
    priv_encrypted, priv_salt = encrypt_private_key_pem(priv_pem, password)
    cur.execute("""
    INSERT INTO users (username, password_hash, role, pubkey_pem, priv_encrypted, priv_salt)
    VALUES (?, ?, ?, ?, ?, ?)
    """, (username, pwd_hash, role, pub_pem.decode('utf-8'), priv_encrypted, priv_salt))
    conn.commit()
    conn.close()
    print(f"User '{username}' registered with role '{role}' and RSA key pair generated.")

def login(username: str) -> Optional[dict]:
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT password_hash, role, pubkey_pem, priv_encrypted, priv_salt FROM users WHERE username = ?", (username,))
    row = cur.fetchone()
    conn.close()
    if not row:
        print("No such user.")
        return None
    stored_hash, role, pubkey_pem, priv_encrypted, priv_salt = row
    password = getpass.getpass("Password: ")
    if hash_password_sha256(password) != stored_hash:
        print("Incorrect password.")
        return None
    # decrypt private key
    priv_pem = decrypt_private_key_pem(priv_encrypted, password, priv_salt)
    if priv_pem is None:
        print("Failed to decrypt private key (wrong password or corrupted).")
        return None
    private_key = RSA.import_key(priv_pem)
    public_key = RSA.import_key(pubkey_pem.encode('utf-8'))
    print(f"Logged in as {username} ({role}).")
    return {"username": username, "role": role, "private_key": private_key, "public_key": public_key, "password": password}

# Document operations
def encrypt_and_store_document(owner: str, priv: RSA.RsaKey, pub: RSA.RsaKey, filepath: str):
    if not os.path.exists(filepath):
        print("File does not exist.")
        return
    with open(filepath, "rb") as f:
        plaintext = f.read()
    plaintext_hash = sha256_hex(plaintext)
    # generate random AES key
    aes_key = get_random_bytes(AES_KEY_BYTES)
    cipher = AES.new(aes_key, AES.MODE_GCM)
    ct, tag = cipher.encrypt_and_digest(plaintext)
    nonce = cipher.nonce
    # Wrap AES key with owner's public RSA key (so owner can unwrap)
    rsa_pub = pub
    rsa_cipher = PKCS1_OAEP.new(rsa_pub, hashAlgo=hashlib.sha256)
    wrapped_key = rsa_cipher.encrypt(aes_key)
    # Store document and wrapped key for owner
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("""
    INSERT INTO documents (owner, filename, ciphertext, aes_nonce, aes_tag, sha256)
    VALUES (?, ?, ?, ?, ?, ?)
    """, (owner, os.path.basename(filepath), ct, nonce, tag, plaintext_hash))
    doc_id = cur.lastrowid
    # store wrapped key in doc_shares for owner
    cur.execute("INSERT INTO doc_shares (doc_id, recipient, wrapped_key) VALUES (?, ?, ?)", (doc_id, owner, wrapped_key))
    conn.commit()
    conn.close()
    print(f"Document stored with id {doc_id} and filename {os.path.basename(filepath)}. SHA-256: {plaintext_hash}")

def list_documents_for_user(current):
    conn = get_conn()
    cur = conn.cursor()
    username = current['username']
    role = current['role']
    if role.lower() == "admin":
        cur.execute("SELECT id, owner, filename, sha256 FROM documents")
    else:
        # show docs owned or shared with user
        cur.execute("""
        SELECT d.id, d.owner, d.filename, d.sha256
        FROM documents d
        JOIN doc_shares s ON d.id = s.doc_id
        WHERE s.recipient = ?
        """, (username,))
    rows = cur.fetchall()
    conn.close()
    if not rows:
        print("No documents available.")
        return
    print("Documents:")
    for r in rows:
        print(f" - id={r[0]} owner={r[1]} filename={r[2]} sha256={r[3]}")

def share_document(current, doc_id: int, recipient: str):
    conn = get_conn()
    cur = conn.cursor()
    # verify recipient exists
    cur.execute("SELECT pubkey_pem FROM users WHERE username = ?", (recipient,))
    row = cur.fetchone()
    if not row:
        print("Recipient does not exist.")
        conn.close()
        return
    recipient_pub_pem = row[0].encode('utf-8')
    # check doc exists
    cur.execute("SELECT id FROM documents WHERE id = ?", (doc_id,))
    if not cur.fetchone():
        print("Document not found.")
        conn.close()
        return
    # ensure current user is owner or admin
    cur.execute("SELECT owner FROM documents WHERE id = ?", (doc_id,))
    owner = cur.fetchone()[0]
    if current['username'] != owner and current['role'].lower() != "admin":
        print("Only document owner or admin can share this document.")
        conn.close()
        return
    # retrieve the AES key wrapped for owner (or any existing wrapped for someone the current user can unwrap)
    # We'll find a wrapped_key for the current user (owner) so we can unwrap AES key and then rewrap for recipient.
    cur.execute("SELECT wrapped_key FROM doc_shares WHERE doc_id = ? AND recipient = ?", (doc_id, owner))
    row = cur.fetchone()
    if not row:
        print("No wrapped key available to unwrap (unexpected).")
        conn.close()
        return
    wrapped_for_owner = row[0]
    # unwrap using current user's private key (must be owner)
    try:
        rsa_priv = current['private_key']
        rsa_dec = PKCS1_OAEP.new(rsa_priv, hashAlgo=hashlib.sha256)
        aes_key = rsa_dec.decrypt(wrapped_for_owner)
    except Exception as e:
        print("Failed to unwrap AES key with your private key.")
        conn.close()
        return
    # re-wrap AES key with recipient's public key
    recipient_pub = RSA.import_key(recipient_pub_pem)
    rsa_enc = PKCS1_OAEP.new(recipient_pub, hashAlgo=hashlib.sha256)
    wrapped_for_recipient = rsa_enc.encrypt(aes_key)
    # insert or replace share
    cur.execute("REPLACE INTO doc_shares (doc_id, recipient, wrapped_key) VALUES (?, ?, ?)", (doc_id, recipient, wrapped_for_recipient))
    conn.commit()
    conn.close()
    print(f"Document {doc_id} shared with {recipient}.")

def download_document(current, doc_id: int, out_path: Optional[str] = None):
    conn = get_conn()
    cur = conn.cursor()
    # find wrapped key for this user
    cur.execute("SELECT wrapped_key FROM doc_shares WHERE doc_id = ? AND recipient = ?", (doc_id, current['username']))
    row = cur.fetchone()
    if not row:
        print("You do not have access to this document or it has not been shared with you.")
        conn.close()
        return
    wrapped_key = row[0]
    # retrieve ciphertext and metadata
    cur.execute("SELECT filename, ciphertext, aes_nonce, aes_tag, sha256 FROM documents WHERE id = ?", (doc_id,))
    r = cur.fetchone()
    conn.close()
    if not r:
        print("Document not found.")
        return
    filename, ct, nonce, tag, sha256_stored = r
    # unwrap AES key with user's private RSA
    try:
        rsa_priv = current['private_key']
        rsa_dec = PKCS1_OAEP.new(rsa_priv, hashAlgo=hashlib.sha256)
        aes_key = rsa_dec.decrypt(wrapped_key)
    except Exception as e:
        print("Failed to unwrap AES key with your private key.")
        return
    # decrypt ciphertext
    try:
        cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
        plaintext = cipher.decrypt_and_verify(ct, tag)
    except Exception as e:
        print("AES decryption or verification failed:", str(e))
        return
    # verify sha256
    computed = sha256_hex(plaintext)
    if computed != sha256_stored:
        print("Integrity check failed: SHA-256 mismatch.")
        return
    # write file
    out_file = out_path if out_path else f"download_{doc_id}_{filename}"
    with open(out_file, "wb") as f:
        f.write(plaintext)
    print(f"Document {doc_id} downloaded to {out_file}. SHA-256 verified.")

def delete_document(current, doc_id: int):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT owner FROM documents WHERE id = ?", (doc_id,))
    row = cur.fetchone()
    if not row:
        print("Document not found.")
        conn.close()
        return
    owner = row[0]
    if current['username'] != owner and current['role'].lower() != "admin":
        print("Only owner or admin can delete document.")
        conn.close()
        return
    cur.execute("DELETE FROM doc_shares WHERE doc_id = ?", (doc_id,))
    cur.execute("DELETE FROM documents WHERE id = ?", (doc_id,))
    conn.commit()
    conn.close()
    print(f"Document {doc_id} deleted.")

# Admin user management
def make_admin(current, username: str):
    if current['role'].lower() != "admin":
        print("Only admin can change roles.")
        return
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT username FROM users WHERE username = ?", (username,))
    if not cur.fetchone():
        print("User not found.")
        conn.close()
        return
    cur.execute("UPDATE users SET role = 'Admin' WHERE username = ?", (username,))
    conn.commit()
    conn.close()
    print(f"User {username} promoted to Admin.")

def revoke_admin(current, username: str):
    if current['role'].lower() != "admin":
        print("Only admin can change roles.")
        return
    if username == current['username']:
        print("Cannot demote yourself.")
        return
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT username FROM users WHERE username = ?", (username,))
    if not cur.fetchone():
        print("User not found.")
        conn.close()
        return
    cur.execute("UPDATE users SET role = 'User' WHERE username = ?", (username,))
    conn.commit()
    conn.close()
    print(f"User {username} demoted to User.")

# CLI loop
def interactive_shell(current):
    print("\nEnter 'help' for commands. 'exit' to logout.")
    while True:
        cmd = input(f"{current['username']}> ").strip()
        if not cmd:
            continue
        parts = cmd.split()
        cmd0 = parts[0].lower()
        try:
            if cmd0 == "help":
                print_commands(current)
            elif cmd0 == "upload":
                if len(parts) < 2:
                    print("Usage: upload <filepath>")
                else:
                    encrypt_and_store_document(current['username'], current['private_key'], current['public_key'], parts[1])
            elif cmd0 == "list":
                list_documents_for_user(current)
            elif cmd0 == "share":
                if len(parts) < 3:
                    print("Usage: share <doc_id> <recipient_username>")
                else:
                    share_document(current, int(parts[1]), parts[2])
            elif cmd0 == "download":
                if len(parts) < 2:
                    print("Usage: download <doc_id> [out_path]")
                else:
                    out = parts[2] if len(parts) >= 3 else None
                    download_document(current, int(parts[1]), out)
            elif cmd0 == "delete":
                if len(parts) < 2:
                    print("Usage: delete <doc_id>")
                else:
                    delete_document(current, int(parts[1]))
            elif cmd0 == "promote":
                if len(parts) < 2:
                    print("Usage: promote <username>")
                else:
                    make_admin(current, parts[1])
            elif cmd0 == "demote":
                if len(parts) < 2:
                    print("Usage: demote <username>")
                else:
                    revoke_admin(current, parts[1])
            elif cmd0 == "whoami":
                print(f"{current['username']} ({current['role']})")
            elif cmd0 in ("exit", "logout", "quit"):
                print("Logging out.")
                break
            else:
                print("Unknown command. Type 'help'.")
        except Exception as e:
            print("Error:", e)

def print_commands(current):
    common = [
        "upload <filepath>                    - Upload & encrypt a file",
        "list                                 - List accessible documents",
        "share <doc_id> <username>            - Share a document with a user (owner or admin)",
        "download <doc_id> [out_path]         - Download & decrypt a document",
        "delete <doc_id>                      - Delete a document (owner/admin)",
        "whoami                               - Show current user",
        "help                                 - Show this help",
        "exit                                 - Logout"
    ]
    print("Available commands:")
    for c in common:
        print("  " + c)
    if current['role'].lower() == "admin":
        print("\nAdmin commands:")
        print("  promote <username>                   - Make user admin")
        print("  demote <username>                    - Demote user to User")

# CLI entry
def main():
    init_db()
    parser = argparse.ArgumentParser(description="SDMS - Secure Document Management System (CLI)")
    parser.add_argument("--init-admin", action="store_true", help="Create initial admin user interactively")
    args = parser.parse_args()

    if args.init_admin:
        print("Create initial admin user")
        uname = input("Username: ").strip()
        if not uname:
            print("Username required.")
            return
        register(uname, "Admin")
        return

    print("SDMS CLI\nType 'register' to create user, 'login' to sign in, 'exit' to quit.")
    while True:
        try:
            cmd = input("> ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nBye.")
            return
        if not cmd:
            continue
        parts = cmd.split()
        action = parts[0].lower()
        if action == "register":
            if len(parts) >= 3:
                uname = parts[1]
                role = parts[2]
            else:
                uname = input("Username: ").strip()
                role = input("Role (Admin/User) [User]: ").strip() or "User"
            register(uname, role)
        elif action == "login":
            uname = parts[1] if len(parts) >= 2 else input("Username: ").strip()
            current = login(uname)
            if current:
                interactive_shell(current)
        elif action in ("exit", "quit"):
            print("Goodbye.")
            return
        else:
            print("Unknown command. Use 'register', 'login', or 'exit'.")

if __name__ == "__main__":
    main()
