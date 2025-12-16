from dataclasses import dataclass
from datetime import datetime
from typing import Optional

@dataclass
class User:
    id: int
    username: str
    password_hash: str
    role: str
    public_key: str
    private_key: str
    created_at: str

@dataclass
class Document:
    id: int
    filename: str
    file_path: str
    file_hash: str
    encrypted_key: str
    owner_id: int
    uploaded_at: str
    is_encrypted: bool