## 3. database.py

import sqlite3
import os
from typing import Optional, List, Tuple


class Database:
    def __init__(self, db_path: str = "secure_dms.db"):
        self.db_path = db_path
        self.init_database()

    def init_database(self):
        """Initialize database with required tables"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # Users table
        cursor.execute('''
                       CREATE TABLE IF NOT EXISTS users
                       (
                           id
                           INTEGER
                           PRIMARY
                           KEY
                           AUTOINCREMENT,
                           username
                           TEXT
                           UNIQUE
                           NOT
                           NULL,
                           password_hash
                           TEXT
                           NOT
                           NULL,
                           role
                           TEXT
                           NOT
                           NULL
                           DEFAULT
                           'user',
                           public_key
                           TEXT
                           NOT
                           NULL,
                           private_key
                           TEXT
                           NOT
                           NULL,
                           created_at
                           TIMESTAMP
                           DEFAULT
                           CURRENT_TIMESTAMP
                       )
                       ''')

        # Documents table
        cursor.execute('''
                       CREATE TABLE IF NOT EXISTS documents
                       (
                           id
                           INTEGER
                           PRIMARY
                           KEY
                           AUTOINCREMENT,
                           filename
                           TEXT
                           NOT
                           NULL,
                           file_path
                           TEXT
                           NOT
                           NULL,
                           file_hash
                           TEXT
                           NOT
                           NULL,
                           encrypted_key
                           TEXT
                           NOT
                           NULL,
                           owner_id
                           INTEGER
                           NOT
                           NULL,
                           uploaded_at
                           TIMESTAMP
                           DEFAULT
                           CURRENT_TIMESTAMP,
                           is_encrypted
                           BOOLEAN
                           DEFAULT
                           TRUE,
                           FOREIGN
                           KEY
                       (
                           owner_id
                       ) REFERENCES users
                       (
                           id
                       )
                           )
                       ''')

        # Document sharing table
        cursor.execute('''
                       CREATE TABLE IF NOT EXISTS document_shares
                       (
                           id
                           INTEGER
                           PRIMARY
                           KEY
                           AUTOINCREMENT,
                           document_id
                           INTEGER
                           NOT
                           NULL,
                           shared_with_user_id
                           INTEGER
                           NOT
                           NULL,
                           shared_by_user_id
                           INTEGER
                           NOT
                           NULL,
                           shared_at
                           TIMESTAMP
                           DEFAULT
                           CURRENT_TIMESTAMP,
                           FOREIGN
                           KEY
                       (
                           document_id
                       ) REFERENCES documents
                       (
                           id
                       ),
                           FOREIGN KEY
                       (
                           shared_with_user_id
                       ) REFERENCES users
                       (
                           id
                       ),
                           FOREIGN KEY
                       (
                           shared_by_user_id
                       ) REFERENCES users
                       (
                           id
                       ),
                           UNIQUE
                       (
                           document_id,
                           shared_with_user_id
                       )
                           )
                       ''')

        conn.commit()
        conn.close()

    def execute_query(self, query: str, params: tuple = ()) -> sqlite3.Cursor:
        """Execute a query and return cursor"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute(query, params)
        conn.commit()
        return cursor

    def fetch_one(self, query: str, params: tuple = ()) -> Optional[tuple]:
        """Fetch single record"""
        cursor = self.execute_query(query, params)
        result = cursor.fetchone()
        cursor.connection.close()
        return result

    def fetch_all(self, query: str, params: tuple = ()) -> List[tuple]:
        """Fetch all records"""
        cursor = self.execute_query(query, params)
        result = cursor.fetchall()
        cursor.connection.close()
        return result