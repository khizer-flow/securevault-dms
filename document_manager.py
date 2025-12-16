import os
import shutil
from database import Database
from crypto import CryptoManager
from models import Document
from typing import List, Optional


class DocumentManager:
    def __init__(self, db: Database, auth_manager):
        self.db = db
        self.auth_manager = auth_manager
        self.upload_dir = "uploads"
        self.ensure_upload_dir()

    def ensure_upload_dir(self):
        """Create upload directory if it doesn't exist"""
        if not os.path.exists(self.upload_dir):
            os.makedirs(self.upload_dir)

    def upload_document(self, file_path: str) -> bool:
        """Upload and encrypt a document"""
        if not self.auth_manager.is_authenticated():
            print("❌ Please login first!")
            return False

        try:
            if not os.path.exists(file_path):
                print("❌ File not found!")
                return False

            # Generate AES key
            aes_key = CryptoManager.generate_aes_key()

            # Read file content
            with open(file_path, 'rb') as f:
                file_content = f.read()

            # Encrypt file content
            encrypted_content, iv = CryptoManager.encrypt_with_aes(file_content, aes_key)

            # Encrypt AES key with user's public key
            user = self.auth_manager.get_current_user()
            encrypted_aes_key = CryptoManager.encrypt_with_rsa(aes_key, user.public_key)

            # Save encrypted file
            filename = os.path.basename(file_path)
            encrypted_filename = f"encrypted_{filename}"
            encrypted_file_path = os.path.join(self.upload_dir, encrypted_filename)

            with open(encrypted_file_path, 'wb') as f:
                f.write(iv + encrypted_content)

            # Calculate file hash
            file_hash = CryptoManager.calculate_file_hash(file_path)

            # Store document metadata in database
            self.db.execute_query(
                '''INSERT INTO documents
                       (filename, file_path, file_hash, encrypted_key, owner_id, is_encrypted)
                   VALUES (?, ?, ?, ?, ?, ?)''',
                (filename, encrypted_file_path, file_hash,
                 encrypted_aes_key.hex(), user.id, True)
            )

            print(f"✅ Document '{filename}' uploaded and encrypted successfully!")
            return True

        except Exception as e:
            print(f"❌ Upload failed: {e}")
            return False

    def download_document(self, doc_id: int, output_path: str) -> bool:
        """Download and decrypt a document"""
        if not self.auth_manager.is_authenticated():
            print("❌ Please login first!")
            return False

        try:
            user = self.auth_manager.get_current_user()

            # Check if user has access to document
            doc_data = self.db.fetch_one(
                '''SELECT d.*
                   FROM documents d
                            LEFT JOIN document_shares ds ON d.id = ds.document_id
                   WHERE d.id = ?
                     AND (d.owner_id = ? OR ds.shared_with_user_id = ?)''',
                (doc_id, user.id, user.id)
            )

            if not doc_data:
                print("❌ Document not found or access denied!")
                return False

            document = Document(
                id=doc_data[0],
                filename=doc_data[1],
                file_path=doc_data[2],
                file_hash=doc_data[3],
                encrypted_key=doc_data[4],
                owner_id=doc_data[5],
                uploaded_at=doc_data[6],
                is_encrypted=doc_data[7]
            )

            if not document.is_encrypted:
                # Copy file directly if not encrypted
                shutil.copy2(document.file_path, output_path)
            else:
                # Decrypt AES key
                encrypted_aes_key = bytes.fromhex(document.encrypted_key)
                aes_key = CryptoManager.decrypt_with_rsa(encrypted_aes_key, user.private_key)

                # Read encrypted file
                with open(document.file_path, 'rb') as f:
                    file_data = f.read()

                # Extract IV and encrypted content
                iv = file_data[:16]
                encrypted_content = file_data[16:]

                # Decrypt content
                decrypted_content = CryptoManager.decrypt_with_aes(
                    encrypted_content, aes_key, iv
                )

                # Save decrypted file
                with open(output_path, 'wb') as f:
                    f.write(decrypted_content)

            # Verify integrity
            if CryptoManager.verify_file_integrity(output_path, document.file_hash):
                print(f"✅ Document downloaded successfully to {output_path}")
                return True
            else:
                print("❌ File integrity check failed!")
                os.remove(output_path)
                return False

        except Exception as e:
            print(f"❌ Download failed: {e}")
            return False

    def list_my_documents(self) -> List[Document]:
        """List documents owned by current user"""
        if not self.auth_manager.is_authenticated():
            return []

        user = self.auth_manager.get_current_user()
        docs_data = self.db.fetch_all(
            "SELECT * FROM documents WHERE owner_id = ? ORDER BY uploaded_at DESC",
            (user.id,)
        )

        documents = []
        for doc_data in docs_data:
            documents.append(Document(
                id=doc_data[0],
                filename=doc_data[1],
                file_path=doc_data[2],
                file_hash=doc_data[3],
                encrypted_key=doc_data[4],
                owner_id=doc_data[5],
                uploaded_at=doc_data[6],
                is_encrypted=doc_data[7]
            ))

        return documents

    def list_shared_documents(self) -> List[Document]:
        """List documents shared with current user"""
        if not self.auth_manager.is_authenticated():
            return []

        user = self.auth_manager.get_current_user()
        docs_data = self.db.fetch_all(
            '''SELECT d.*
               FROM documents d
                        JOIN document_shares ds ON d.id = ds.document_id
               WHERE ds.shared_with_user_id = ?
               ORDER BY ds.shared_at DESC''',
            (user.id,)
        )

        documents = []
        for doc_data in docs_data:
            documents.append(Document(
                id=doc_data[0],
                filename=doc_data[1],
                file_path=doc_data[2],
                file_hash=doc_data[3],
                encrypted_key=doc_data[4],
                owner_id=doc_data[5],
                uploaded_at=doc_data[6],
                is_encrypted=doc_data[7]
            ))

        return documents

    def share_document(self, doc_id: int, target_username: str) -> bool:
        """Share document with another user"""
        if not self.auth_manager.is_authenticated():
            print("❌ Please login first!")
            return False

        try:
            user = self.auth_manager.get_current_user()

            # Verify document ownership
            doc_data = self.db.fetch_one(
                "SELECT * FROM documents WHERE id = ? AND owner_id = ?",
                (doc_id, user.id)
            )

            if not doc_data:
                print("❌ Document not found or you don't own this document!")
                return False

            # Get target user
            target_user_data = self.db.fetch_one(
                "SELECT id, public_key FROM users WHERE username = ?",
                (target_username,)
            )

            if not target_user_data:
                print("❌ Target user not found!")
                return False

            target_user_id, target_public_key = target_user_data

            # Re-encrypt AES key with target user's public key
            encrypted_aes_key = bytes.fromhex(doc_data[4])
            aes_key = CryptoManager.decrypt_with_rsa(encrypted_aes_key, user.private_key)
            re_encrypted_aes_key = CryptoManager.encrypt_with_rsa(aes_key, target_public_key)

            # Update document with new encrypted key for sharing
            self.db.execute_query(
                "UPDATE documents SET encrypted_key = ? WHERE id = ?",
                (re_encrypted_aes_key.hex(), doc_id)
            )

            # Create share record
            self.db.execute_query(
                "INSERT INTO document_shares (document_id, shared_with_user_id, shared_by_user_id) VALUES (?, ?, ?)",
                (doc_id, target_user_id, user.id)
            )

            print(f"✅ Document shared successfully with {target_username}!")
            return True

        except Exception as e:
            print(f"❌ Sharing failed: {e}")
            return False

    def delete_document(self, doc_id: int) -> bool:
        """Delete a document"""
        if not self.auth_manager.is_authenticated():
            print("❌ Please login first!")
            return False

        try:
            user = self.auth_manager.get_current_user()

            # Verify document ownership or admin rights
            if user.role == "admin":
                doc_data = self.db.fetch_one(
                    "SELECT file_path FROM documents WHERE id = ?",
                    (doc_id,)
                )
            else:
                doc_data = self.db.fetch_one(
                    "SELECT file_path FROM documents WHERE id = ? AND owner_id = ?",
                    (doc_id, user.id)
                )

            if not doc_data:
                print("❌ Document not found or access denied!")
                return False

            # Delete file
            file_path = doc_data[0]
            if os.path.exists(file_path):
                os.remove(file_path)

            # Delete database records
            self.db.execute_query("DELETE FROM document_shares WHERE document_id = ?", (doc_id,))
            self.db.execute_query("DELETE FROM documents WHERE id = ?", (doc_id,))

            print("✅ Document deleted successfully!")
            return True

        except Exception as e:
            print(f"❌ Deletion failed: {e}")
            return False