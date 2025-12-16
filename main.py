#!/usr/bin/env python3
import sys
import os
import getpass
from database import Database
from auth import AuthManager
from document_manager import DocumentManager


class SDMS_CLI:
    def __init__(self):
        self.db = Database()
        self.auth_manager = AuthManager(self.db)
        self.doc_manager = DocumentManager(self.db, self.auth_manager)
        self.running = True

    def print_menu(self):
        """Print main menu"""
        print("\n" + "=" * 50)
        print("    SECURE DOCUMENT MANAGEMENT SYSTEM")
        print("=" * 50)

        if not self.auth_manager.is_authenticated():
            print("1. Register")
            print("2. Login")
            print("3. Exit")
        else:
            user = self.auth_manager.get_current_user()
            print(f"Welcome, {user.username} ({user.role})")
            print("\n--- DOCUMENT MANAGEMENT ---")
            print("1. Upload Document")
            print("2. Download Document")
            print("3. List My Documents")
            print("4. List Shared Documents")
            print("5. Share Document")
            print("6. Delete Document")

            if self.auth_manager.is_admin():
                print("\n--- ADMIN FUNCTIONS ---")
                print("7. List All Users")
                print("8. List All Documents")

            print("\n--- ACCOUNT ---")
            print("9. Logout")
            print("0. Exit")

    def handle_register(self):
        """Handle user registration"""
        print("\n--- USER REGISTRATION ---")
        username = input("Username: ").strip()
        password = getpass.getpass("Password: ")
        confirm_password = getpass.getpass("Confirm Password: ")

        if password != confirm_password:
            print("❌ Passwords don't match!")
            return

        role = "user"
        if input("Register as admin? (y/N): ").lower() == 'y':
            # In real system, this would require special admin token
            role = "admin"

        self.auth_manager.register_user(username, password, role)

    def handle_login(self):
        """Handle user login"""
        print("\n--- USER LOGIN ---")
        username = input("Username: ").strip()
        password = getpass.getpass("Password: ")
        self.auth_manager.login(username, password)

    def handle_upload(self):
        """Handle document upload"""
        print("\n--- UPLOAD DOCUMENT ---")
        file_path = input("Enter file path: ").strip()
        self.doc_manager.upload_document(file_path)

    def handle_download(self):
        """Handle document download"""
        print("\n--- DOWNLOAD DOCUMENT ---")
        doc_id = input("Enter document ID: ").strip()
        output_path = input("Enter output path: ").strip()

        if not doc_id.isdigit():
            print("❌ Invalid document ID!")
            return

        self.doc_manager.download_document(int(doc_id), output_path)

    def handle_list_my_documents(self):
        """List user's documents"""
        print("\n--- MY DOCUMENTS ---")
        documents = self.doc_manager.list_my_documents()

        if not documents:
            print("No documents found.")
            return

        for doc in documents:
            print(f"ID: {doc.id}, Filename: {doc.filename}, Uploaded: {doc.uploaded_at}")

    def handle_list_shared_documents(self):
        """List shared documents"""
        print("\n--- SHARED DOCUMENTS ---")
        documents = self.doc_manager.list_shared_documents()

        if not documents:
            print("No shared documents found.")
            return

        for doc in documents:
            print(f"ID: {doc.id}, Filename: {doc.filename}, Uploaded: {doc.uploaded_at}")

    def handle_share(self):
        """Handle document sharing"""
        print("\n--- SHARE DOCUMENT ---")
        doc_id = input("Enter document ID: ").strip()
        target_user = input("Enter target username: ").strip()

        if not doc_id.isdigit():
            print("❌ Invalid document ID!")
            return

        self.doc_manager.share_document(int(doc_id), target_user)

    def handle_delete(self):
        """Handle document deletion"""
        print("\n--- DELETE DOCUMENT ---")
        doc_id = input("Enter document ID: ").strip()

        if not doc_id.isdigit():
            print("❌ Invalid document ID!")
            return

        self.doc_manager.delete_document(int(doc_id))

    def handle_list_all_users(self):
        """List all users (admin only)"""
        if not self.auth_manager.is_admin():
            print("❌ Admin access required!")
            return

        print("\n--- ALL USERS ---")
        users = self.db.fetch_all("SELECT id, username, role, created_at FROM users")

        for user in users:
            print(f"ID: {user[0]}, Username: {user[1]}, Role: {user[2]}, Created: {user[3]}")

    def handle_list_all_documents(self):
        """List all documents (admin only)"""
        if not self.auth_manager.is_admin():
            print("❌ Admin access required!")
            return

        print("\n--- ALL DOCUMENTS ---")
        docs = self.db.fetch_all(
            "SELECT d.id, d.filename, u.username, d.uploaded_at FROM documents d JOIN users u ON d.owner_id = u.id"
        )

        for doc in docs:
            print(f"ID: {doc[0]}, Filename: {doc[1]}, Owner: {doc[2]}, Uploaded: {doc[3]}")

    def run(self):
        """Main application loop"""
        print("🚀 Secure Document Management System Started!")

        while self.running:
            try:
                self.print_menu()
                choice = input("\nEnter your choice: ").strip()

                if not self.auth_manager.is_authenticated():
                    if choice == '1':
                        self.handle_register()
                    elif choice == '2':
                        self.handle_login()
                    elif choice == '3':
                        print("👋 Goodbye!")
                        self.running = False
                    else:
                        print("❌ Invalid choice!")

                else:
                    if choice == '1':
                        self.handle_upload()
                    elif choice == '2':
                        self.handle_download()
                    elif choice == '3':
                        self.handle_list_my_documents()
                    elif choice == '4':
                        self.handle_list_shared_documents()
                    elif choice == '5':
                        self.handle_share()
                    elif choice == '6':
                        self.handle_delete()
                    elif choice == '7' and self.auth_manager.is_admin():
                        self.handle_list_all_users()
                    elif choice == '8' and self.auth_manager.is_admin():
                        self.handle_list_all_documents()
                    elif choice == '9':
                        self.auth_manager.logout()
                    elif choice == '0':
                        print("👋 Goodbye!")
                        self.running = False
                    else:
                        print("❌ Invalid choice!")

            except KeyboardInterrupt:
                print("\n\n👋 Goodbye!")
                self.running = False
            except Exception as e:
                print(f"❌ An error occurred: {e}")


if __name__ == "__main__":
    cli = SDMS_CLI()
    cli.run()