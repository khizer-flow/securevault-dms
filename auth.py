from database import Database
from crypto import CryptoManager
from models import User
import getpass


class AuthManager:
    def __init__(self, db: Database):
        self.db = db
        self.current_user = None

    def register_user(self, username: str, password: str, role: str = "user") -> bool:
        """Register a new user"""
        try:
            # Check if username exists
            existing_user = self.db.fetch_one(
                "SELECT id FROM users WHERE username = ?", (username,)
            )
            if existing_user:
                print("❌ Username already exists!")
                return False

            # Hash password
            password_hash = CryptoManager.hash_password(password)

            # Generate RSA key pair
            private_key, public_key = CryptoManager.generate_rsa_keypair()

            # Insert user into database
            self.db.execute_query(
                "INSERT INTO users (username, password_hash, role, public_key, private_key) VALUES (?, ?, ?, ?, ?)",
                (username, password_hash, role, public_key, private_key)
            )

            print("✅ User registered successfully!")
            return True

        except Exception as e:
            print(f"❌ Registration failed: {e}")
            return False

    def login(self, username: str, password: str) -> bool:
        """Authenticate user"""
        try:
            # Get user from database
            user_data = self.db.fetch_one(
                "SELECT id, username, password_hash, role, public_key, private_key, created_at FROM users WHERE username = ?",
                (username,)
            )

            if not user_data:
                print("❌ User not found!")
                return False

            # Verify password
            password_hash = CryptoManager.hash_password(password)
            if user_data[2] != password_hash:
                print("❌ Invalid password!")
                return False

            # Create user object
            self.current_user = User(
                id=user_data[0],
                username=user_data[1],
                password_hash=user_data[2],
                role=user_data[3],
                public_key=user_data[4],
                private_key=user_data[5],
                created_at=user_data[6]
            )

            print(f"✅ Login successful! Welcome {username} ({self.current_user.role})")
            return True

        except Exception as e:
            print(f"❌ Login failed: {e}")
            return False

    def logout(self):
        """Logout current user"""
        self.current_user = None
        print("✅ Logged out successfully!")

    def is_authenticated(self) -> bool:
        """Check if user is authenticated"""
        return self.current_user is not None

    def is_admin(self) -> bool:
        """Check if current user is admin"""
        return self.is_authenticated() and self.current_user.role == "admin"

    def get_current_user(self) -> User:
        """Get current user object"""
        return self.current_user