import sqlite3
import bcrypt
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import base64
import os
import json
from datetime import datetime 

class DatabaseManager:
    def __init__(self, db_path='chatapp.db'):
        self.db_path = db_path
        self.create_tables()
        self.master_key = self._get_or_generate_master_key()

    def _get_or_generate_master_key(self):
        key_file = 'master_key.key'
        if os.path.exists(key_file):
            with open(key_file, 'rb') as f:
                key = f.read()
        else:
            key = Fernet.generate_key()
            with open(key_file, 'wb') as f:
                f.write(key)
        return Fernet(key)

    def _encrypt_private_key(self, private_key_pem):
        return self.master_key.encrypt(private_key_pem)

    def _decrypt_private_key(self, encrypted_private_key):
        try:
            return self.master_key.decrypt(encrypted_private_key)
        except Exception as e:
            print(f"Error decrypting private key with master key: {e}")
            return None

    def create_tables(self):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL UNIQUE,
                    email TEXT NOT NULL UNIQUE,
                    password_hash TEXT NOT NULL,
                    public_key_pem BLOB,
                    encrypted_private_key_pem BLOB,
                    online BOOLEAN DEFAULT 0
                )
            ''')
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS messages (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    sender_id INTEGER NOT NULL,
                    receiver_id INTEGER NOT NULL,
                    message_type TEXT NOT NULL,
                    content_encrypted TEXT NOT NULL,
                    aes_key_encrypted TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    plain_content_for_sender TEXT, 
                    FOREIGN KEY (sender_id) REFERENCES users (id),
                    FOREIGN KEY (receiver_id) REFERENCES users (id)
                )
            ''')
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS notifications (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    receiver_id INTEGER NOT NULL,
                    sender_id INTEGER NOT NULL,
                    message_id INTEGER DEFAULT NULL, 
                    notification_type TEXT NOT NULL, 
                    content TEXT NOT NULL, 
                    is_read BOOLEAN DEFAULT 0,
                    timestamp TEXT NOT NULL,
                    FOREIGN KEY (receiver_id) REFERENCES users (id),
                    FOREIGN KEY (sender_id) REFERENCES users (id),
                    FOREIGN KEY (message_id) REFERENCES messages (id)
                )
            ''')
            conn.commit()

    def add_user(self, username, email, password): 
        password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)",
                (username, email, password_hash)
            )
            conn.commit()
            return cursor.lastrowid

    def get_user_by_email(self, email):
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM users WHERE email = ?", (email,))
            return cursor.fetchone()

    def get_user_by_username(self, username):
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
            return cursor.fetchone()

    def get_user_by_id(self, user_id):
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
            return cursor.fetchone()

    def verify_password(self, user, password):
        return bcrypt.checkpw(password.encode('utf-8'), user['password_hash'].encode('utf-8'))

    def update_user_status(self, user_id, online_status):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("UPDATE users SET online = ? WHERE id = ?", (online_status, user_id))
            conn.commit()

    def get_online_users(self):
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute("SELECT id, username, email, online FROM users WHERE online = 1")
            return cursor.fetchall()

    def save_user_keys(self, user_id, public_key_pem, private_key_pem):
        encrypted_private_key = self._encrypt_private_key(private_key_pem)
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                "UPDATE users SET public_key_pem = ?, encrypted_private_key_pem = ? WHERE id = ?",
                (public_key_pem, encrypted_private_key, user_id)
            )
            conn.commit()

    def get_user_public_key(self, user_id):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT public_key_pem FROM users WHERE id = ?", (user_id,))
            result = cursor.fetchone()
            return result[0] if result else None

    def get_user_private_key(self, user_id):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT encrypted_private_key_pem FROM users WHERE id = ?", (user_id,))
            result = cursor.fetchone()
            if result and result[0]:
                return self._decrypt_private_key(result[0])
            return None

    def save_message(self, sender_id, receiver_id, message_type, content_encrypted, aes_key_encrypted, timestamp, plain_content_for_sender):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                """INSERT INTO messages (sender_id, receiver_id, message_type, content_encrypted, aes_key_encrypted, timestamp, plain_content_for_sender)
                VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (sender_id, receiver_id, message_type, content_encrypted, aes_key_encrypted, timestamp, plain_content_for_sender)
            )
            conn.commit()
            return cursor.lastrowid

    def get_conversation(self, user1_id, user2_id):
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute(
                """SELECT * FROM messages
                WHERE (sender_id = ? AND receiver_id = ?) OR (sender_id = ? AND receiver_id = ?)
                ORDER BY timestamp ASC""",
                (user1_id, user2_id, user2_id, user1_id)
            )
            return cursor.fetchall()
    
    def add_notification(self, receiver_id, sender_id, notification_type, content, message_id=None):
        """Adds a new notification to the database."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            timestamp = datetime.now().isoformat()
            cursor.execute(
                """INSERT INTO notifications (receiver_id, sender_id, message_id, notification_type, content, timestamp)
                VALUES (?, ?, ?, ?, ?, ?)""",
                (receiver_id, sender_id, message_id, notification_type, content, timestamp)
            )
            conn.commit()
            return cursor.lastrowid

    def get_unread_notifications(self, user_id):
        """Fetches all unread notifications for a given user, including sender details."""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute(
                """SELECT 
                    n.id, 
                    n.receiver_id, 
                    n.sender_id, 
                    n.message_id, 
                    n.notification_type, 
                    n.content, 
                    n.is_read, 
                    n.timestamp,
                    s.username AS sender_username
                FROM notifications n
                JOIN users s ON n.sender_id = s.id
                WHERE n.receiver_id = ? AND n.is_read = 0
                ORDER BY n.timestamp DESC""",
                (user_id,)
            )
            return cursor.fetchall()

    def mark_notification_as_read(self, notification_id):
        """Marks a specific notification as read."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("UPDATE notifications SET is_read = 1 WHERE id = ?", (notification_id,))
            conn.commit()

    def mark_all_notifications_as_read(self, user_id):
        """Marks all unread notifications for a user as read."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("UPDATE notifications SET is_read = 1 WHERE receiver_id = ? AND is_read = 0", (user_id,))
            conn.commit()
    
    def mark_all_notifications_as_read_from_sender(self, receiver_id, sender_id):
        """Marks all unread notifications from a specific sender for a given receiver as read."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                "UPDATE notifications SET is_read = 1 WHERE receiver_id = ? AND sender_id = ? AND is_read = 0", 
                (receiver_id, sender_id)
            )
            conn.commit()
