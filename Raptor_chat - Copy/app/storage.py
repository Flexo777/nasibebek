import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime

DB_NAME = 'chatapp.db'

class User:
    """Class representasi objek User dari database."""
    def __init__(self, id, username, email, password, online):
        self.id = id
        self.username = username
        self.email = email
        self.password = password
        self.online = bool(online) # Pastikan online adalah boolean

    def __repr__(self):
        return f"<User {self.username} (ID: {self.id}) Online: {self.online}>"

class DatabaseManager:
    """Manajer untuk interaksi dengan database SQLite."""
    def __init__(self):
        self.db_name = DB_NAME
        self.create_tables()

    def create_tables(self):
        """Membuat tabel users dan messages jika belum ada."""
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()
        cursor.execute('''CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE, -- Tambahkan UNIQUE untuk username juga
            email TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL,
            online INTEGER NOT NULL DEFAULT 0 -- Default 0 (offline)
        )''')
        cursor.execute('''CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender_id INTEGER NOT NULL,
            receiver_id INTEGER NOT NULL,
            message_type TEXT NOT NULL, -- e.g., 'text', 'image', 'video'
            content TEXT, -- Bisa teks pesan atau nama file
            timestamp TEXT NOT NULL, -- Simpan sebagai ISO format string
            FOREIGN KEY (sender_id) REFERENCES users(id) ON DELETE CASCADE, -- Jika user dihapus, pesan juga dihapus
            FOREIGN KEY (receiver_id) REFERENCES users(id) ON DELETE CASCADE
        )''')
        conn.commit()
        conn.close()

    def add_user(self, username, email, password):
        """Menambahkan user baru ke database."""
        hashed_password = generate_password_hash(password)
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()
        cursor.execute('''
        INSERT INTO users (username, email, password, online)
        VALUES (?, ?, ?, ?)
        ''', (username, email, hashed_password, 0)) # Default online status 0 saat register
        conn.commit()
        conn.close()

    def get_user_by_username(self, username):
        """Mencari user berdasarkan username."""
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()
        cursor.execute('SELECT id, username, email, password, online FROM users WHERE username = ?', (username,))
        user_data = cursor.fetchone()
        conn.close()
        if user_data:
            return User(id=user_data[0], username=user_data[1], email=user_data[2], password=user_data[3], online=user_data[4])
        return None

    def get_user_by_email(self, email):
        """Mencari user berdasarkan email."""
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()
        cursor.execute('SELECT id, username, email, password, online FROM users WHERE email = ?', (email,))
        user_data = cursor.fetchone()
        conn.close()
        if user_data:
            return User(id=user_data[0], username=user_data[1], email=user_data[2], password=user_data[3], online=user_data[4])
        return None

    def get_user_by_id(self, user_id):
        """Mencari user berdasarkan ID."""
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()
        cursor.execute('SELECT id, username, email, password, online FROM users WHERE id = ?', (user_id,))
        user_data = cursor.fetchone()
        conn.close()
        if user_data:
            return User(id=user_data[0], username=user_data[1], email=user_data[2], password=user_data[3], online=user_data[4])
        return None

    def verify_password(self, user, password):
        """Memverifikasi password user."""
        return check_password_hash(user.password, password)

    def update_user_status(self, user_id, online):
        """Mengupdate status online user (True/False)."""
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()
        cursor.execute('UPDATE users SET online = ? WHERE id = ?', (int(online), user_id)) # Konversi boolean ke integer
        conn.commit()
        conn.close()

    def save_message(self, sender_id, receiver_id, message_type, content, timestamp):
        """Menyimpan pesan baru ke database."""
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()
        cursor.execute('''
        INSERT INTO messages (sender_id, receiver_id, message_type, content, timestamp)
        VALUES (?, ?, ?, ?, ?)
        ''', (sender_id, receiver_id, message_type, content, timestamp))
        conn.commit()
        return cursor.lastrowid # Mengembalikan ID pesan yang baru saja disimpan

    def get_conversation(self, user1_id, user2_id):
        """Mengambil semua pesan antara dua user, diurutkan berdasarkan timestamp."""
        conn = sqlite3.connect(self.db_name)
        conn.row_factory = sqlite3.Row # Mengembalikan baris sebagai objek mirip dict
        cursor = conn.cursor()
        query = '''
        SELECT id, sender_id, receiver_id, message_type, content, timestamp
        FROM messages
        WHERE (sender_id = ? AND receiver_id = ?)
        OR (sender_id = ? AND receiver_id = ?)
        ORDER BY timestamp ASC
        '''
        cursor.execute(query, (user1_id, user2_id, user2_id, user1_id))
        messages = cursor.fetchall()
        conn.close()
        # Mengubah hasil fetchall menjadi list of dictionaries
        return [dict(m) for m in messages]

    def get_online_users(self):
        """Mengambil daftar semua user yang sedang online."""
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()
        cursor.execute('SELECT id, username, email, password, online FROM users WHERE online = 1')
        users_data = cursor.fetchall()
        conn.close()
        return [User(id=u[0], username=u[1], email=u[2], password=u[3], online=u[4]) for u in users_data]