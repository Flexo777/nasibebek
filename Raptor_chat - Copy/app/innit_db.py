import sqlite3

# Nama database
DB_NAME = 'chatapp.db'

# Fungsi untuk membuat tabel
def init_db():
    # Membuat koneksi ke database SQLite
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    # Membuat tabel pengguna (users)
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL,
        email TEXT NOT NULL UNIQUE,
        online BOOLEAN NOT NULL
    )
    ''')
    
    # Membuat tabel pesan (messages)
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        sender_id INTEGER NOT NULL,
        receiver_id INTEGER NOT NULL,
        message_type TEXT NOT NULL,
        content TEXT NOT NULL,
        timestamp TEXT NOT NULL,
        FOREIGN KEY (sender_id) REFERENCES users(id),
        FOREIGN KEY (receiver_id) REFERENCES users(id)
    )
    ''')

    # Menyimpan perubahan dan menutup koneksi
    conn.commit()
    conn.close()

# Memanggil fungsi untuk menginisialisasi database
if __name__ == '__main__':
    init_db()
    print("Database initialized successfully.")
