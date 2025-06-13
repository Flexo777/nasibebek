from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from flask_socketio import SocketIO, emit, join_room, leave_room
from werkzeug.utils import secure_filename
from datetime import datetime
import os
from functools import wraps
import json
import uuid  # Import for unique filenames if you handle base64 uploads
import base64 # Import for base64 decoding if you handle base64 uploads

from app.storage import DatabaseManager

app = Flask(__name__)
# Ganti dengan kunci yang lebih kompleks di produksi! Pastikan ini aman dan rahasia.
app.secret_key = 'your_secret_key_should_be_more_complex_and_random'
app.config['UPLOAD_FOLDER'] = os.path.join('static', 'uploads')
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024 # 16 MB max upload size
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif', 'mp4', 'mov'}

# Pastikan folder uploads ada
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

db = DatabaseManager()

# Inisialisasi SocketIO
# Penting: cors_allowed_origins="*" hanya untuk development!
# Di produksi, ganti dengan domain frontend Anda (misal: "http://localhost:3000")
socketio = SocketIO(app, cors_allowed_origins="*")

# Dictionary untuk melacak SID (Socket ID) dari setiap user yang login
# Ini diperlukan untuk mengirim pesan ke user spesifik
user_sids = {}  # {user_id: [sid1, sid2, ...]} - satu user bisa punya banyak tab/device
sid_to_user_id = {}  # {sid: user_id}


# Helper Functions
def login_required(f):
    """Decorator untuk memastikan user sudah login."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please login to access this page.', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def allowed_file(filename):
    """Mengecek apakah ekstensi file diizinkan."""
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']


# --- Auth Routes ---
@app.route('/register', methods=['GET', 'POST'])
def register():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '').strip()

        if not all([username, email, password]):
            flash("All fields are required.", "error")
            return render_template('register.html')

        if len(password) < 6:
            flash("Password must be at least 6 characters.", "error")
            return render_template('register.html')

        if db.get_user_by_email(email):
            flash("Email already registered.", "error")
            return render_template('register.html')

        if db.get_user_by_username(username):
            flash("Username already taken.", "error")
            return render_template('register.html')

        try:
            db.add_user(username, email, password)
            flash("Registration successful. Please login.", "success")
            return redirect(url_for('login'))
        except Exception as e:
            flash("Registration failed. Please try again.", "error")
            print(f"Registration error: {str(e)}")

    return render_template('register.html')

@app.route('/', methods=['GET', 'POST'])
@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '').strip()

        user = db.get_user_by_email(email)
        if user and db.verify_password(user, password):
            session['user_id'] = user.id
            flash("Login successful!", "success")
            return redirect(url_for('dashboard'))

        flash("Invalid email or password.", "error")

    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    user_id = session.pop('user_id', None)
    if user_id:
        # Status online akan diupdate via Socket.IO 'disconnect' event
        pass
    flash("You have been logged out.", "info")
    return redirect(url_for('login'))


# --- Dashboard Routes ---
@app.route('/dashboard')
@login_required
def dashboard():
    current_user = db.get_user_by_id(session['user_id'])
    if not current_user:
        session.pop('user_id', None) # Clear session if user not found (e.g., deleted from DB)
        return redirect(url_for('login'))

    # Dapatkan daftar pengguna online kecuali pengguna saat ini
    online_users = [user for user in db.get_online_users()
                    if user.id != current_user.id]

    return render_template('dashboard.html',
                           current_user=current_user,
                           online_users=online_users)

# --- Chat Routes ---
@app.route('/chat/<int:partner_id>', methods=['GET'])
@login_required
def chat(partner_id):
    current_user = db.get_user_by_id(session['user_id'])
    partner = db.get_user_by_id(partner_id)

    if not partner:
        flash("User not found.", "error")
        return redirect(url_for('dashboard'))

    messages = []
    try:
        # Ambil pesan dari database
        raw_messages = db.get_conversation(current_user.id, partner.id)
        if raw_messages:
            for msg in raw_messages:
                # Konversi timestamp string ke objek datetime jika diperlukan untuk formatting di template
                if isinstance(msg['timestamp'], str):
                    try:
                        msg['timestamp'] = datetime.fromisoformat(msg['timestamp'])
                    except ValueError:
                        print(f"Warning: Could not parse timestamp '{msg['timestamp']}'")
                        pass # Biarkan saja jika tidak bisa diubah

                # Ambil nama pengirim untuk ditampilkan
                sender = db.get_user_by_id(msg['sender_id'])
                if sender:
                    msg['sender_name'] = sender.username
                else:
                    msg['sender_name'] = 'Unknown' # Fallback
                messages.append(msg)

    except Exception as e:
        print(f"Error getting messages from database: {str(e)}")
        flash("Error loading messages.", "error")

    return render_template('chat.html',
                           current_user=current_user,
                           partner=partner,
                           messages=messages)


# --- API Endpoint untuk Upload Media (Menggunakan REST API) ---
# Socket.IO tidak ideal untuk upload file besar, jadi kita pisahkan.
@app.route('/api/upload_media', methods=['POST'])
@login_required
def upload_media():
    if 'media' not in request.files:
        return jsonify({'success': False, 'error': 'No media file part'}), 400

    media_file = request.files['media']
    if media_file.filename == '':
        return jsonify({'success': False, 'error': 'No selected file'}), 400

    if media_file and allowed_file(media_file.filename):
        # Buat nama file unik untuk mencegah konflik
        filename = secure_filename(f"{datetime.now().timestamp()}_{media_file.filename}")
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        try:
            media_file.save(filepath)
            # Kembalikan path relatif agar bisa diakses dari frontend
            return jsonify({'success': True, 'filename': filename, 'filepath': url_for('static', filename=f'uploads/{filename}')}), 200
        except Exception as e:
            print(f"File upload error: {str(e)}")
            return jsonify({'success': False, 'error': 'Failed to upload file'}), 500
    else:
        return jsonify({'success': False, 'error': f"Invalid file type. Allowed types: {', '.join(app.config['ALLOWED_EXTENSIONS'])}"}), 400


# --- SOCKET.IO EVENT HANDLERS ---
@socketio.on('connect')
def handle_connect():
    """Menangani koneksi Socket.IO baru."""
    user_id = session.get('user_id')
    if user_id:
        print(f'User {user_id} connected with SID: {request.sid}')
        if user_id not in user_sids:
            user_sids[user_id] = []
        user_sids[user_id].append(request.sid)
        sid_to_user_id[request.sid] = user_id

        # Update status online di database (jika belum online)
        user = db.get_user_by_id(user_id)
        if user and not user.online:
            db.update_user_status(user_id, True)
            # Beri tahu semua klien bahwa user ini sekarang online
            socketio.emit('user_connected_status', {
                'user_id': user.id,
                'username': user.username
            }, broadcast=True)
    else:
        print(f'Anonymous client connected with SID: {request.sid}')


@socketio.on('disconnect')
def handle_disconnect():
    """Menangani pemutusan koneksi Socket.IO."""
    user_id = sid_to_user_id.get(request.sid)
    if user_id:
        print(f'User {user_id} disconnected from SID: {request.sid}')
        # Hapus SID dari daftar user_sids
        if user_id in user_sids:
            user_sids[user_id].remove(request.sid)
            if not user_sids[user_id]:  # Jika tidak ada SID lain untuk user ini
                del user_sids[user_id]
                # Update status offline di database
                db.update_user_status(user_id, False)
                # Beri tahu semua klien bahwa user ini sekarang offline
                user = db.get_user_by_id(user_id) # Ambil info user untuk broadcast
                if user:
                    socketio.emit('user_disconnected_status', {
                        'user_id': user.id,
                        'username': user.username
                    }, broadcast=True)
        del sid_to_user_id[request.sid]
    else:
        print(f'Anonymous client disconnected from SID: {request.sid}')


@socketio.on('user_online')
def handle_user_online(data):
    """
    Event ini dikirim dari dashboard.html untuk memastikan server tahu user ada di dashboard.
    Logika status online sebagian besar sudah ditangani oleh 'connect' event,
    tapi ini bisa jadi fallback atau untuk re-konfirmasi.
    """
    user_id = data.get('user_id')
    if user_id:
        user = db.get_user_by_id(user_id)
        if user and not user.online:
            db.update_user_status(user_id, True)
            socketio.emit('user_connected_status', {
                'user_id': user.id,
                'username': user.username
            }, broadcast=True)


@socketio.on('join_chat_room')
def handle_join_chat_room(data):
    """Memungkinkan klien untuk bergabung ke room chat spesifik."""
    current_user_id = data.get('user_id')
    partner_id = data.get('partner_id')

    if current_user_id and partner_id:
        room_name = get_conversation_room_name(current_user_id, partner_id)
        join_room(room_name)
        print(f"User {current_user_id} (SID: {request.sid}) joined room: {room_name}")


@socketio.on('send_message')
def handle_send_message(data):
    """Menangani pengiriman pesan dari klien."""
    sender_id = data.get('sender_id')
    receiver_id = data.get('receiver_id')
    message_type = data.get('message_type')
    content = data.get('content')
    file_data = data.get('file') # Jika frontend mengirim base64 langsung via Socket.IO

    # Validasi dasar data yang masuk
    if not all([sender_id, receiver_id, message_type]):
        return {'success': False, 'error': 'Missing message data'}

    sender = db.get_user_by_id(sender_id)
    receiver = db.get_user_by_id(receiver_id)

    if not sender or not receiver:
        return {'success': False, 'error': 'Sender or receiver not found'}

    # Menangani file media yang dikirim langsung via Socket.IO (base64)
    # Ini opsional, endpoint /api/upload_media lebih disarankan untuk file besar
    if message_type in ['image', 'video'] and file_data:
        try:
            # Contoh sederhana decoding base64 dan penyimpanan
            # Header contoh: 'data:image/png;base64,'
            header, encoded = file_data.split(",", 1)
            file_ext = header.split(';')[0].split('/')[1]
            decoded_file = base64.b64decode(encoded)
            unique_filename = f"{datetime.now().timestamp()}_{uuid.uuid4().hex}.{file_ext}"
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
            with open(filepath, 'wb') as f:
                f.write(decoded_file)
            content = unique_filename # Content sekarang adalah nama file yang tersimpan
        except Exception as e:
            print(f"Error decoding/saving file via Socket.IO: {e}")
            return {'success': False, 'error': 'Failed to process media file'}
    # Jika frontend mengupload duluan via REST, maka `content` sudah berupa filename
    # Tidak perlu ada `elif message_type in ['image', 'video'] and content:` di sini
    # karena `content` sudah akan berisi nama file yang benar dari frontend.

    try:
        timestamp = datetime.now().isoformat()
        # Simpan pesan ke database
        message_id = db.save_message(
            sender_id=sender_id,
            receiver_id=receiver_id,
            message_type=message_type,
            content=content, # content bisa berupa teks atau nama file
            timestamp=timestamp
        )

        # Buat objek pesan yang akan dikirim ke klien
        message_obj = {
            'id': message_id,
            'sender_id': sender_id,
            'sender_name': sender.username,
            'receiver_id': receiver_id,
            'receiver_name': receiver.username,
            'message_type': message_type,
            'content': content,
            'timestamp': timestamp # Kirim timestamp dalam format ISO string
        }

        # 1. Emit ke room chat (untuk semua klien yang sedang berada di percakapan ini)
        room_name = get_conversation_room_name(sender_id, receiver_id)
        socketio.emit('receive_message', message_obj, room=room_name)
        print(f"Message sent to chat room {room_name}: {message_obj}")

        # 2. Emit langsung ke SID penerima untuk notifikasi dashboard
        # Ini akan memastikan notifikasi sampai ke dashboard atau tab lain dari penerima
        if receiver_id in user_sids:
            for sid in user_sids[receiver_id]:
                # Hindari mengirim duplikat jika penerima sudah berada di room chat yang sama
                # dengan SID ini (misalnya, buka chat dan dashboard di tab terpisah)
                if sid not in socketio.rooms(sid):
                    print(f"Emitting notification to receiver {receiver_id} SID: {sid}")
                    emit('receive_message', message_obj, room=sid)
        # Jika receiver.online (di DB) tapi tidak di user_sids, artinya ada ketidaksesuaian.
        # Biasanya, user_sids harus selalu up-to-date jika connect/disconnect ditangani dengan benar.

        # Mengirim kembali ke pengirim sebagai konfirmasi (jika menggunakan callback di frontend)
        return {'success': True, 'message': message_obj}

    except Exception as e:
        print(f"Error sending message via Socket.IO: {str(e)}")
        return {'success': False, 'error': 'Failed to send message'}


@socketio.on('typing')
def handle_typing(data):
    """Menangani status mengetik dari klien."""
    user_id = data.get('user_id')
    username = data.get('username')
    partner_id = data.get('partner_id')
    is_typing = data.get('is_typing')

    if user_id and partner_id:
        room_name = get_conversation_room_name(user_id, partner_id)
        # Kirim status mengetik hanya ke partner yang sedang berbicara, kecuali pengirim itu sendiri
        socketio.emit('typing_status', {
            'user_id': user_id,
            'username': username,
            'is_typing': is_typing
        }, room=room_name, include_self=False)
        # print(f"Typing status from {username} ({user_id}) to {partner_id} in room {room_name}: {is_typing}")



def get_conversation_room_name(user1_id, user2_id):
    """Membuat nama room unik yang konsisten untuk kedua user."""
    # Pastikan nama room selalu sama, tidak peduli urutan user1_id dan user2_id
    if user1_id < user2_id:
        return f"chat_{user1_id}_{user2_id}"
    else:
        return f"chat_{user2_id}_{user1_id}"

# Menjalankan aplikasi Flask-SocketIO
if __name__ == '__main__':
    # Penting: Gunakan socketio.run(app) BUKAN app.run()
    # Ini akan menjalankan server Flask dan Socket.IO secara bersamaan
    socketio.run(app, debug=True, host='0.0.0.0', port=5000)