from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from flask_socketio import SocketIO, emit, join_room, leave_room
from werkzeug.utils import secure_filename
from datetime import datetime
import os
from functools import wraps
import json
import uuid
import re
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
import base64
import traceback

from app.storage import DatabaseManager

app = Flask(__name__)
app.secret_key = 'your_secret_key_should_be_more_complex_and_random' 
app.config['UPLOAD_FOLDER'] = os.path.join('static', 'uploads')
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024 
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif', 'mp4', 'mov'}

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

db = DatabaseManager()

socketio = SocketIO(app, cors_allowed_origins="*") 

user_sids = {} 
sid_to_user_id = {} 

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please login to access this page.', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

@app.route('/register', methods=['GET', 'POST'])
def register():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '').strip()
        

        
        context = {
            'username': username,
            'email': email,
            
        }

       
        if not all([username, email, password]): 
            flash("All fields are required.", "error")
            return render_template('register.html', **context)
        
        
        password_regex = r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()_+={}\[\]|\\:;\"'<>,.?/~`-])[A-Za-z\d!@#$%^&*()_+={}\[\]|\\:;\"'<>,.?/~`-]{8,}$"

        if not re.match(password_regex, password):
            flash("Password must be at least 8 characters long and include at least one uppercase letter, one lowercase letter, one digit, and one special character (e.g., !@#$%^&*).", "error")
            return render_template('register.html', **context)
        
        
        if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
            flash('Invalid email address format.', 'error')
            return render_template('register.html', **context)

        if db.get_user_by_email(email):
            flash("Email already registered.", "error")
            return render_template('register.html', **context)

        if db.get_user_by_username(username):
            flash("Username already taken.", "error")
            return render_template('register.html', **context)

        try:
            
            user_id = db.add_user(username, email, password)

            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
                backend=default_backend()
            )
            public_key = private_key.public_key()

            private_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption() 
            )
            public_pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )

            db.save_user_keys(user_id, public_pem, private_pem)

            flash("Registration successful. Please login.", "success")
            return redirect(url_for('login'))
        except Exception as e:
            flash(f"Registration failed. Error: {str(e)}", "error")
            traceback.print_exc()
            print(f"Registration error: {str(e)}")
            return render_template('register.html', **context)

   
    return render_template('register.html', username='', email='')

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
            session['user_id'] = user['id'] 
            flash("Login successful!", "success")
            return redirect(url_for('dashboard'))

        flash("Invalid email or password.", "error")

    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    user_id = session.pop('user_id', None)
    if user_id:
        db.update_user_status(user_id, False) 
        
        user = db.get_user_by_id(user_id)
        if user:
            socketio.emit('user_disconnected_status', {
                'user_id': user['id'],
                'username': user['username']
            })

    flash("You have been logged out.", "info")
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    current_user = db.get_user_by_id(session['user_id'])
    if not current_user:
        session.pop('user_id', None)
        flash("Your user account was not found. Please login again.", "error")
        return redirect(url_for('login'))

    online_users = [user for user in db.get_online_users()
                    if user['id'] != current_user['id']]
    
    
    unread_notifications = db.get_unread_notifications(current_user['id'])
    
    notifications_data = []
    for notif in unread_notifications:
        notifications_data.append({
            'id': notif['id'],
            'sender_id': notif['sender_id'],
            'sender_name': notif['sender_username'], 
            'content': notif['content'],
            'timestamp': notif['timestamp']
        })
    
    return render_template('dashboard.html',
                           current_user=current_user,
                           online_users=online_users,
                           notifications=notifications_data) 

@app.route('/chat/<int:partner_id>', methods=['GET'])
@login_required
def chat(partner_id):
    current_user = db.get_user_by_id(session['user_id'])
    partner = db.get_user_by_id(partner_id)

    if not current_user:
        session.pop('user_id', None)
        flash("Your user account was not found. Please login again.", "error")
        return redirect(url_for('login'))

    if not partner:
        flash("User not found.", "error")
        return redirect(url_for('dashboard'))

    messages = []
    try:
        raw_messages = db.get_conversation(current_user['id'], partner['id'])

        current_user_private_key_pem = db.get_user_private_key(current_user['id'])
        print(f"\n--- DEBUG CHAT: Loading messages for User {current_user['id']} ---")
        print(f"DEBUG CHAT: Private key PEM for current user retrieved: {'YES' if current_user_private_key_pem else 'NO'}")

        if not current_user_private_key_pem:
            flash("Error: Your private key is not available. Cannot decrypt messages. Master key mismatch?", "error")
            print(f"ERROR main: Private key for user {current_user['id']} not found or failed to decrypt from DB.")
            return render_template('chat.html', current_user=current_user, partner=partner, messages=[])

        current_user_private_key = serialization.load_pem_private_key(
            current_user_private_key_pem,
            password=None,
            backend=default_backend()
        )
        print(f"DEBUG CHAT: Private key for user {current_user['id']} successfully loaded.")

        if raw_messages:
            for raw_msg in raw_messages: 
                msg = dict(raw_msg) 

                if isinstance(msg['timestamp'], str):
                    try:
                        msg['timestamp'] = datetime.fromisoformat(msg['timestamp'])
                    except ValueError:
                        print(f"Warning: Could not parse timestamp '{msg['timestamp']}' for message ID {msg['id']}")
                        pass

                sender_user = db.get_user_by_id(msg['sender_id'])
                if sender_user:
                    msg['sender_name'] = sender_user['username']
                else:
                    msg['sender_name'] = 'Unknown'

                if msg['sender_id'] == current_user['id']:
                    print(f"DEBUG main: Message ID {msg['id']} sent by current user. Using stored plaintext.")
                    msg['content'] = msg['plain_content_for_sender']
                    messages.append(msg)
                    continue

                try:
                    print(f"\n--- DEBUG main: Processing message ID: {msg['id']} from {msg.get('sender_name')} for decryption ---")
                    print(f"DEBUG main: Current user private key loaded for decryption: {'YES' if current_user_private_key_pem else 'NO'}")

                    print(f"DEBUG main: Encrypted AES key (b64) for msg {msg['id']}: {msg['aes_key_encrypted'][:50]}...")
                    encrypted_aes_key_bytes = base64.b64decode(msg['aes_key_encrypted'])
                    print(f"DEBUG main: Encrypted AES key (bytes) length: {len(encrypted_aes_key_bytes)} bytes.")

                    decrypted_aes_key = current_user_private_key.decrypt(
                        encrypted_aes_key_bytes,
                        padding.OAEP(
                            mgf=padding.MGF1(algorithm=hashes.SHA256()),
                            algorithm=hashes.SHA256(),
                            label=None
                        )
                    )
                    print(f"DEBUG main: AES key for msg {msg['id']} successfully decrypted. Length: {len(decrypted_aes_key)} bytes.")

                    if len(decrypted_aes_key) != 32:
                        print(f"ERROR CHAT: Decrypted AES key for msg {msg['id']} has INCORRECT length: {len(decrypted_aes_key)} bytes (expected 32). This is a critical mismatch.")
                        raise ValueError(f"Decrypted AES key has incorrect length: {len(decrypted_aes_key)} bytes. Expected 32 bytes.")

                    encoded_aes_key_for_fernet = base64.urlsafe_b64encode(decrypted_aes_key)
                    print(f"DEBUG main: Re-encoded AES key length for Fernet: {len(encoded_aes_key_for_fernet)} bytes. (Expected 44)")

                    aes_cipher_dec = Fernet(encoded_aes_key_for_fernet)
                    print(f"DEBUG main: Attempting to decrypt content for msg {msg['id']}. Encrypted content starts with: {msg['content_encrypted'][:50]}...")
                    decrypted_content_bytes = aes_cipher_dec.decrypt(msg['content_encrypted'].encode())
                    msg['content'] = decrypted_content_bytes.decode()
                    print(f"DEBUG main: Content for msg {msg['id']} successfully decrypted. Content starts with: {msg['content'][:50]}...")
                    print(f"--- DEBUG main: Message ID {msg['id']} processed. ---")

                except Exception as dec_e:
                    msg['content'] = "[Failed to decrypt message]"
                    print(f"ERROR main: Decryption failed for message ID {msg['id']}. Reason: {str(dec_e)}")
                    traceback.print_exc()

                messages.append(msg)

    except Exception as e:
        print(f"ERROR: General error loading or processing messages from database: {str(e)}")
        traceback.print_exc()
        flash("Error loading messages.", "error")

    return render_template('chat.html',
                           current_user=current_user,
                           partner=partner,
                           messages=messages)

@app.route('/api/upload_media', methods=['POST'])
@login_required
def upload_media():
    if 'media' not in request.files:
        return jsonify({'success': False, 'error': 'No media file part'}), 400

    media_file = request.files['media']
    if media_file.filename == '':
        return jsonify({'success': False, 'error': 'No selected file'}), 400

    if media_file and allowed_file(media_file.filename):
        filename = secure_filename(f"{datetime.now().timestamp()}_{media_file.filename}")
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        try:
            media_file.save(filepath)
            return jsonify({'success': True, 'filename': filename, 'filepath': url_for('static', filename=f'uploads/{filename}')}), 200
        except Exception as e:
            print(f"File upload error: {str(e)}")
            return jsonify({'success': False, 'error': 'Failed to upload file'}), 500
    else:
        return jsonify({'success': False, 'error': f"Invalid file type. Allowed types: {', '.join(app.config['ALLOWED_EXTENSIONS'])}"}), 400

@socketio.on('connect')
def handle_connect(): 
    user_id = session.get('user_id')
    if user_id:
        print(f'User {user_id} connected with SID: {request.sid}')
        if user_id not in user_sids:
            user_sids[user_id] = []
        user_sids[user_id].append(request.sid)
        sid_to_user_id[request.sid] = user_id

        user = db.get_user_by_id(user_id)
        if user and not user['online']:
            db.update_user_status(user['id'], True)
            socketio.emit('user_connected_status', {
                'user_id': user['id'],
                'username': user['username']
            }, broadcast=True)
    else:
        print(f'Anonymous client connected with SID: {request.sid}')

@socketio.on('disconnect')
def handle_disconnect(): 
    user_id = sid_to_user_id.get(request.sid)
    if user_id:
        print(f'User {user_id} disconnected from SID: {request.sid}')
        if user_id in user_sids:
            user_sids[user_id].remove(request.sid)
            if not user_sids[user_id]:
                del user_sids[user_id]
                db.update_user_status(user_id, False)
                user = db.get_user_by_id(user_id)
                if user:
                    socketio.emit('user_disconnected_status', {
                        'user_id': user['id'],
                        'username': user['username']
                    }, broadcast=True)
            del sid_to_user_id[request.sid]
        else:
            print(f'SID {request.sid} found in sid_to_user_id but not in user_sids. Clean up needed.')
            del sid_to_user_id[request.sid]
    else:
        print(f'Anonymous client disconnected from SID: {request.sid}')

@socketio.on('user_online')
def handle_user_online(data):
    user_id = data.get('user_id')
    if user_id:
        user = db.get_user_by_id(user_id)
        if user and not user['online']:
            db.update_user_status(user['id'], True)
            socketio.emit('user_connected_status', {
                'user_id': user['id'],
                'username': user['username']
            }, broadcast=True)

@socketio.on('join_chat_room')
def handle_join_chat_room(data):
    current_user_id = data.get('user_id')
    partner_id = data.get('partner_id')

    if current_user_id and partner_id:
        room_name = get_conversation_room_name(current_user_id, partner_id)
        join_room(room_name)
        print(f"User {current_user_id} (SID: {request.sid}) joined room: {room_name}")
        
        
        db.mark_all_notifications_as_read_from_sender(current_user_id, partner_id)
        
        emit('notifications_updated', {'user_id': current_user_id})


@socketio.on('send_message')
def handle_send_message(data):
    sender_id = data.get('sender_id')
    receiver_id = data.get('receiver_id')
    message_type = data.get('message_type')
    content = data.get('content') 
    file_data = data.get('file') 

    if not all([sender_id, receiver_id, message_type]):
        print("Missing message data in send_message event.")
        return {'success': False, 'error': 'Missing message data'}

    sender = db.get_user_by_id(sender_id)
    receiver = db.get_user_by_id(receiver_id)

    if not sender or not receiver:
        print(f"Sender ({sender_id}) or receiver ({receiver_id}) not found.")
        return {'success': False, 'error': 'Sender or receiver not found'}

    try:
        timestamp = datetime.now().isoformat()

        raw_aes_key = Fernet.generate_key()
        aes_cipher = Fernet(raw_aes_key)
        encrypted_content = aes_cipher.encrypt(content.encode()).decode()

        receiver_public_key_pem = db.get_user_public_key(receiver_id)
        if not receiver_public_key_pem:
            print(f"Error: Receiver {receiver_id} public key not found for encryption.")
            return {'success': False, 'error': 'Receiver public key not available'}

        
        receiver_public_key = serialization.load_pem_public_key(
            receiver_public_key_pem,
            backend=default_backend() 
        )

        encrypted_aes_key = receiver_public_key.encrypt(
            base64.urlsafe_b64decode(raw_aes_key),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        encrypted_aes_key_b64 = base64.b64encode(encrypted_aes_key).decode()

        message_id = db.save_message(
            sender_id=sender_id,
            receiver_id=receiver_id,
            message_type=message_type,
            content_encrypted=encrypted_content,
            aes_key_encrypted=encrypted_aes_key_b64,
            timestamp=timestamp,
            plain_content_for_sender=content
        )
        print(f"DEBUG SEND MESSAGE: Message ID {message_id} saved to DB, plain_content_for_sender stored.")

        message_obj = {
            'id': message_id,
            'sender_id': sender_id,
            'sender_name': sender['username'], 
            'receiver_id': receiver_id,
            'receiver_name': receiver['username'], 
            'message_type': message_type,
            'content': content, 
            'timestamp': timestamp
        }

        room_name = get_conversation_room_name(sender_id, receiver_id)
        socketio.emit('receive_message', message_obj, room=room_name)

       
        db.add_notification(
            receiver_id=receiver_id,
            sender_id=sender_id,
            notification_type='new_message',
            content=f"{sender['username']} sent you a new message", 
            message_id=message_id
        )
        print(f"Notification added to DB for receiver {receiver_id}")

       
        if receiver_id in user_sids:
            for sid in user_sids[receiver_id]:
                
                socketio.emit('new_notification', {
                    'sender_id': sender_id,
                    'sender_name': sender['username'],
                    'message_preview': content, 
                    'timestamp': timestamp,
                    'type': 'new_message',
                    'notification_id': message_id 
                }, room=sid)
                print(f"Emitted new_notification to receiver {receiver_id} on SID {sid}")
        
        return {'success': True, 'message': message_obj}

    except Exception as e:
        print(f"ERROR: Failed to send message via Socket.IO: {str(e)}")
        traceback.print_exc()
        return {'success': False, 'error': 'Failed to send message'}

@socketio.on('typing')
def handle_typing(data):
    user_id = data.get('user_id')
    username = data.get('username')
    partner_id = data.get('partner_id')
    is_typing = data.get('is_typing')

    if user_id and partner_id:
        room_name = get_conversation_room_name(user_id, partner_id)
        socketio.emit('typing_status', {
            'user_id': user_id,
            'username': username,
            'is_typing': is_typing
        }, room=room_name, include_self=False)


@socketio.on('mark_notification_as_read')
def handle_mark_notification_as_read(data):
    notification_id = data.get('notification_id')
    user_id = session.get('user_id')
    if notification_id and user_id:
        db.mark_notification_as_read(notification_id)
        
        emit('notifications_updated', {'user_id': user_id})
        print(f"Notification {notification_id} marked as read by user {user_id}")

@socketio.on('mark_all_notifications_as_read')
def handle_mark_all_notifications_as_read(data):
    user_id = session.get('user_id')
    if user_id:
        db.mark_all_notifications_as_read(user_id)
        
        emit('notifications_updated', {'user_id': user_id})
        print(f"All notifications marked as read for user {user_id}")

@socketio.on('request_notification_count')
def handle_request_notification_count():
    user_id = session.get('user_id')
    if user_id:
        count = len(db.get_unread_notifications(user_id))
        emit('notification_count_update', {'count': count}, room=request.sid)
        print(f"Sent initial notification count ({count}) to user {user_id} on SID {request.sid}")


@app.route('/api/notifications/unread', methods=['GET'])
@login_required
def get_unread_notifications_api():
    current_user_id = session.get('user_id')
    if not current_user_id:
        return jsonify({'error': 'Unauthorized'}), 401
    
    unread_notifications = db.get_unread_notifications(current_user_id)
    notifications_data = []
    for notif in unread_notifications:
        notifications_data.append({
            'id': notif['id'],
            'sender_id': notif['sender_id'],
            'sender_name': notif['sender_username'], 
            'content': notif['content'],
            'timestamp': notif['timestamp']
        })
    return jsonify(notifications_data)


def get_conversation_room_name(user1_id, user2_id):
    if user1_id < user2_id:
        return f"chat_{user1_id}_{user2_id}"
    else:
        return f"chat_{user2_id}_{user1_id}"

if __name__ == '__main__':
    socketio.run(app, debug=True, host='0.0.0.0', port=5000)
