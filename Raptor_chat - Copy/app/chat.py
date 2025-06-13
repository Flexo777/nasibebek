import tkinter as tk
from tkinter import messagebox, scrolledtext
import threading
import socket
from app.security import Encryption

class ChatApp(tk.Frame):
    def __init__(self, master=None):
        super().__init__(master)
        self.master = master
        self.client = None
        self.typing = False

        self.master.title("RAPTOR - Real-time Chat")
        self.master.geometry("400x600")
        self.master.configure(bg="#5A189A")
        self.create_widgets()

    def create_widgets(self):
        self.chat_area = scrolledtext.ScrolledText(self.master, state='disabled', bg="#F3F0FF")
        self.chat_area.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)

        self.entry = tk.Entry(self.master)
        self.entry.pack(padx=10, pady=(0,10), fill=tk.X)
        self.entry.bind("<Return>", self.send_message)
        self.entry.bind("<KeyPress>", self.typing_indicator)

        self.status_label = tk.Label(self.master, text="Not connected", bg="#5A189A", fg="white")
        self.status_label.pack(pady=5)

    def set_client(self, client):
        self.client = client
        self.client.set_receive_callback(self.receive_message)
        self.status_label.config(text=f"Connected to {client.server_ip}")

    def send_message(self, event=None):
        msg = self.entry.get()
        if msg and self.client:
            self.client.send(msg)
            self.display_message(f"You: {msg}")
            self.entry.delete(0, tk.END)

    def receive_message(self, message):
        self.display_message(f"Partner: {message}")

    def display_message(self, message):
        self.chat_area.config(state='normal')
        self.chat_area.insert(tk.END, message + "\n")
        self.chat_area.config(state='disabled')
        self.chat_area.yview(tk.END)

    def show_error(self, message):
        messagebox.showerror("Error", message)

    def typing_indicator(self, event=None):
        if not self.typing and self.client:
            self.client.send_typing()
            self.typing = True
            threading.Timer(2.0, self.reset_typing).start()

    def reset_typing(self):
        self.typing = False

class Client:
    def __init__(self, server_ip, server_port=12345):
        self.server_ip = server_ip
        self.server_port = server_port
        self.encryption = Encryption()
        self.socket = None
        self.receive_callback = None

    def connect(self):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.connect((self.server_ip, self.server_port))
        threading.Thread(target=self.receive_loop, daemon=True).start()

    def send(self, message):
        encrypted_message = self.encryption.encrypt(message)
        self.socket.sendall(encrypted_message)

    def send_typing(self):
        typing_message = "[typing...]"
        encrypted_typing = self.encryption.encrypt(typing_message)
        self.socket.sendall(encrypted_typing)

    def receive_loop(self):
        while True:
            try:
                encrypted_data = self.socket.recv(4096)
                if not encrypted_data:
                    break
                message = self.encryption.decrypt(encrypted_data)
                if self.receive_callback:
                    self.receive_callback(message)
            except Exception as e:
                print(f"[CLIENT ERROR] {e}")
                break

    def set_receive_callback(self, callback):
        self.receive_callback = callback

    def disconnect(self):
        if self.socket:
            self.socket.close()