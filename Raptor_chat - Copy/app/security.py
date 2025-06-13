from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
import base64

class Encryption:
    def __init__(self):
        self.private_key = RSA.generate(2048)
        self.public_key = self.private_key.publickey()
        self.aes_key = get_random_bytes(16)
        self.encrypted_aes_key = self.encrypt_aes_key()

    def encrypt_aes_key(self):
        cipher_rsa = PKCS1_OAEP.new(self.public_key)
        return cipher_rsa.encrypt(self.aes_key)

    def encrypt(self, message):
        cipher_aes = AES.new(self.aes_key, AES.MODE_EAX)
        ciphertext, tag = cipher_aes.encrypt_and_digest(message.encode('utf-8'))
        return str({
            'nonce': base64.b64encode(cipher_aes.nonce).decode('utf-8'),
            'tag': base64.b64encode(tag).decode('utf-8'),
            'ciphertext': base64.b64encode(ciphertext).decode('utf-8')
        }).encode('utf-8')

    def decrypt(self, encrypted_components):
        components = eval(encrypted_components.decode('utf-8'))
        nonce = base64.b64decode(components['nonce'])
        tag = base64.b64decode(components['tag'])
        ciphertext = base64.b64decode(components['ciphertext'])
        cipher_aes = AES.new(self.aes_key, AES.MODE_EAX, nonce)
        return cipher_aes.decrypt_and_verify(ciphertext, tag).decode('utf-8')