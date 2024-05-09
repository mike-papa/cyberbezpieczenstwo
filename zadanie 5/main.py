import base64
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from flask import Flask, request, jsonify
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15

app = Flask(__name__)

# Funkcja do generowania klucza symetrycznego
@app.route('/generate_symmetric_key', methods=['GET'])
def generate_symmetric_key():
    new_key = get_random_bytes(32)
    result = {
        'secret_key': base64.b64encode(new_key).decode()
    }
    return jsonify(result)

# Funkcja do generowania kluczy asymetrycznych
@app.route('/generate_asymmetric_keys', methods=['GET'])
def generate_asymmetric_keys():
    new_private_key = RSA.generate(2048)
    new_public_key = new_private_key.publickey()
    result = {
        'private_key': base64.b64encode(new_private_key.export_key()).decode(),
        'public_key': base64.b64encode(new_public_key.export_key()).decode()
    }
    return jsonify(result)

# Funkcja do szyfrowania wiadomości za pomocą klucza symetrycznego
@app.route('/encrypt_symmetric', methods=['POST'])
def encrypt_symmetric():
    data = request.json
    key = base64.b64decode(data['secret_key'])
    plaintext = data['message'].encode()

    cipher = AES.new(key, AES.MODE_ECB)
    padded_plaintext = pad(plaintext, AES.block_size)
    ciphertext = cipher.encrypt(padded_plaintext)

    result = {
        'ciphertext': base64.b64encode(ciphertext).decode()
    }
    return jsonify(result)

# Funkcja do deszyfrowania wiadomości za pomocą klucza symetrycznego
@app.route('/decrypt_symmetric', methods=['POST'])
def decrypt_symmetric():
    data = request.json
    key = base64.b64decode(data['secret_key'])
    ciphertext = base64.b64decode(data['ciphertext'])

    cipher = AES.new(key, AES.MODE_ECB)
    padded_plaintext = cipher.decrypt(ciphertext)
    plaintext = unpad(padded_plaintext, AES.block_size)

    result = {
        'message': plaintext.decode()
    }
    return jsonify(result)

# Funkcja do szyfrowania wiadomości za pomocą klucza publicznego
@app.route('/encrypt_asymmetric', methods=['POST'])
def encrypt_asymmetric():
    data = request.json
    pub_key = base64.b64decode(data['public_key'])
    plaintext = data['message'].encode()

    public_key_obj = RSA.import_key(pub_key)
    cipher = PKCS1_OAEP.new(public_key_obj)
    ciphertext = cipher.encrypt(plaintext)

    result = {
        'ciphertext': base64.b64encode(ciphertext).decode()
    }
    return jsonify(result)

# Funkcja do deszyfrowania wiadomości za pomocą klucza prywatnego
@app.route('/decrypt_asymmetric', methods=['POST'])
def decrypt_asymmetric():
    data = request.json
    priv_key = base64.b64decode(data['private_key'])
    ciphertext = base64.b64decode(data['ciphertext'])

    private_key_obj = RSA.import_key(priv_key)
    cipher = PKCS1_OAEP.new(private_key_obj)
    plaintext = cipher.decrypt(ciphertext)

    result = {
        'message': plaintext.decode()
    }
    return jsonify(result)
@app.route('/sign_message', methods=['POST'])
def sign_message():
    data = request.json
    priv_key = base64.b64decode(data['private_key'])
    message = data['message'].encode()

    # Wczytanie klucza prywatnego
    private_key_obj = RSA.import_key(priv_key)
    h = SHA256.new(message)
    # Podpisanie wiadomości
    signature = pkcs1_15.new(private_key_obj).sign(h)
    result = {
        'signature': base64.b64encode(signature).decode()
    }
    return jsonify(result)
@app.route('/verify_signature', methods=['POST'])
def verify_signature():
    data = request.json
    pub_key = base64.b64decode(data['public_key'])
    message = data['message'].encode()
    signature = base64.b64decode(data['signature'])

    # Wczytanie klucza publicznego
    public_key_obj = RSA.import_key(pub_key)
    h = SHA256.new(message)
    try:
        # Weryfikacja podpisu
        pkcs1_15.new(public_key_obj).verify(h, signature)
        result = {
            'valid': True
        }
    except (ValueError, TypeError):
        result = {
            'valid': False
        }

    return jsonify(result)

# Uruchomienie aplikacji
if __name__ == '__main__':
    app.run()