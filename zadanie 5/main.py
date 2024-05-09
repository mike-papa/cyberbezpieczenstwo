import base64
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from flask import Flask, request, jsonify
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID
from cryptography import x509
from datetime import datetime, timedelta
import uuid

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
@app.route('/generate_self_signed_cert', methods=['GET'])
def generate_self_signed_cert():
    # Generowanie klucza prywatnego
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    # Tworzenie certyfikatu X.509
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"PL"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Wielkopolskie"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"Poznan"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"83803"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"cybersecurity.com"),
    ])

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(uuid.uuid4().int)
        .not_valid_before(datetime.utcnow())
        .not_valid_after(datetime.utcnow() + timedelta(days=365))
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True,
        )
        .sign(private_key, hashes.SHA256(), default_backend())
    )

    # Serializacja certyfikatu i klucza prywatnego do formatu PEM
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    result = {
        'cert_pem': base64.b64encode(cert_pem).decode(),
        'private_key_pem': base64.b64encode(private_key_pem).decode()
    }

    return jsonify(result)
@app.route('/get_cert_info', methods=['POST'])
def get_cert_info():
    data = request.json
    cert_pem = base64.b64decode(data['cert_pem'])

    # Wczytanie certyfikatu z formatu PEM
    cert = x509.load_pem_x509_certificate(cert_pem, default_backend())

    # Pobranie informacji z certyfikatu
    subject = cert.subject
    issuer = cert.issuer
    not_valid_before = cert.not_valid_before
    not_valid_after = cert.not_valid_after

    result = {
        'subject': subject.rfc4514_string(),
        'issuer': issuer.rfc4514_string(),
        'not_valid_before': not_valid_before.strftime('%Y-%m-%d %H:%M:%S'),
        'not_valid_after': not_valid_after.strftime('%Y-%m-%d %H:%M:%S')
    }

    return jsonify(result)
@app.route('/encrypt_with_cert', methods=['POST'])
def encrypt_with_cert():
    data = request.json
    cert_pem = base64.b64decode(data['cert_pem'])
    plaintext = data['message'].encode()

    # Wczytanie certyfikatu z formatu PEM
    cert = x509.load_pem_x509_certificate(cert_pem, default_backend())

    # Pobranie klucza publicznego z certyfikatu
    public_key = cert.public_key()

    # Szyfrowanie wiadomości za pomocą klucza publicznego i paddingu OAEP
    cipher = padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
    ciphertext = public_key.encrypt(plaintext, cipher)

    result = {
        'ciphertext': base64.b64encode(ciphertext).decode()
    }
    return jsonify(result)
@app.route('/decrypt_with_cert', methods=['POST'])
def decrypt_with_cert():
    data = request.json
    private_key_pem = base64.b64decode(data['private_key_pem'])
    ciphertext = base64.b64decode(data['ciphertext'])

    # Wczytanie klucza prywatnego z formatu PEM
    private_key = serialization.load_pem_private_key(
        private_key_pem,
        password=None,
        backend=default_backend()
    )

    # Deszyfrowanie wiadomości za pomocą klucza prywatnego i paddingu OAEP
    cipher = padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
    plaintext = private_key.decrypt(ciphertext, cipher)

    result = {
        'message': plaintext.decode()
    }
    return jsonify(result)

# Uruchomienie aplikacji
if __name__ == '__main__':
    app.run()