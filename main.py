from flask import Flask, request, jsonify, make_response
import jwt
from flask_mysqldb import MySQL # do połączenia z bazą danych
import bcrypt # do szyfrowania haseł
import pyotp # do generowania kodów TOTP
import qrcode # do generowania kodu QR
import base64 # do kodowania obrazu w formacie base64
from io import BytesIO # do zapisu obrazu w pamięci

app = Flask(__name__)

# Konfiguracja bazy danych
app.config["MYSQL_USER"] = "root" # nazwa użytkownika
app.config["MYSQL_PASSWORD"] = "12345" # hasło do bazy danych
app.config["MYSQL_DB"] = "cyberbezpieczenstwo_db" # nazwa bazy danych
app.config["MYSQL_CURSORCLASS"] = "DictCursor" # zwraca słownik zamiast tupli (krotki) - czyli zamiast (1, "Jan") zwraca {"id": 1, "name": "Jan"}
app.config["MYSQL_HOST"] = "127.0.0.1" # adres serwera bazy danych

# Inicjalizacja połączenia z bazą danych
mysql = MySQL(app)



# Klucz secret do generowania i weryfikacji tokenów JWT
secret_key = "secret_key"

# Funkcja do rejestracji użytkownika
@app.route("/register", methods=["POST"])
def register():
    # Pobieranie danych użytkownika z żądania
    username = request.json.get("username")
    password = request.json.get("password")

    # Sprawdzanie, czy użytkownik już istnieje w bazie danych
    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM users WHERE username = %s", [username])
    user = cur.fetchone()
    if user:
        cur.close()
        return jsonify({"message": "User already exists"}), 400

    # Haszowanie hasła użytkownika za pomocą funkcji bcrypt
    hashed_password = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

    # Generowanie klucza dla Google Authenticator i zapisywanie go w bazie danych
    auth_secret_key = pyotp.random_base32()

    # Dodawanie nowego użytkownika do bazy danych
    cur.execute("INSERT INTO users (username, password, auth_secret_key) VALUES (%s, %s, %s)",
                (username, hashed_password, auth_secret_key))
    mysql.connection.commit()
    cur.close()

    # Generowanie URL z kluczem dla aplikacji Google Authenticator
    totp = pyotp.totp.TOTP(auth_secret_key)
    otp_url = totp.provisioning_uri(username, issuer_name="CyberSecurity Lab")

    # Generowanie kodu QR dla URL z kluczem dla aplikacji Google Authenticator
    qr = qrcode.make(otp_url)

    # Zapisywanie kodu QR do bufora jako plik PNG
    buffer = BytesIO()
    qr.save(buffer)

    # Kodowanie obrazka QR w formacie base64
    qr_image_data = base64.b64encode(buffer.getvalue()).decode("utf-8")

    # Tworzenie odpowiedzi HTTP i ustawianie nagłówka Content-Type na obraz PNG
    response = make_response(base64.b64decode(qr_image_data))
    response.headers.set('Content-Type', 'image/png')
    return response

# Funkcja do logowania użytkownika
@app.route("/login", methods=["POST"])
def login():
    # Pobieranie danych użytkownika z żądania
    username = request.json.get("username")
    password = request.json.get("password")

    # Wyszukiwanie użytkownika w bazie danych
    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM users WHERE username = %s", [username])
    user = cur.fetchone()
    cur.close()

    auth_code = request.json.get("auth_code")  # nowy parametr - kod z aplikacji Google Authenticator

    if user:
        # Sprawdzanie hasła użytkownika
        if bcrypt.checkpw(password.encode("utf-8"), user["password"].encode("utf-8")):
            # Sprawdzanie kodu uwierzytelniającego z aplikacji Google Authenticator
            totp = pyotp.TOTP(user["auth_secret_key"])
            if totp.verify(auth_code):
                # Generowanie tokenu JWT
                token = jwt.encode({"username": username}, secret_key, algorithm="HS256")
                return jsonify({"token": token})
            else:
                # Zwracanie komunikatu o błędzie, jeśli kod uwierzytelniający jest niepoprawny
                return jsonify({"message": "Wrong authentication code"}), 401
        else:
            # Zwracanie komunikatu o błędzie, jeśli hasło jest niepoprawne
            return jsonify({"message": "Wrong password"}), 401
    else:
        # Zwracanie komunikatu o błędzie, jeśli użytkownik nie istnieje
        return jsonify({"message": "User does not exist"}), 401

# Funkcja do weryfikacji tokenu JWT
def verify_token(token):
    try:
        # Weryfikacja tokenu za pomocą klucza secret
        data = jwt.decode(token, secret_key, algorithms=["HS256"])
        return data["username"]
    # Obsługa błędów weryfikacji tokenu JWT (niepoprawny podpis)
    except jwt.exceptions.InvalidSignatureError:
        return None
    # Obsługa błędów weryfikacji tokenu JWT (niepoprawne kodowanie)
    except jwt.exceptions.DecodeError:
        return None
    # Obsługa błędów weryfikacji tokenu JWT (niepoprawny algorytm)
    except jwt.exceptions.InvalidAlgorithmError:
        return None

# Funkcja testowa do weryfikacji tokenu JWT
@app.route("/test", methods=["GET"])
def test():
    token = request.headers.get("Authorization") # Pobieranie tokenu z nagłówka żądania
    if token:
        # Usunięcie słowa "Bearer " z tokenu JWT (jeśli istnieje) i pobranie tylko tokenu
        token = token.replace("Bearer ", "")
        # Weryfikacja tokenu
        decoded_token = verify_token(token)
        if decoded_token:
            return "Token is valid"
        else:
            return "Token is invalid"
    else:
        return "Token is missing"

if __name__ == "__main__":
    app.run(debug=True) # Uruchomienie aplikacji Flask w trybie debugowania na porcie 5000 (domyślnie)
