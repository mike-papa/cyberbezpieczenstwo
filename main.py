from flask import Flask, request, jsonify
import jwt
from flask_mysqldb import MySQL # do połączenia z bazą danych
import bcrypt # do szyfrowania haseł


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

    # Dodawanie nowego użytkownika do bazy danych
    cur.execute("INSERT INTO users (username, password) VALUES (%s, %s)", (username, hashed_password))
    mysql.connection.commit()
    cur.close()

    # Zwracanie informacji o pomyślnej rejestracji
    return jsonify({"message": "User registered successfully"}), 201

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

    # Sprawdzanie hasła użytkownika
    if user and bcrypt.checkpw(password.encode("utf-8"), user["password"].encode("utf-8")):
        # Generowanie tokenu JWT
        token = jwt.encode({"username": username}, secret_key, algorithm="HS256")
        return jsonify({"token": token})
    else:
        # Zwracanie komunikatu o błędzie, jeśli dane są niepoprawne
        return jsonify({"message": "Wrong username or password"}), 401

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
