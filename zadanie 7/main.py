from flask import Flask, request, jsonify
import jwt
from multiprocessing import Process

app = Flask(__name__)

# Klucz secret do generowania i weryfikacji tokenów JWT
secret_key = "secret_key"

# Funkcja do logowania użytkownika
@app.route("/login", methods=["POST"])
def login():
    # Pobieranie danych użytkownika z żądania
    username = request.json.get("username")
    password = request.json.get("password")

    # Weryfikacja danych użytkownika (to tylko przykład,
    # prawdziwe weryfikacje powinno się wykonywać z bazy danych)
    if username == "admin" and password == "SomePass123@":
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


def run_http():
    app.run(port=5080)

def run_https():
    app.run(ssl_context=('cert.pem', 'key.pem'), port=5443)

if __name__ == '__main__':
    http_process = Process(target=run_http)
    https_process = Process(target=run_https)
    http_process.start()
    https_process.start()
    http_process.join()
    https_process.join()