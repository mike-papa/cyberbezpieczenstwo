import requests

# Adres URL serwera
url = "http://127.0.0.1:5000"

# Funkcja do logowania użytkownika
def login(username, password):
    # Wysyłanie żądania POST z danymi użytkownika
    response = requests.post(f"{url}/login", json={"username": username, "password": password})
    if response.status_code == 200:
        # Pobieranie tokenu JWT z odpowiedzi
        token = response.json()["token"]
        return token
    else:
        # Zwracanie komunikatu o błędzie, jeśli odpowiedź jest niepoprawna
        return None

# Funkcja do wykonywania uwierzytelnionych żądań
def request_with_token(token, endpoint):
    # Wysyłanie żądania GET z nagłówkiem Authorization zawierającym token JWT
    response = requests.get(f"{url}/{endpoint}", headers={"Authorization": f"Bearer {token}"})
    if response.status_code == 200:
        # Zwracanie odpowiedzi
        return response.text
    else:
        # Zwracanie komunikatu o błędzie, jeśli odpowiedź jest niepoprawna
        return None

# Przykład użycia funkcji logowania i wykonywania uwierzytelnionych żądań
token = login("user", "password")
if token:
    response = request_with_token(token, "test")
    print(response)
else:
    print("Login failed")
