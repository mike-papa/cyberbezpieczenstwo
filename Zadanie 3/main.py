import mysql.connector
import os
from flask import Flask, request, render_template_string, render_template
from werkzeug.utils import secure_filename

app = Flask(__name__)

def get_db_connection():
    connection = mysql.connector.connect(
        host="127.0.0.1",
        port=3307,
        user="root",
        password="1234",
        database="cyberpezpieczenstwo"
    )
    return connection

@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    with get_db_connection() as connection:
        cursor = connection.cursor(dictionary=True)
        query = "SELECT * FROM users WHERE username = %s AND password = %s"
        cursor.execute(query, (username, password))
        user = cursor.fetchone()
    if user:
        return f"Welcome, {user['username']}!"
    else:
        return "Invalid credentials"

@app.route('/display_message')
def display_message():
    message = request.args.get('message')
    return render_template('message.html', message=message)

@app.route('/download_template')
def download_template():
    file = request.args.get('file')
    secure_path = secure_filename(file)
    full_path = os.path.join('templates', secure_path)

    if not os.path.exists(full_path) or not full_path.endswith('.html'):
        return "Invalid file requested"

    return render_template_string(open(full_path).read())

if __name__ == '__main__':
    app.run()