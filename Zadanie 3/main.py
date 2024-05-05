import mysql.connector
import os
from flask import Flask, request, render_template_string

app = Flask(__name__)

def get_db_connection():
    connection = mysql.connector.connect(
        host="150.254.36.243",
        user="p4_12345",
        password="12345",
        database="cb12345"
    )
    return connection

@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    with get_db_connection() as connection:
        cursor = connection.cursor(dictionary=True)
        cursor.execute(f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'")
        user = cursor.fetchone()
    if user:
        return f"Welcome, {user['username']}!"
    else:
        return "Invalid credentials"

@app.route('/display_message')
def display_message():
    message = request.args.get('message')
    return render_template_string(open('templates/message.html').read().replace('{{message}}', message))

@app.route('/download_template')
def download_template():
    file = request.args.get('file')
    return render_template_string(open(os.path.join('templates', file)).read())

if __name__ == '__main__':
    app.run()