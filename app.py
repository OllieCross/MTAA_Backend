import os
from dotenv import load_dotenv
from flask import Flask, request, jsonify
import psycopg2

load_dotenv()  # loads variables from .env file into environment
app = Flask(__name__)
url = os.environ.get("DATABASE_URL")
connection = psycopg2.connect(url)# gets variables from environment

@app.get("/default")
def create_room():

    with connection.cursor(url) as cursor:
        cursor.execute(("SELECT * FROM movies;"))
        result = cursor.fetchall()
    return {"connection successful": result }, 201


@app.route('/login', methods=['POST'])
def login():
    data = request.json
    email = data.get('email')
    password = data.get('password')

    try:
        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT * FROM users WHERE email = %s AND password = %s;",
                (email, password)
            )
            user = cursor.fetchone()

        if user:
            return jsonify({'success': True, 'message': 'Login successful'}), 200
        else:
            return jsonify({'success': False, 'message': 'Invalid credentials'}), 401

    except Exception as e:
        print("Error during login:", e)
        return jsonify({'success': False, 'message': 'Server error'}), 500