import os
import jwt
import datetime
import bcrypt
from functools import wraps
from dotenv import load_dotenv
from flask import Flask, request, jsonify
import psycopg2
import requests

# Načítanie credentials z .env súboru
load_dotenv()
app = Flask(__name__)
SECRET_KEY = os.environ.get("SECRET_KEY")
url = os.environ.get("DATABASE_URL")
connection = psycopg2.connect(url)

# overenia JWT tokenu
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'Authorization' in request.headers:
            bearer = request.headers['Authorization']
            token = bearer.split(" ")[1] if " " in bearer else bearer

        if not token:
            return jsonify({'message': 'Token is missing!'}), 401

        try:
            data = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
            request.user = data
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Invalid token'}), 401

        return f(*args, **kwargs)
    return decorated

# Testovací endpoint
@app.get("/default")
@token_required
def default():
    user_data = request.user  # získané z tokenu
    return jsonify({
        "message": "Access granted",
        "user_id": user_data['uid'],
        "role": user_data['role']
    }), 200

# LOGIN s generovaním JWT tokenu
@app.route('/login', methods=['POST'])
def login():
    data = request.json
    email = data.get('email')
    password = data.get('password')

    try:
        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT uid, password, role FROM users WHERE email = %s;",
                (email,)
            )
            user = cursor.fetchone()

        if user:
            uid, hashed_pw, role = user

            if bcrypt.checkpw(password.encode('utf-8'), hashed_pw.encode('utf-8')):
                token = jwt.encode({
                    'uid': uid,
                    'role': role,
                    'exp': datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=1)
                }, SECRET_KEY, algorithm='HS256')

                return jsonify({'success': True, 'token': token}), 200
            else:
                return jsonify({'success': False, 'message': 'Invalid password'}), 401
        else:
            return jsonify({'success': False, 'message': 'User not found'}), 404

    except Exception as e:
        print("Error during login:", e)
        return jsonify({'success': False, 'message': 'Server error'}), 500


@app.route('/delete-accommodation/<int:aid>', methods=['DELETE'])
@token_required
def delete_accommodation(aid):
    uid = request.user['uid']

    try:
        with connection.cursor() as cursor:
            # Skontroluj, či používateľ je vlastníkom ubytovania
            cursor.execute("SELECT * FROM accommodations WHERE aid = %s AND owner = %s;", (aid, uid))
            acc = cursor.fetchone()

            if not acc:
                return jsonify({'success': False, 'message': 'Accommodation not found or unauthorized'}), 404

            # Najprv vymaž obrázky
            cursor.execute("DELETE FROM pictures WHERE aid = %s;", (aid,))
            # Potom vymaž ubytovanie
            cursor.execute("DELETE FROM accommodations WHERE aid = %s;", (aid,))
            connection.commit()

        return jsonify({'success': True, 'message': f'Accommodation {aid} deleted'}), 200

    except Exception as e:
        print("Delete accommodation error:", e)
        return jsonify({'success': False, 'message': 'Server error', 'error': str(e)}), 500

# REGISTRÁCIA používateľa
@app.route('/register', methods=['POST'])
def register():
    data = request.json
    email = data.get('email')
    password = data.get('password')
    role = data.get('role', 'guest')

    try:
        with connection.cursor() as cursor:
            cursor.execute("SELECT * FROM users WHERE email = %s;", (email,))
            existing_user = cursor.fetchone()

            if existing_user:
                return jsonify({'success': False, 'message': 'User already exists'}), 409

            hashed_pw = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode()

            cursor.execute(
                "INSERT INTO users (email, password, role) VALUES (%s, %s, %s);",
                (email, hashed_pw, role)
            )
            connection.commit()

        return jsonify({'success': True, 'message': 'Registration successful'}), 201

    except Exception as e:
        print("Error during registration:", e)
        return jsonify({'success': False, 'message': 'Server error'}), 500

def geocode_address_full(address):
    url = "https://nominatim.openstreetmap.org/search"
    params = {
        'q': address,
        'format': 'json',
        'limit': 1,
        'addressdetails': 1
    }
    headers = {
        'User-Agent': 'mtaa-app/1.0'
    }

    response = requests.get(url, params=params, headers=headers)
    data = response.json()

    if data:
        lat = float(data[0]['lat'])
        lon = float(data[0]['lon'])
        address_info = data[0].get("address", {})
        city = address_info.get("city") or address_info.get("town") or address_info.get("village") or ""
        country = address_info.get("country") or ""
        return lat, lon, city, country
    else:
        return None, None, "", ""
@app.route('/add-accommodation', methods=['POST'])
@token_required
def add_accommodation():
    try:
        name = request.form.get("name")
        max_guests = request.form.get("guests")
        price = request.form.get("price")
        address = request.form.get("address")
        description = request.form.get("description")
        iban = request.form.get("iban")  # Pridanie IBAN
        images = request.files.getlist("images")

        latitude, longitude, location_city, location_country = geocode_address_full(address)

        if not all([name, location_city, location_country, max_guests, price, latitude, longitude, description, iban]):
            return jsonify({'success': False, 'message': 'Missing required fields'}), 400

        if not images or len(images) < 3:
            return jsonify({'success': False, 'message': 'At least 3 images are required'}), 400

        conn = psycopg2.connect(url)
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO accommodations
                (name, location_city, location_country, owner, max_guests, latitude, longitude, pricepn, description, iban)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                RETURNING aid;
            """, (
                name, location_city, location_country,
                request.user['uid'], max_guests, latitude, longitude,
                price, description, iban
            ))
            aid = cur.fetchone()[0]

            for img in images:
                cur.execute("INSERT INTO pictures (aid, image) VALUES (%s, %s);", (aid, psycopg2.Binary(img.read())))

            conn.commit()

        return jsonify({'success': True, 'message': 'Accommodation added', 'aid': aid}), 201

    except Exception as e:
        print("Accommodation upload error:", e)
        return jsonify({'success': False, 'message': 'Server error', 'error': str(e)}), 500

@app.route('/edit-accommodation/<int:aid>', methods=['PUT'])
@token_required
def edit_accommodation(aid):
    uid = request.user['uid']

    try:
        name = request.form.get("name")
        max_guests = request.form.get("guests")
        price = request.form.get("price")
        address = request.form.get("address")
        description = request.form.get("description")
        iban = request.form.get("iban")  # Pridanie IBAN
        images = request.files.getlist("images")

        latitude, longitude, location_city, location_country = geocode_address_full(address)

        if not all([name, location_city, location_country, max_guests, price, latitude, longitude, description, iban]):
            return jsonify({'success': False, 'message': 'Missing required fields'}), 400

        if not images or len(images) < 3:
            return jsonify({'success': False, 'message': 'At least 3 images are required'}), 400

        with connection.cursor() as cursor:
            cursor.execute("SELECT * FROM accommodations WHERE aid = %s AND owner = %s;", (aid, uid))
            accommodation = cursor.fetchone()

            if not accommodation:
                return jsonify({'success': False, 'message': 'Accommodation not found or unauthorized'}), 404

            cursor.execute("""
                UPDATE accommodations SET
                    name = %s,
                    location_city = %s,
                    location_country = %s,
                    max_guests = %s,
                    pricepn = %s,
                    latitude = %s,
                    longitude = %s,
                    description = %s,
                    iban = %s
                WHERE aid = %s;
            """, (
                name, location_city, location_country,
                max_guests, price, latitude, longitude,
                description, iban, aid
            ))

            cursor.execute("DELETE FROM pictures WHERE aid = %s;", (aid,))
            for img in images:
                cursor.execute("INSERT INTO pictures (aid, image) VALUES (%s, %s);", (aid, psycopg2.Binary(img.read())))

            connection.commit()

        return jsonify({'success': True, 'message': 'Accommodation updated', 'aid': aid}), 200

    except Exception as e:
        print("Edit accommodation error:", e)
        return jsonify({'success': False, 'message': 'Server error', 'error': str(e)}), 500

@app.route('/like_dislike', methods=['POST'])
@token_required
def like_dislike_accommodation():
    data = request.json
    aid = data.get('aid')
    uid = request.user['uid']

    if not aid:
        return jsonify({'success': False, 'message': 'Missing AID'}), 400

    try:
        with connection.cursor() as cursor:
            # Over, či už existuje záznam
            cursor.execute("SELECT * FROM liked WHERE uid = %s AND aid = %s", (uid, aid))
            exists = cursor.fetchone()

            if exists:
                # Ak existuje, odstráň
                cursor.execute("DELETE FROM liked WHERE uid = %s AND aid = %s", (uid, aid))
                message = 'Unliked accommodation'
            else:
                # Inak pridaj
                cursor.execute("INSERT INTO liked (uid, aid) VALUES (%s, %s)", (uid, aid))
                message = 'Liked accommodation'

            connection.commit()

        return jsonify({'success': True, 'message': message, 'aid': aid}), 200

    except Exception as e:
        print("Like error:", e)
        return jsonify({'success': False, 'message': 'Server error', 'error': str(e)}), 500



@app.route('/liked-accommodations', methods=['GET'])
@token_required
def get_liked_accommodations():
    uid = request.user['uid']

    try:
        with connection.cursor() as cursor:
            cursor.execute("""
                SELECT 
                    a.aid,
                    a.name,
                    a.location_city,
                    a.location_country,
                    a.pricepn,
                    r.rating,
                    (
                        SELECT encode(image, 'base64') 
                        FROM pictures 
                        WHERE aid = a.aid 
                        ORDER BY pid ASC 
                        LIMIT 1
                    ) AS image_base64
                FROM liked l
                JOIN accommodations a ON a.aid = l.aid
                LEFT JOIN (
                    SELECT aid, ROUND(AVG(rating), 2) AS rating 
                    FROM reviews 
                    GROUP BY aid
                ) r ON a.aid = r.aid
                WHERE l.uid = %s
                LIMIT 20;
            """, (uid,))
            results = cursor.fetchall()

        accommodations = []
        for row in results:
            aid, name, city, country, price, rating, image_base64 = row
            accommodations.append({
                'aid': aid,
                'name': name,
                'location': f"{city}, {country}",
                'price_per_night': price,
                'rating': rating if rating else 0.0,
                'image_base64': image_base64
            })

        return jsonify({'success': True, 'liked_accommodations': accommodations}), 200

    except Exception as e:
        print("Get liked accommodations error:", e)
        return jsonify({'success': False, 'message': 'Server error', 'error': str(e)}), 500

# PRE GPS POZIADAVKU
@app.route('/get-address', methods=['POST'])
def get_address_from_coordinates():
    data = request.json
    lat = data.get('latitude')
    lon = data.get('longitude')

    if not lat or not lon:
        return jsonify({'success': False, 'message': 'Missing coordinates'}), 400

    try:
        url = 'https://nominatim.openstreetmap.org/reverse'
        params = {
            'format': 'json',
            'lat': lat,
            'lon': lon
        }
        headers = {
            'User-Agent': 'mtaa-app/1.0'
        }

        response = requests.get(url, params=params, headers=headers)
        result = response.json()

        address = result.get('display_name', 'Unknown location')
        return jsonify({'success': True, 'address': address}), 200

    except Exception as e:
        print("Reverse geocoding error:", e)
        return jsonify({'success': False, 'message': 'Server error', 'error': str(e)}), 500