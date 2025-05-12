from flask import Flask, request, jsonify, abort, Response, current_app
from flask_socketio import SocketIO, join_room
import eventlet; eventlet.monkey_patch(socket=True, select=True, thread=True, time=True, os=True)
import os
import jwt
import datetime
import bcrypt
from functools import wraps
from dotenv import load_dotenv
from flasgger import Swagger, swag_from
import psycopg2
from psycopg2 import pool
import requests
import logging
from datetime import date

load_dotenv()
app = Flask(__name__)
app.logger.setLevel(logging.DEBUG)
SECRET_KEY = os.environ.get("SECRET_KEY")
DATABASE_URL = os.environ.get("DATABASE_URL")

db_pool = pool.ThreadedConnectionPool(
    minconn=1,
    maxconn=20,
    dsn=DATABASE_URL
)

app.config['SWAGGER'] = {'title': 'Login API', 'uiversion': 3}
swagger = Swagger(app)
socketio = SocketIO(app,logger=True)

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

@socketio.on("connect")
def handle_connect(*args) -> bool | None:
    current_app.logger.debug(f"WS connect: args={request.args}")
    token = request.args.get("token")
    try:
        data = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
    except jwt.InvalidTokenError:
        return False

    uid = data["uid"]
    join_room(f"user:{uid}")
    current_app.logger.debug(f"Joined room user:{uid}")

def push_to_owner(owner_id: int, text: str) -> None:
    current_app.logger.debug(f"push_to_owner → room=user:{owner_id}, message={text}")
    socketio.emit(
        "accommodation_liked",
        {"message": text},
        room=f"user:{owner_id}",
    )

@app.get("/default")
@swag_from({
    'tags': ['Test'],
    'summary': 'Access test endpoint',
    'description': 'Returns user info if a valid JWT token is provided.',
    'security': [{
        'BearerAuth': []
    }],
    'responses': {
        200: {
            'description': 'Access granted',
            'content': {
                'application/json': {
                    'example': {
                        'message': 'Access granted',
                        'user_id': 1,
                        'role': 'owner'
                    }
                }
            }
        },
        401: {
            'description': 'Unauthorized - Missing or invalid token'
        }
    }
})
@token_required
def default():
    user_data = request.user
    return jsonify({"message": "Access granted", "user_id": user_data['uid'], "role": user_data['role']}), 200

@app.route('/login', methods=['POST'])
@swag_from({
    'tags': ['Authentication'],
    'summary': 'Login a user',
    'description': 'Authenticates user credentials and returns a JWT token on success.',
    'requestBody': {
        'required': True,
        'content': {
            'application/json': {
                'example': {
                    'email': 'user@example.com',
                    'password': 'yourPassword123'
                }
            }
        }
    },
    'responses': {
        200: {
            'description': 'Login successful',
            'content': {
                'application/json': {
                    'example': {
                        'success': True,
                        'token': 'your.jwt.token.here'
                    }
                }
            }
        },
        401: {
            'description': 'Invalid password'
        },
        404: {
            'description': 'User not found'
        },
        500: {
            'description': 'Server error'
        }
    }
})
def login():
    data = request.json
    email = data.get('email')
    password = data.get('password')

    conn = db_pool.getconn()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT uid, password, role FROM users WHERE email = %s;", (email,))
            user = cur.fetchone()
        if not user:
            return jsonify({'success': False, 'message': 'User not found'}), 404

        uid, hashed_pw, role = user
        if not bcrypt.checkpw(password.encode('utf-8'), hashed_pw.encode('utf-8')):
            return jsonify({'success': False, 'message': 'Invalid password'}), 401

        token = jwt.encode({
            'uid': uid,
            'role': role,
            'exp': datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=1)
        }, SECRET_KEY, algorithm='HS256')
        return jsonify({'success': True, 'token': token}), 200
    except Exception as e:
        current_app.logger.error(f"Login error: {e}")
        return jsonify({'success': False, 'message': 'Server error'}), 500
    finally:
        db_pool.putconn(conn)

@app.route('/delete-accommodation/<int:aid>', methods=['DELETE'])
@swag_from({
    'tags': ['Accommodations'],
    'summary': 'Delete accommodation',
    'description': 'Deletes a user-owned accommodation by ID. Requires JWT in the Authorization header.',
    'parameters': [
        {
            'name': 'aid',
            'in': 'path',
            'type': 'integer',
            'required': True,
            'description': 'ID of the accommodation to delete'
        }
    ],
    'security': [{'BearerAuth': []}],
    'responses': {
        200: {
            'description': 'Successfully deleted',
            'content': {
                'application/json': {
                    'example': {'success': True, 'message': 'Accommodation 12 deleted'}
                }
            }
        },
        404: {
            'description': 'Not found or unauthorized',
            'content': {
                'application/json': {
                    'example': {'success': False, 'message': 'Accommodation not found or unauthorized'}
                }
            }
        },
        500: {
            'description': 'Internal server error'
        }
    }
})
@token_required
def delete_accommodation(aid):
    uid = request.user['uid']

    conn = db_pool.getconn()
    try:
        with conn.cursor() as cursor:
            # Skontroluj, či používateľ je vlastníkom ubytovania
            cursor.execute("SELECT * FROM accommodations WHERE aid = %s AND owner_id = %s;", (aid, uid))
            acc = cursor.fetchone()

            if not acc:
                return jsonify({'success': False, 'message': 'Accommodation not found or unauthorized'}), 404

            # Najprv vymaž obrázky
            cursor.execute("DELETE FROM pictures WHERE aid = %s;", (aid,))
            # Potom vymaž ubytovanie
            cursor.execute("DELETE FROM accommodations WHERE aid = %s;", (aid,))
            conn.commit()

        return jsonify({'success': True, 'message': f'Accommodation {aid} deleted'}), 200

    except Exception as e:
        print("Delete accommodation error:", e)
        return jsonify({'success': False, 'message': 'Server error', 'error': str(e)}), 500
    finally:
        db_pool.putconn(conn)

@app.route('/register', methods=['POST'])
@swag_from({
    'tags': ['Authentication'],
    'summary': 'Register a new user',
    'description': 'Creates a new user account with email, password, and role (default: guest).',
    'requestBody': {
        'required': True,
        'content': {
            'application/json': {
                'example': {
                    'email': 'newuser@example.com',
                    'password': 'securePassword123',
                    'role': 'guest'
                }
            }
        }
    },
    'responses': {
        201: {
            'description': 'Registration successful',
            'content': {
                'application/json': {
                    'example': {
                        'success': True,
                        'message': 'Registration successful'
                    }
                }
            }
        },
        409: {
            'description': 'User already exists',
            'content': {
                'application/json': {
                    'example': {
                        'success': False,
                        'message': 'User already exists'
                    }
                }
            }
        },
        500: {
            'description': 'Server error'
        }
    }
})
def register():
    data = request.json
    email = data.get('email')
    password = data.get('password')
    role = data.get('role', 'owner')

    conn = db_pool.getconn()
    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT * FROM users WHERE email = %s;", (email,))
            existing_user = cursor.fetchone()

            if existing_user:
                return jsonify({'success': False, 'message': 'User already exists'}), 409

            hashed_pw = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode()

            cursor.execute(
                "INSERT INTO users (email, password, role) VALUES (%s, %s, %s);",
                (email, hashed_pw, role)
            )
            conn.commit()

        return jsonify({'success': True, 'message': 'Registration successful'}), 201

    except Exception as e:
        print("Error during registration:", e)
        return jsonify({'success': False, 'message': 'Server error'}), 500
    finally:
        db_pool.putconn(conn)

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
@swag_from({
    'tags': ['Accommodations'],
    'summary': 'Add a new accommodation',
    'description': 'Adds a new accommodation with at least 3 images. Location data is auto-filled by geocoding the address. **Requires a valid JWT in the `Authorization` header.**',
    'security': [{'BearerAuth': []}],
    'requestBody': {
        'required': True,
        'content': {
            'multipart/form-data': {
                'schema': {
                    'type': 'object',
                    'properties': {
                        'name': {
                            'type': 'string',
                            'description': 'Name/title of the accommodation'
                        },
                        'guests': {
                            'type': 'string',
                            'description': 'Max number of guests (stored as string/int)'
                        },
                        'price': {
                            'type': 'string',
                            'description': 'Price per night'
                        },
                        'address': {
                            'type': 'string',
                            'description': 'Address used for geocoding'
                        },
                        'description': {
                            'type': 'string',
                            'description': 'Text description'
                        },
                        'iban': {
                            'type': 'string',
                            'description': 'IBAN for payment'
                        },
                        'images': {
                            'type': 'array',
                            'description': 'At least 3 images are required',
                            'items': {
                                'type': 'string',
                                'format': 'binary'
                            }
                        }
                    },
                    'required': ['name', 'guests', 'price', 'address', 'description', 'iban', 'images']
                }
            }
        }
    },
    'responses': {
        201: {
            'description': 'Accommodation created successfully',
            'content': {
                'application/json': {
                    'example': {
                        'success': True,
                        'message': 'Accommodation added',
                        'aid': 1
                    }
                }
            }
        },
        400: {
            'description': 'Bad Request (missing field or insufficient images)',
            'content': {
                'application/json': {
                    'example': {
                        'success': False,
                        'message': 'Missing required fields'
                    }
                }
            }
        },
        500: {
            'description': 'Server Error',
            'content': {
                'application/json': {
                    'example': {
                        'success': False,
                        'message': 'Server error',
                        'error': 'Debug info...'
                    }
                }
            }
        }
    }
})
@token_required
def add_accommodation():
    print("[DEBUG] add_accommodation() called for user ID:", request.user.get('uid'))
    conn = db_pool.getconn()
    print("[DEBUG] Obtained DB connection:", conn)
    try:
        name = request.form.get("name")
        max_guests = request.form.get("guests")
        price = request.form.get("price")
        address = request.form.get("address")
        description = request.form.get("description")
        iban = request.form.get("iban")  # Pridanie IBAN
        images = request.files.getlist("images")

        print(f"[DEBUG] Form inputs - name: {name}, guests: {max_guests}, price: {price}, address: {address}, iban: {iban}")
        print(f"[DEBUG] Number of images received: {len(images)}")

        latitude, longitude, location_city, location_country = geocode_address_full(address)
        print(f"[DEBUG] Geocoded address '{address}' to: latitude={latitude}, longitude={longitude}, city={location_city}, country={location_country}")

        if not all([name, location_city, location_country, max_guests, price, latitude, longitude, description, iban]):
            print("[DEBUG] Validation failed - missing one or more required fields")
            return jsonify({'success': False, 'message': 'Missing required fields'}), 400

        if not images or len(images) < 3:
            print("[DEBUG] Validation failed - insufficient images")
            return jsonify({'success': False, 'message': 'At least 3 images are required'}), 400

        with conn.cursor() as cur:
            print("[DEBUG] Executing INSERT into accommodations table")
            cur.execute("""
                INSERT INTO accommodations
                (name, location_city, location_country, owner_id, max_guests, latitude, longitude, price_per_night, description, iban)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                RETURNING aid;
            """, (
                name, location_city, location_country,
                request.user['uid'], max_guests, latitude, longitude,
                price, description, iban
            ))
            aid = cur.fetchone()[0]
            print(f"[DEBUG] New accommodation ID: {aid}")

            for img in images:
                print(f"[DEBUG] Inserting images for accommodation ID {aid})")
                cur.execute("INSERT INTO pictures (aid, image) VALUES (%s, %s);", (aid, psycopg2.Binary(img.read())))

            cur.execute("UPDATE users SET role = 'owner'::user_role WHERE uid = %s;", (request.user['uid'],))
            conn.commit()
            print("[DEBUG] Transaction committed successfully")

        return jsonify({'success': True, 'message': 'Accommodation added', 'aid': aid}), 201
    except Exception as e:
        print("Accommodation upload error:", e)
        try:
            conn.rollback()
            print("[DEBUG] Transaction rolled back due to error")
        except Exception as rollback_err:
            print("[ERROR] Rollback failed:", rollback_err)
        return jsonify({'success': False, 'message': 'Server error', 'error': str(e)}), 500
    finally:
        db_pool.putconn(conn)
        print("[DEBUG] Returned DB connection to the pool")

@app.route('/edit-accommodation/<int:aid>', methods=['PUT'])
@swag_from({
    'tags': ['Accommodations'],
    'summary': 'Edit existing accommodation',
    'description': (
        'Edits an existing accommodation by ID. The request must include at least 3 new images, '
        'as old ones get deleted. Requires a valid JWT in the `Authorization` header.'
    ),
    'security': [{'BearerAuth': []}],
    'parameters': [
        {
            'name': 'aid',
            'in': 'path',
            'required': True,
            'type': 'integer',
            'description': 'ID of the accommodation to edit'
        }
    ],
    'requestBody': {
        'required': True,
        'content': {
            'multipart/form-data': {
                'schema': {
                    'type': 'object',
                    'properties': {
                        'name': {'type': 'string'},
                        'guests': {'type': 'string'},
                        'price': {'type': 'string'},
                        'address': {'type': 'string'},
                        'description': {'type': 'string'},
                        'iban': {'type': 'string'},
                        'images': {
                            'type': 'array',
                            'description': 'At least 3 images required',
                            'items': {
                                'type': 'string',
                                'format': 'binary'
                            }
                        }
                    },
                    'required': [
                        'name', 'guests', 'price', 'address',
                        'description', 'iban', 'images'
                    ]
                }
            }
        }
    },
    'responses': {
        200: {
            'description': 'Accommodation updated successfully',
            'content': {
                'application/json': {
                    'example': {
                        'success': True,
                        'message': 'Accommodation updated',
                        'aid': 123
                    }
                }
            }
        },
        400: {
            'description': 'Missing required fields or fewer than 3 images',
            'content': {
                'application/json': {
                    'example': {
                        'success': False,
                        'message': 'Missing required fields'
                    }
                }
            }
        },
        404: {
            'description': 'Accommodation not found or unauthorized',
            'content': {
                'application/json': {
                    'example': {
                        'success': False,
                        'message': 'Accommodation not found or unauthorized'
                    }
                }
            }
        },
        500: {
            'description': 'Server error'
        }
    }
})
@token_required
def edit_accommodation(aid):
    uid = request.user['uid']

    conn = db_pool.getconn()
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

        with conn.cursor() as cursor:
            cursor.execute("SELECT * FROM accommodations WHERE aid = %s AND owner_id = %s;", (aid, uid))
            accommodation = cursor.fetchone()

            if not accommodation:
                return jsonify({'success': False, 'message': 'Accommodation not found or unauthorized'}), 404

            cursor.execute("""
                UPDATE accommodations SET
                    name = %s,
                    location_city = %s,
                    location_country = %s,
                    max_guests = %s,
                    price_per_night = %s,
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

            conn.commit()

        return jsonify({'success': True, 'message': 'Accommodation updated', 'aid': aid}), 200

    except Exception as e:
        print("Edit accommodation error:", e)
        return jsonify({'success': False, 'message': 'Server error', 'error': str(e)}), 500
    finally:
        db_pool.putconn(conn)

@app.route('/like_dislike', methods=['POST'])
@swag_from({
    'tags': ['Interactions'],
    'summary': 'Toggle like/dislike for an accommodation',
    'description': (
        'Toggles the like status for an accommodation. If a record exists, '
        'the accommodation is unliked; if not, it is liked. Requires a valid JWT in the Authorization header.'
    ),
    'security': [{'BearerAuth': []}],
    'requestBody': {
        'required': True,
        'content': {
            'application/json': {
                'schema': {
                    'type': 'object',
                    'properties': {
                        'aid': {
                            'type': 'integer',
                            'description': 'ID of the accommodation to like or dislike'
                        }
                    },
                    'required': ['aid']
                },
                'example': {
                    'aid': 12
                }
            }
        }
    },
    'responses': {
        200: {
            'description': 'Operation successful',
            'content': {
                'application/json': {
                    'example': {
                        'success': True,
                        'message': 'Liked accommodation',  # or "Unliked accommodation"
                        'aid': 12
                    }
                }
            }
        },
        400: {
            'description': 'Bad Request - Missing AID',
            'content': {
                'application/json': {
                    'example': {
                        'success': False,
                        'message': 'Missing AID'
                    }
                }
            }
        },
        500: {
            'description': 'Server error during the like/dislike operation',
            'content': {
                'application/json': {
                    'example': {
                        'success': False,
                        'message': 'Server error',
                        'error': 'Detailed error message'
                    }
                }
            }
        }
    }
})
@token_required
def like_dislike_accommodation() -> tuple[Response, int] | None:
    data = request.json or {}
    aid = data.get("aid")
    liker_uid = request.user["uid"]

    current_app.logger.debug(f"like_dislike called by uid={liker_uid}, aid={aid}")

    if not aid:
        return jsonify({"success": False, "message": "Missing AID"}), 400

    conn = db_pool.getconn()
    try:
        with conn.cursor() as cur:
            # 1. Who owns it and what's its name?
            cur.execute(
                """
                SELECT owner_id, name
                FROM accommodations
                WHERE aid = %s;
                """,
                (aid,),
            )
            row = cur.fetchone()
            if not row:
                return jsonify({"success": False, "message": "Accommodation not found"}), 404
            owner_id, acc_name = row

            cur.execute("SELECT email FROM users WHERE uid = %s;", (liker_uid,))
            liker_email_row = cur.fetchone()
            liker_email = liker_email_row[0] if liker_email_row else "unknown@email"

            current_app.logger.debug(f"Owner={owner_id}, acc_name={acc_name}, liker_email={liker_email}")

            cur.execute("SELECT 1 FROM liked WHERE uid = %s AND aid = %s;", (liker_uid, aid))
            already = cur.fetchone() is not None

            if already:
                cur.execute("DELETE FROM liked WHERE uid = %s AND aid = %s;", (liker_uid, aid))
                action = "unliked"
            else:
                cur.execute("INSERT INTO liked (uid, aid) VALUES (%s, %s);", (liker_uid, aid))
                action = "liked"

        conn.commit()

        # 4. Compose the sentence and push via WebSocket
        text = f'Your accommodation "{acc_name}" was {action} by {liker_email}'
        push_to_owner(owner_id, text)

        return (
            jsonify(
                {
                    "success": True,
                    "message": f"{action.capitalize()} accommodation",
                    "aid": aid,
                }
            ),
            200,
        )

    except Exception as exc:
        conn.rollback()
        current_app.logger.error("Like/dislike error: %s", exc)
        return (
            jsonify(
                {
                    "success": False,
                    "message": "Server error",
                    "error": str(exc),
                }
            ),
            500,
        )
    finally:
        db_pool.putconn(conn)

@app.route('/liked-accommodations', methods=['GET'])
@swag_from({
    'tags': ['Accommodations'],
    'summary': 'Retrieve liked accommodations',
    'description': (
        'Returns a list of accommodations that the authenticated user has liked, '
        'including details like accommodation ID, name, location (city and country), '
        'price per night.'
    ),
    'security': [{'BearerAuth': []}],
    'responses': {
        200: {
            'description': 'List of liked accommodations retrieved successfully',
            'content': {
                'application/json': {
                    'example': {
                        'success': True,
                        'liked_accommodations': [
                            {
                                'aid': 1,
                                'name': 'Hotel ABC',
                                'location': 'City, Country',
                                'price_per_night': 100,
                            }
                        ]
                    }
                }
            }
        },
        500: {
            'description': 'Server error',
            'content': {
                'application/json': {
                    'example': {
                        'success': False,
                        'message': 'Server error',
                        'error': 'Detailed error message here...'
                    }
                }
            }
        }
    }
})
@token_required
def get_liked_accommodations():
    uid = request.user['uid']
    conn = db_pool.getconn()

    try:
        with conn.cursor() as cursor:
            cursor.execute("""
                SELECT 
                    a.aid,
                    a.name,
                    a.location_city,
                    a.location_country,
                    a.price_per_night
                FROM liked l
                JOIN accommodations a ON a.aid = l.aid
                WHERE l.uid = %s
                LIMIT 20;
            """, (uid,))
            results = cursor.fetchall()

        accommodations = []
        for row in results:
            aid, name, city, country, price = row
            accommodations.append({
                'aid': aid,
                'name': name,
                'location': f"{city}, {country}",
                'price_per_night': price,
            })

        return jsonify({'success': True, 'liked_accommodations': accommodations}), 200

    except Exception as e:
        print("Get liked accommodations error:", e)
        return jsonify({'success': False, 'message': 'Server error', 'error': str(e)}), 500

    finally:
        db_pool.putconn(conn)

@app.route('/get-address', methods=['POST'])
@swag_from({
    'tags': ['Geocoding'],
    'summary': 'Retrieve address from GPS coordinates',
    'description': (
        'Performs reverse geocoding using OpenStreetMap Nominatim to convert GPS coordinates (latitude and longitude) '
        'into a human-readable address. Returns the address in the response.'
    ),
    'requestBody': {
        'required': True,
        'content': {
            'application/json': {
                'schema': {
                    'type': 'object',
                    'properties': {
                        'latitude': {
                            'type': 'number',
                            'example': 48.8566,
                            'description': 'Latitude coordinate'
                        },
                        'longitude': {
                            'type': 'number',
                            'example': 2.3522,
                            'description': 'Longitude coordinate'
                        }
                    },
                    'required': ['latitude', 'longitude']
                },
                'example': {
                    'latitude': 48.8566,
                    'longitude': 2.3522
                }
            }
        }
    },
    'responses': {
        200: {
            'description': 'Address retrieved successfully',
            'content': {
                'application/json': {
                    'example': {
                        'success': True,
                        'address': 'Paris, Île-de-France, France'
                    }
                }
            }
        },
        400: {
            'description': 'Missing or invalid coordinates',
            'content': {
                'application/json': {
                    'example': {
                        'success': False,
                        'message': 'Missing coordinates'
                    }
                }
            }
        },
        500: {
            'description': 'Server error during reverse geocoding',
            'content': {
                'application/json': {
                    'example': {
                        'success': False,
                        'message': 'Server error',
                        'error': 'Detailed error message'
                    }
                }
            }
        }
    }
})
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

@app.route('/accommodation/<int:aid>', methods=['GET'])
@swag_from({
    'tags': ['Accommodations'],
    'summary': 'Retrieve accommodation details',
    'description': (
        'Returns detailed information of an accommodation specified by its ID. '
        'The response includes the accommodation’s name, location (city and country), maximum guests, '
        'coordinates, price per night, description, owner email. '
        'Requires a valid JWT provided in the Authorization header.'
    ),
    'security': [{'BearerAuth': []}],
    'parameters': [
        {
            'name': 'aid',
            'in': 'path',
            'description': 'ID of the accommodation',
            'required': True,
            'type': 'integer'
        }
    ],
    'responses': {
        200: {
            'description': 'Accommodation details retrieved successfully',
            'content': {
                'application/json': {
                    'example': {
                        'success': True,
                        'accommodation': {
                            'aid': 1,
                            'name': 'Hotel Paradise',
                            'location': 'Paris, France',
                            'max_guests': 4,
                            'latitude': 48.8566,
                            'longitude': 2.3522,
                            'price_per_night': 150,
                            'description': 'A wonderful place to stay',
                            'owner_email': 'owner@example.com',
                        }
                    }
                }
            }
        },
        404: {
            'description': 'Accommodation not found',
            'content': {
                'application/json': {
                    'example': {
                        'success': False,
                        'message': 'Accommodation not found'
                    }
                }
            }
        },
        500: {
            'description': 'Server error',
            'content': {
                'application/json': {
                    'example': {
                        'success': False,
                        'message': 'Server error',
                        'error': 'Detailed error message'
                    }
                }
            }
        }
    }
})
@token_required
def get_accommodation_details(aid):

    conn = db_pool.getconn()
    try:
        with conn.cursor() as cursor:
            # Získaj základné info o ubytovaní + priemerné hodnotenie
            cursor.execute("""
                SELECT 
                    a.name,
                    a.location_city,
                    a.location_country,
                    a.max_guests,
                    a.latitude,
                    a.longitude,
                    a.price_per_night,
                    a.description,
                    u.email AS owner_email
                FROM accommodations a
                JOIN users u ON u.uid = a.owner_id
                WHERE a.aid = %s
                GROUP BY a.aid, u.email;
            """, (aid,))
            result = cursor.fetchone()

            if not result:
                return jsonify({'success': False, 'message': 'Accommodation not found'}), 404

            (name, city, country, guests, lat, lon, price, desc, owner_email) = result

            return jsonify({
                'success': True,
                'accommodation': {
                    'aid': aid,
                    'name': name,
                    'location': f"{city}, {country}",
                    'max_guests': guests,
                    'latitude': lat,
                    'longitude': lon,
                    'price_per_night': price,
                    'description': desc,
                    'owner_email': owner_email
                }
            }), 200


    except Exception as e:
        print("Get accommodation detail error:", e)
        return jsonify({'success': False, 'message': 'Server error', 'error': str(e)}), 500
    finally:
        db_pool.putconn(conn)

@app.route('/make-reservation', methods=['POST'])
@swag_from({
    'tags': ['Reservations'],
    'summary': 'Make a new reservation',
    'description': (
        'Creates a reservation for an accommodation if the requested date range is available. '
        'The JSON payload must include the accommodation ID (aid), a start date ("from"), and an end date ("to"). '
        'Requires a valid JWT provided in the Authorization header.'
    ),
    'security': [{'BearerAuth': []}],
    'requestBody': {
        'required': True,
        'content': {
            'application/json': {
                'schema': {
                    'type': 'object',
                    'properties': {
                        'aid': {
                            'type': 'integer',
                            'description': 'ID of the accommodation to reserve'
                        },
                        'from': {
                            'type': 'string',
                            'format': 'date',
                            'description': 'Reservation start date (format: YYYY-MM-DD)'
                        },
                        'to': {
                            'type': 'string',
                            'format': 'date',
                            'description': 'Reservation end date (format: YYYY-MM-DD)'
                        }
                    },
                    'required': ['aid', 'from', 'to']
                },
                'example': {
                    'aid': 5,
                    'from': '2025-05-01',
                    'to': '2025-05-10'
                }
            }
        }
    },
    'responses': {
        201: {
            'description': 'Reservation created successfully',
            'content': {
                'application/json': {
                    'example': {
                        'success': True,
                        'message': 'Reservation created',
                        'rid': 123
                    }
                }
            }
        },
        400: {
            'description': 'Missing required fields',
            'content': {
                'application/json': {
                    'example': {
                        'success': False,
                        'message': 'Missing required fields'
                    }
                }
            }
        },
        409: {
            'description': 'Accommodation already reserved in the given date range',
            'content': {
                'application/json': {
                    'example': {
                        'success': False,
                        'message': 'Accommodation is already reserved in this date range'
                    }
                }
            }
        },
        500: {
            'description': 'Server error',
            'content': {
                'application/json': {
                    'example': {
                        'success': False,
                        'message': 'Server error',
                        'error': 'Detailed error message'
                    }
                }
            }
        }
    }
})
@token_required
def make_reservation():
    data = request.json
    aid = data.get("aid")
    date_from = data.get("from")
    date_to = data.get("to")
    uid = request.user['uid']

    if not all([aid, date_from, date_to]):
        return jsonify({'success': False, 'message': 'Missing required fields'}), 400

    conn = db_pool.getconn()
    try:
        with conn.cursor() as cursor:
            # Over, či dátumy nie sú kolízne s existujúcou rezerváciou
            cursor.execute("""
                SELECT * FROM reservations
                WHERE aid = %s
                    AND NOT (%s > "To" OR %s < "From")
            """, (aid, date_from, date_to))
            conflict = cursor.fetchone()

            if conflict:
                return jsonify({'success': False, 'message': 'Accommodation is already reserved in this date range'}), 409

            # Ak nie je konflikt, vytvor rezerváciu
            cursor.execute("""
                INSERT INTO reservations (aid, "From", "To", reserved_by)
                VALUES (%s, %s, %s, %s)
                RETURNING rid;
            """, (aid, date_from, date_to, uid))
            rid = cursor.fetchone()[0]
            conn.commit()

        return jsonify({'success': True, 'message': 'Reservation created', 'rid': rid}), 201

    except Exception as e:
        print("Make reservation error:", e)
        return jsonify({'success': False, 'message': 'Server error', 'error': str(e)}), 500
    finally:
        db_pool.putconn(conn)

@app.route('/delete-reservation/<int:rid>', methods=['DELETE'])
@swag_from({
    'tags': ['Reservations'],
    'summary': 'Delete a reservation',
    'description': (
        'Deletes a reservation specified by its reservation ID (rid) if it belongs to the authenticated user. '
        'Requires a valid JWT provided in the Authorization header.'
    ),
    'security': [{'BearerAuth': []}],
    'parameters': [
        {
            'name': 'rid',
            'in': 'path',
            'required': True,
            'schema': {
                'type': 'integer'
            },
            'description': 'ID of the reservation to delete'
        }
    ],
    'responses': {
        200: {
            'description': 'Reservation deleted successfully',
            'content': {
                'application/json': {
                    'example': {
                        'success': True,
                        'message': 'Reservation 123 deleted'
                    }
                }
            }
        },
        404: {
            'description': 'Reservation not found or unauthorized',
            'content': {
                'application/json': {
                    'example': {
                        'success': False,
                        'message': 'Reservation not found or unauthorized'
                    }
                }
            }
        },
        500: {
            'description': 'Server error encountered while deleting the reservation',
            'content': {
                'application/json': {
                    'example': {
                        'success': False,
                        'message': 'Server error',
                        'error': 'Detailed error message'
                    }
                }
            }
        }
    }
})
@token_required
def delete_reservation(rid):
    uid = request.user['uid']

    conn = db_pool.getconn()
    try:
        with conn.cursor() as cursor:
            # Over, či rezerváciu vlastní prihlásený používateľ
            cursor.execute("SELECT * FROM reservations WHERE rid = %s AND reserved_by = %s;", (rid, uid))
            reservation = cursor.fetchone()

            if not reservation:
                return jsonify({'success': False, 'message': 'Reservation not found or unauthorized'}), 404

            # Vymaž rezerváciu
            cursor.execute("DELETE FROM reservations WHERE rid = %s;", (rid,))
            conn.commit()

        return jsonify({'success': True, 'message': f'Reservation {rid} deleted'}), 200

    except Exception as e:
        print("Delete reservation error:", e)
        return jsonify({'success': False, 'message': 'Server error', 'error': str(e)}), 500
    finally:
        db_pool.putconn(conn)

@app.route('/my-accommodations', methods=['GET'])
@swag_from({
    'tags': ['Accommodations'],
    'summary': 'Retrieve user-owned accommodations',
    'description': (
        'Retrieves a list of accommodations that belong to the authenticated user. '
        'Each accommodation returned includes its ID, name, city and country. '
        'This endpoint requires a valid JWT provided in the Authorization header.'
    ),
    'security': [{'BearerAuth': []}],
    'responses': {
        200: {
            'description': 'Accommodations retrieved successfully',
            'content': {
                'application/json': {
                    'example': {
                        'success': True,
                        'accommodations': [
                            {
                                'aid': 1,
                                'name': 'Hotel Sunshine',
                                'city': 'Miami',
                                'country': 'USA'
                            }
                        ]
                    }
                }
            }
        },
        500: {
            'description': 'Server error while retrieving accommodations',
            'content': {
                'application/json': {
                    'example': {
                        'success': False,
                        'message': 'Server error',
                        'error': 'Detailed error message'
                    }
                }
            }
        }
    }
})
@token_required
def get_my_accommodations():
    uid = request.user['uid']
    conn = db_pool.getconn()
    try:
        with conn.cursor() as cursor:
            cursor.execute("""
                SELECT 
                    a.aid,
                    a.name,
                    a.location_city,
                    a.location_country
                FROM accommodations a
                WHERE a.owner_id = %s;
            """, (uid,))
            results = cursor.fetchall()

        accommodations = []
        for row in results:
            aid, name, city, country = row
            accommodations.append({
                'aid': aid,
                'name': name,
                'city': city,
                'country': country
            })

        return jsonify({'success': True, 'accommodations': accommodations}), 200

    except Exception as e:
        print("Get my accommodations error:", e)
        return jsonify({'success': False, 'message': 'Server error', 'error': str(e)}), 500
    finally:
        db_pool.putconn(conn)


@app.route('/my-reservations', methods=['GET'])
@swag_from({
    'tags': ['Reservations'],
    'summary': 'Retrieve user reservations',
    'description': (
        'Returns a list of reservations made by the authenticated user. Each reservation includes '
        'its reservation ID (rid), the associated accommodation ID (aid), and the location (city and country) of the accommodation. '
        'This endpoint requires a valid JWT provided in the Authorization header.'
    ),
    'security': [{'BearerAuth': []}],
    'responses': {
        200: {
            'description': 'Reservations retrieved successfully',
            'content': {
                'application/json': {
                    'example': {
                        'success': True,
                        'reservations': [
                            {
                                'rid': 101,
                                'aid': 5,
                                'city': 'Paris',
                                'country': 'France'
                            },
                            {
                                'rid': 102,
                                'aid': 8,
                                'city': 'Berlin',
                                'country': 'Germany'
                            }
                        ]
                    }
                }
            }
        },
        500: {
            'description': 'Server error while retrieving reservations',
            'content': {
                'application/json': {
                    'example': {
                        'success': False,
                        'message': 'Server error',
                        'error': 'Detailed error message'
                    }
                }
            }
        }
    }
})
@token_required
def get_my_reservations():
    uid = request.user['uid']
    conn = db_pool.getconn()
    try:
        with conn.cursor() as cursor:
            cursor.execute("""
                SELECT 
                    r.rid,
                    r.aid,
                    a.location_city,
                    a.location_country
                FROM reservations r
                JOIN accommodations a ON r.aid = a.aid
                WHERE r.reserved_by = %s;
            """, (uid,))
            reservations = cursor.fetchall()

        result = []
        for rid, aid, city, country in reservations:
            result.append({
                "rid": rid,
                "aid": aid,
                "city": city,
                "country": country
            })

        return jsonify({'success': True, 'reservations': result}), 200

    except Exception as e:
        print("Get my reservations error:", e)
        return jsonify({'success': False, 'message': 'Server error', 'error': str(e)}), 500
    finally:
        db_pool.putconn(conn)

@app.route('/search-accommodations', methods=['POST'])
@swag_from({
    'tags': ['Accommodations'],
    'summary': 'Search accommodations',
    'description': (
        'Search for accommodations based on optional filters: location, date range, and number of guests. '
        'If a location is provided, it is geocoded to latitude and longitude and accommodations within a 50 km radius are returned. '
        'Additionally, if a date range is provided, accommodations with conflicting reservations are excluded. '
        'A valid JWT is required in the Authorization header.'
    ),
    'security': [{'BearerAuth': []}],
    'requestBody': {
        'required': True,
        'content': {
            'application/json': {
                'schema': {
                    'type': 'object',
                    'properties': {
                        'location': {
                            'type': 'string',
                            'description': 'Location to search for (e.g., "Zagreb")'
                        },
                        'from': {
                            'type': 'string',
                            'format': 'date',
                            'description': 'Start date for availability (format: YYYY-MM-DD)'
                        },
                        'to': {
                            'type': 'string',
                            'format': 'date',
                            'description': 'End date for availability (format: YYYY-MM-DD)'
                        },
                        'guests': {
                            'type': 'integer',
                            'description': 'Minimum number of guests the accommodation must support'
                        }
                    },
                    'example': {
                        "location": "Zagreb",
                        "from": "2025-06-01",
                        "to": "2025-06-10",
                        "guests": 2
                    }
                }
            }
        }
    },
    'responses': {
        200: {
            'description': 'Search results with matching accommodations',
            'content': {
                'application/json': {
                    'example': {
                        "success": True,
                        "results": [
                            {
                                "aid": 1,
                                "name": "Cozy Apartment",
                                "price_per_night": 80,
                                "location": "Zagreb, Croatia"
                            },
                            {
                                "aid": 2,
                                "name": "Modern Studio",
                                "price_per_night": 120,
                                "location": "Zagreb, Croatia"
                            }
                        ]
                    }
                }
            }
        },
        500: {
            'description': 'Server error during search',
            'content': {
                'application/json': {
                    'example': {
                        "success": False,
                        "message": "Server error",
                        "error": "Detailed error message here..."
                    }
                }
            }
        }
    }
})
@token_required
def search_accommodations():
    data = request.json
    location = data.get("location")  # napr. "Zagreb"
    date_from = data.get("from")
    date_to = data.get("to")
    guests = data.get("guests")

    latitude = longitude = None
    if location:
        lat, lon, _, _ = geocode_address_full(location)
        latitude, longitude = lat, lon

    conn = db_pool.getconn()
    try:
        with conn.cursor() as cursor:
            query = """
                SELECT
                    a.aid,
                    a.name,
                    a.price_per_night,
                    a.location_city,
                    a.location_country,
                    a.latitude,
                    a.longitude
                FROM accommodations a
                WHERE TRUE
            """
            params = []

            # Filtrovanie podľa počtu hostí
            if guests:
                query += " AND a.max_guests >= %s"
                params.append(guests)

            # Filtrovanie podľa vzdialenosti (Haversine formula)
            if latitude and longitude:
                query += """
                    AND (
                        6371000 * acos(
                            cos(radians(%s)) * cos(radians(a.latitude)) *
                            cos(radians(a.longitude) - radians(%s)) +
                            sin(radians(%s)) * sin(radians(a.latitude))
                        )
                    ) < 50000
                """
                params.extend([latitude, longitude, latitude])

            cursor.execute(query, tuple(params))
            accommodations = cursor.fetchall()

            result = []
            for aid, name, price, city, country, lat, lon in accommodations:
                # Over dostupnosť podľa dátumov
                if date_from and date_to:
                    cursor.execute("""
                        SELECT 1 FROM reservations
                        WHERE aid = %s
                        AND NOT (%s > "To" OR %s < "From")
                    """, (aid, date_from, date_to))
                    reserved = cursor.fetchone()
                    if reserved:
                        continue

                result.append({
                    "aid": aid,
                    "name": name,
                    "price_per_night": price,
                    "location": f"{city}, {country}"
                })

        return jsonify({"success": True, "results": result}), 200

    except Exception as e:
        conn.rollback()
        print("Search accommodations error:", e)
        return jsonify({
            "success": False,
            "message": "Server error",
            "error": str(e)
        }), 500
    finally:
        db_pool.putconn(conn)

@app.route('/accommodation-confirmation/<int:aid>', methods=['GET'])
@swag_from({
    'tags': ['Accommodations'],
    'summary': 'Confirm accommodation details',
    'description': (
        'Retrieves the confirmation details of an accommodation, including the nightly price and the IBAN, '
        'using the provided accommodation ID (aid). Requires a valid JWT provided in the Authorization header.'
    ),
    'security': [{'BearerAuth': []}],
    'parameters': [
        {
            'name': 'aid',
            'in': 'path',
            'required': True,
            'schema': {
                'type': 'integer'
            },
            'description': 'The ID of the accommodation to confirm'
        }
    ],
    'responses': {
        200: {
            'description': 'Accommodation confirmation details retrieved successfully',
            'content': {
                'application/json': {
                    'example': {
                        'success': True,
                        'price': 150,
                        'iban': 'HRkk 1234 5678 9012 3456 7890'
                    }
                }
            }
        },
        404: {
            'description': 'Accommodation not found',
            'content': {
                'application/json': {
                    'example': {
                        'success': False,
                        'message': 'Accommodation not found'
                    }
                }
            }
        },
        500: {
            'description': 'Server error',
            'content': {
                'application/json': {
                    'example': {
                        'success': False,
                        'message': 'Server error',
                        'error': 'Detailed error message'
                    }
                }
            }
        }
    }
})
@token_required
def accommodation_confirmation(aid):
    conn = db_pool.getconn()
    try:
        with conn.cursor() as cursor:
            cursor.execute("""
                SELECT price_per_night, iban FROM accommodations WHERE aid = %s;
            """, (aid,))
            accommodation = cursor.fetchone()

            if not accommodation:
                return jsonify({'success': False, 'message': 'Accommodation not found'}), 404

            price, iban = accommodation
            return jsonify({'success': True, 'price': price, 'iban': iban}), 200

    except Exception as e:
        print("Accommodation confirmation error:", e)
        return jsonify({'success': False, 'message': 'Server error', 'error': str(e)}), 500
    finally:
        db_pool.putconn(conn)

@app.route('/main-screen-accommodations', methods=['GET'])
@swag_from({
    'tags': ['Accommodations'],
    'summary': 'Retrieve main screen accommodations',
    'description': (
        'Returns a random selection of 5 accommodations to be displayed on the main screen. '
        'Each accommodation includes its ID, name, price per night, a location string (city and country). Requires a valid JWT in the Authorization header.'
    ),
    'security': [{'BearerAuth': []}],
    'responses': {
        200: {
            'description': 'Main screen accommodations retrieved successfully',
            'content': {
                'application/json': {
                    'example': {
                        "success": True,
                        "results": [
                            {
                                "aid": 1,
                                "name": "Cozy Apartment",
                                "price_per_night": 80,
                                "location": "Zagreb, Croatia"
                            },
                            {
                                "aid": 2,
                                "name": "Modern Studio",
                                "price_per_night": 120,
                                "location": "Zagreb, Croatia"
                            }
                        ]
                    }
                }
            }
        },
        500: {
            'description': 'Server error while retrieving accommodations',
            'content': {
                'application/json': {
                    'example': {
                        "success": False,
                        "message": "Server error",
                        "error": "Detailed error message"
                    }
                }
            }
        }
    }
})
@token_required
def main_screen_accommodations():
    uid = request.user['uid']
    conn = db_pool.getconn()

    try:
        with conn.cursor() as cursor:
            query = """
                SELECT
                    a.aid,
                    a.name,
                    a.price_per_night,
                    a.location_city,
                    a.location_country,
                    CASE WHEN l.aid IS NOT NULL THEN TRUE ELSE FALSE END AS is_liked
                FROM accommodations a
                LEFT JOIN liked l ON a.aid = l.aid AND l.uid = %s
                ORDER BY RANDOM()
                LIMIT 5;
            """
            cursor.execute(query, (uid,))
            accommodations = cursor.fetchall()

        result = [
            {
                "aid": aid,
                "name": name,
                "price_per_night": price,
                "location": f"{city}, {country}",
                "is_liked": is_liked
            }
            for aid, name, price, city, country, is_liked in accommodations
        ]

        return jsonify({"success": True, "results": result}), 200

    except Exception as e:
        conn.rollback()
        print("Main screen accommodations error:", e)
        return jsonify({
            "success": False,
            "message": "Server error",
            "error": str(e)
        }), 500
    finally:
        db_pool.putconn(conn)

@app.route('/accommodations/<int:aid>/image/<int:image_index>', methods=['GET'])
@swag_from({
    'tags': ['Accommodations'],
    'summary': 'Retrieve a specific accommodation image',
    'description': (
        'Fetches a specific image for the given accommodation (aid) as a binary stream. '
        'The image_index parameter represents poradové číslo obrázka (začínajúc od 1). '
        'Odpoveď obsahuje HTTP hlavičku Content-Type nastavenú na "image/jpeg".'
    ),
    'parameters': [
        {
            'name': 'aid',
            'in': 'path',
            'description': 'Unique identifier of the accommodation',
            'required': True,
            'type': 'integer'
        },
        {
            'name': 'image_index',
            'in': 'path',
            'description': 'Index of the image to fetch (starting at 1)',
            'required': True,
            'type': 'integer'
        }
    ],
    'responses': {
        200: {
            'description': 'Image stream returned successfully',
            'content': {
                'image/jpeg': {
                    'schema': {
                        'type': 'string',
                        'format': 'binary'
                    }
                }
            }
        },
        400: {
            'description': 'Invalid parameter: image_index must be 1 or greater',
            'content': {
                'application/json': {
                    'example': {
                        'success': False,
                        'message': 'Zlý Parameter image_index'
                    }
                }
            }
        },
        404: {
            'description': 'Image not found for the given accommodation',
            'content': {
                'application/json': {
                    'example': {
                        'success': False,
                        'message': 'Obrázok nebol nájdený'
                    }
                }
            }
        },
        500: {
            'description': 'Server error',
            'content': {
                'application/json': {
                    'example': {
                        'success': False,
                        'message': 'Server error',
                        'error': 'Detailed error message'
                    }
                }
            }
        }
    },
    'security': [
        {
            'BearerAuth': []
        }
    ]
})
@token_required
def get_accommodation_image(aid, image_index):
    if image_index < 1:
        abort(400, description="Invalid image_index")

    conn = db_pool.getconn()
    try:
        with conn.cursor() as cur:
            offset = image_index - 1
            cur.execute(
                """
                SELECT image
                FROM pictures
                WHERE aid = %s
                ORDER BY pid ASC
                LIMIT 1 OFFSET %s;
                """,
                (aid, offset)
            )
            row = cur.fetchone()
        if not row:
            abort(404, description="Image not found")

        resp = Response(row[0], mimetype='image/jpeg')
        resp.headers['Cache-Control'] = 'public, max-age=3600'
        return resp
    except Exception as e:
        current_app.logger.error(f"Error fetching image aid={aid} idx={image_index}: {e}")
        abort(500, description="Server error")
    finally:
        db_pool.putconn(conn)

@app.route('/upcoming_reservations', methods=['GET'])
@token_required
def upcoming_reservations():
    current_app.logger.debug("→ entered upcoming_reservations")

    payload = request.user
    current_app.logger.debug("JWT payload: %r", payload)

    user_id = payload.get('uid')
    if not user_id:
        current_app.logger.warning("Missing user_id in token payload")
        return jsonify({'message': 'Invalid token: user_id claim missing'}), 401
    current_app.logger.debug("Authenticated user_id=%s", user_id)

    today = date.today()
    current_app.logger.debug("Using date filter from %s onward", today)

    conn = db_pool.getconn()
    try:
        cur = conn.cursor()
        query = (
            'SELECT "From", "To" '
            'FROM reservations '
            'WHERE reserved_by = %s AND "From" >= %s '
            'ORDER BY "From"'
        )
        current_app.logger.debug("Executing SQL: %s with params (%s, %s)", query, user_id, today)
        cur.execute(query, (user_id, today))

        rows = cur.fetchall()
        current_app.logger.debug("SQL returned %d rows", len(rows))

        data = []
        for idx, (start, end) in enumerate(rows, 1):
            iso_from = start.isoformat()
            iso_to   = end.isoformat()
            current_app.logger.debug(" Row %d: from=%s to=%s", idx, iso_from, iso_to)
            data.append({'from': iso_from, 'to': iso_to})

        current_app.logger.debug("Returning %d reservations", len(data))
        return jsonify(data), 200

    except Exception as e:
        current_app.logger.error("Database error fetching reservations", exc_info=e)
        abort(500, description="Server error")
    finally:
        db_pool.putconn(conn)


if __name__ == "__main__":
    socketio.run(host="0.0.0.0", port=5001)