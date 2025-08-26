import os
from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
import psycopg2
import psycopg2.extras
import bcrypt
from datetime import date, timedelta
from dotenv import load_dotenv
import io
import cloudinary
import cloudinary.uploader
import requests

load_dotenv()

app = Flask(__name__)
CORS(app)

DATABASE_URL = os.getenv("NEON_DATABASE_URL")
ENCRYPTION_KEY = os.getenv("ENCRYPTION_KEY")

cloudinary.config(
  cloud_name = os.getenv("CLOUDINARY_CLOUD_NAME"),
  api_key = os.getenv("CLOUDINARY_API_KEY"),
  api_secret = os.getenv("CLOUDINARY_API_SECRET"),
  secure = True
)

def get_db_connection():
    try:
        conn = psycopg2.connect(DATABASE_URL)
        return conn
    except Exception as e:
        print(f"Database connection error: {e}")
        return None

# --- AUTHENTICATION API ---
@app.route('/api/signup', methods=['POST'])
def signup():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    if not username or not password: return jsonify({"error": "Username and password are required"}), 400
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    conn = get_db_connection()
    if not conn: return jsonify({"error": "Database connection failed"}), 500
    try:
        with conn.cursor() as cur:
            start_date = date.today()
            expiry_date = start_date + timedelta(days=30)
            cur.execute("INSERT INTO users (username, password, trial_start_date, expiry_date, subscription_type) VALUES (%s, %s, %s, %s, %s)", (username, hashed_password.decode('utf-8'), start_date, expiry_date, 'trial'))
        conn.commit()
        return jsonify({"message": "User created successfully"}), 201
    except psycopg2.IntegrityError:
        conn.rollback()
        return jsonify({"error": "Username already exists"}), 409
    except Exception as e:
        conn.rollback()
        return jsonify({"error": str(e)}), 500
    finally:
        if conn: conn.close()

@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    if not username or not password: return jsonify({"error": "Username and password are required"}), 400
    conn = get_db_connection()
    if not conn: return jsonify({"error": "Database connection failed"}), 500
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.DictCursor) as cur:
            cur.execute("SELECT * FROM users WHERE username = %s", (username,))
            user = cur.fetchone()
        if user and bcrypt.checkpw(password.encode('utf-8'), user['password'].encode('utf-8')):
            if user['expiry_date'] is not None and date.today() > user['expiry_date']:
                return jsonify({"error": "Your subscription has expired"}), 403
            return jsonify({
                "message": "Login successful",
                "userId": user['id'],
                "subscriptionType": user['subscription_type'],
                "expiryDate": user['expiry_date'].isoformat() if user['expiry_date'] else None
            }), 200
        else:
            return jsonify({"error": "Invalid username or password"}), 401
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        if conn: conn.close()

@app.route('/api/user/change-password/<int:user_id>', methods=['POST'])
def change_password(user_id):
    data = request.get_json()
    current_pass = data.get('currentPassword')
    new_pass = data.get('newPassword')
    conn = get_db_connection()
    if not conn: return jsonify({"error": "Database connection failed"}), 500
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.DictCursor) as cur:
            cur.execute("SELECT password FROM users WHERE id = %s", (user_id,))
            user = cur.fetchone()
            if not user: return jsonify({"error": "User not found"}), 404
            if bcrypt.checkpw(current_pass.encode('utf-8'), user['password'].encode('utf-8')):
                new_hashed_password = bcrypt.hashpw(new_pass.encode('utf-8'), bcrypt.gensalt())
                cur.execute("UPDATE users SET password = %s WHERE id = %s", (new_hashed_password.decode('utf-8'), user_id))
                conn.commit()
                return jsonify({"message": "Password changed successfully"}), 200
            else:
                return jsonify({"error": "Incorrect current password"}), 403
    except Exception as e:
        conn.rollback()
        return jsonify({"error": str(e)}), 500
    finally:
        if conn: conn.close()

# --- GENERIC DELETE ROUTE ---
def delete_item(table, item_id):
    conn = get_db_connection()
    if not conn: return jsonify({"error": "Database connection failed"}), 500
    try:
        with conn.cursor() as cur:
            safe_tables = {"contacts": "contacts", "accounts": "accounts", "cards": "cards", "files": "files", "notes": "notes"}
            if table not in safe_tables:
                return jsonify({"error": "Invalid table specified"}), 400
            
            if table == "files":
                cur.execute(f"UPDATE files SET is_deleted = TRUE WHERE id = %s", (item_id,))
            else:
                cur.execute(f"DELETE FROM {safe_tables[table]} WHERE id = %s", (item_id,))
        conn.commit()
        return jsonify({"message": f"Item from {table} deleted successfully"}), 200
    except Exception as e:
        conn.rollback()
        return jsonify({"error": str(e)}), 500
    finally:
        if conn: conn.close()

# --- CONTACTS API ---
@app.route('/api/contacts/<int:user_id>', methods=['GET'])
def get_contacts(user_id):
    conn = get_db_connection()
    if not conn: return jsonify({"error": "Database connection failed"}), 500
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.DictCursor) as cur:
            cur.execute("SELECT id, name, phone, email, notes, whatsapp, facebook, instagram, youtube FROM contacts WHERE user_id = %s ORDER BY name", (user_id,))
            items = [dict(row) for row in cur.fetchall()]
        return jsonify(items), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        if conn: conn.close()

@app.route('/api/contacts/<int:item_id>', methods=['DELETE'])
def delete_contact(item_id): return delete_item('contacts', item_id)

@app.route('/api/contacts', methods=['POST', 'PUT'])
def manage_contact():
    data = request.get_json()
    phones = data.get('phones', [])
    phones = [p for p in phones if p]
    conn = get_db_connection()
    if not conn: return jsonify({"error": "Database connection failed"}), 500
    try:
        with conn.cursor() as cur:
            if request.method == 'POST':
                cur.execute("INSERT INTO contacts (user_id, name, phone, email, notes, whatsapp, facebook, instagram, youtube) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)", (data['userId'], data['name'], phones, data['email'], data['notes'], data['whatsapp'], data['facebook'], data['instagram'], data['youtube']))
            elif request.method == 'PUT':
                cur.execute("UPDATE contacts SET name=%s, phone=%s, email=%s, notes=%s, whatsapp=%s, facebook=%s, instagram=%s, youtube=%s WHERE id=%s", (data['name'], phones, data['email'], data['notes'], data['whatsapp'], data['facebook'], data['instagram'], data['youtube'], data['id']))
        conn.commit()
        return jsonify({"message": "Contact saved successfully"}), 200
    except Exception as e:
        conn.rollback()
        return jsonify({"error": str(e)}), 500
    finally:
        if conn: conn.close()

# --- ACCOUNTS API ---
@app.route('/api/accounts/<int:user_id>', methods=['GET'])
def get_accounts(user_id):
    conn = get_db_connection()
    if not conn: return jsonify({"error": "Database connection failed"}), 500
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.DictCursor) as cur:
            query = "SELECT id, website, username, pgp_sym_decrypt(encrypted_password, %s)::text as password FROM accounts WHERE user_id = %s ORDER BY website"
            cur.execute(query, (ENCRYPTION_KEY, user_id))
            items = [dict(row) for row in cur.fetchall()]
        return jsonify(items), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        if conn: conn.close()

@app.route('/api/accounts/<int:item_id>', methods=['DELETE'])
def delete_account(item_id): return delete_item('accounts', item_id)

@app.route('/api/accounts', methods=['POST', 'PUT'])
def manage_account():
    data = request.get_json()
    conn = get_db_connection()
    if not conn: return jsonify({"error": "Database connection failed"}), 500
    try:
        with conn.cursor() as cur:
            if request.method == 'POST':
                cur.execute("INSERT INTO accounts (user_id, website, username, encrypted_password) VALUES (%s, %s, %s, pgp_sym_encrypt(%s, %s))", (data['userId'], data['website'], data['username'], data['password'], ENCRYPTION_KEY))
            elif request.method == 'PUT':
                cur.execute("UPDATE accounts SET website=%s, username=%s, encrypted_password=pgp_sym_encrypt(%s, %s) WHERE id=%s", (data['website'], data['username'], data['password'], ENCRYPTION_KEY, data['id']))
        conn.commit()
        return jsonify({"message": "Account saved successfully"}), 200
    except Exception as e:
        conn.rollback()
        return jsonify({"error": str(e)}), 500
    finally:
        if conn: conn.close()

# --- CARDS API ---
@app.route('/api/cards/<int:user_id>', methods=['GET'])
def get_cards(user_id):
    conn = get_db_connection()
    if not conn: return jsonify({"error": "Database connection failed"}), 500
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.DictCursor) as cur:
            query = "SELECT id, card_name, pgp_sym_decrypt(encrypted_card_number, %s)::text as card_number, expiry_date, pgp_sym_decrypt(encrypted_cvv, %s)::text as cvv FROM cards WHERE user_id = %s ORDER BY card_name"
            cur.execute(query, (ENCRYPTION_KEY, ENCRYPTION_KEY, user_id))
            items = [dict(row) for row in cur.fetchall()]
        return jsonify(items), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        if conn: conn.close()

@app.route('/api/cards/<int:item_id>', methods=['DELETE'])
def delete_card(item_id): return delete_item('cards', item_id)

@app.route('/api/cards', methods=['POST', 'PUT'])
def manage_card():
    data = request.get_json()
    conn = get_db_connection()
    if not conn: return jsonify({"error": "Database connection failed"}), 500
    try:
        with conn.cursor() as cur:
            if request.method == 'POST':
                cur.execute("INSERT INTO cards (user_id, card_name, encrypted_card_number, expiry_date, encrypted_cvv) VALUES (%s, %s, pgp_sym_encrypt(%s, %s), %s, pgp_sym_encrypt(%s, %s))", (data['userId'], data['card_name'], data['card_number'], ENCRYPTION_KEY, data['expiry_date'], data['cvv'], ENCRYPTION_KEY))
            elif request.method == 'PUT':
                cur.execute("UPDATE cards SET card_name=%s, encrypted_card_number=pgp_sym_encrypt(%s, %s), expiry_date=%s, encrypted_cvv=pgp_sym_encrypt(%s, %s) WHERE id=%s", (data['card_name'], data['card_number'], ENCRYPTION_KEY, data['expiry_date'], data['cvv'], ENCRYPTION_KEY, data['id']))
        conn.commit()
        return jsonify({"message": "Card saved successfully"}), 201
    except Exception as e:
        conn.rollback()
        return jsonify({"error": str(e)}), 500
    finally:
        if conn: conn.close()

# --- FILES API ---
@app.route('/api/files/<int:user_id>', methods=['GET'])
def get_files(user_id):
    conn = get_db_connection()
    if not conn: return jsonify({"error": "Database connection failed"}), 500
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.DictCursor) as cur:
            cur.execute("SELECT id, filename, file_url FROM files WHERE user_id = %s AND is_deleted = FALSE ORDER BY filename", (user_id,))
            items = [dict(row) for row in cur.fetchall()]
        return jsonify(items), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        if conn: conn.close()

@app.route('/api/files/<int:item_id>', methods=['DELETE'])
def delete_file(item_id): return delete_item('files', item_id)

@app.route('/api/files/upload/<int:user_id>', methods=['POST'])
def upload_file(user_id):
    if 'file' not in request.files: return jsonify({"error": "No file part"}), 400
    file_to_upload = request.files['file']
    if file_to_upload.filename == '': return jsonify({"error": "No selected file"}), 400
    try:
        upload_result = cloudinary.uploader.upload(file_to_upload, resource_type="auto")
        file_url = upload_result.get('secure_url')
        if not file_url: return jsonify({"error": "Could not upload file to Cloudinary"}), 500
        conn = get_db_connection()
        if not conn: return jsonify({"error": "Database connection failed"}), 500
        with conn.cursor() as cur:
            cur.execute("INSERT INTO files (user_id, filename, file_url) VALUES (%s, %s, %s)", (user_id, file_to_upload.filename, file_url))
        conn.commit()
        return jsonify({"message": "File uploaded successfully"}), 201
    except Exception as e:
        if 'conn' in locals() and conn: conn.rollback()
        return jsonify({"error": str(e)}), 500
    finally:
        if 'conn' in locals() and conn: conn.close()

@app.route('/api/files/download/<int:file_id>', methods=['GET'])
def download_file_route(file_id):
    conn = get_db_connection()
    if not conn: return "Database connection failed", 500
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.DictCursor) as cur:
            cur.execute("SELECT filename, file_url FROM files WHERE id = %s", (file_id,))
            file_record = cur.fetchone()
        if file_record and file_record['file_url']:
            response = requests.get(file_record['file_url'], stream=True)
            if response.status_code == 200:
                return send_file(io.BytesIO(response.content), download_name=file_record['filename'], as_attachment=True)
            else: return "Could not fetch file from storage.", 500
        else: return "File not found.", 404
    except Exception as e:
        return str(e), 500
    finally:
        if conn: conn.close()

# --- NOTES API ---
@app.route('/api/notes/<int:user_id>', methods=['GET'])
def get_notes(user_id):
    conn = get_db_connection()
    if not conn: return jsonify({"error": "Database connection failed"}), 500
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.DictCursor) as cur:
            cur.execute("SELECT id, title, content FROM notes WHERE user_id = %s ORDER BY title", (user_id,))
            items = [dict(row) for row in cur.fetchall()]
        return jsonify(items), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        if conn: conn.close()

@app.route('/api/notes/<int:item_id>', methods=['DELETE'])
def delete_note(item_id):
    return delete_item('notes', item_id)

@app.route('/api/notes', methods=['POST', 'PUT'])
def manage_note():
    data = request.get_json()
    conn = get_db_connection()
    if not conn: return jsonify({"error": "Database connection failed"}), 500
    try:
        with conn.cursor() as cur:
            if request.method == 'POST':
                cur.execute("INSERT INTO notes (user_id, title, content) VALUES (%s, %s, %s)", (data['userId'], data['title'], data['content']))
            elif request.method == 'PUT':
                cur.execute("UPDATE notes SET title=%s, content=%s WHERE id=%s", (data['title'], data['content'], data['id']))
        conn.commit()
        return jsonify({"message": "Note saved successfully"}), 200
    except Exception as e:
        conn.rollback()
        return jsonify({"error": str(e)}), 500
    finally:
        if conn: conn.close()