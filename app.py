from flask import Flask, render_template, request, jsonify, make_response
import sqlite3
import os
import requests
import imaplib
import email
from email.header import decode_header
import time
import threading
import dotenv
from datetime import datetime
import base64

dotenv.load_dotenv()

app = Flask(__name__)
DB_FILE = "appointments.db"

# Pre "specialpassword" autentifikáciu
SESSION_SALT = os.getenv("SESSION_SALT", "DefaultSaltValue")

IMAP_EMAIL = os.getenv("IMAP_EMAIL")
IMAP_PASSWORD = os.getenv("IMAP_PASSWORD")
IMAP_SERVER = os.getenv("IMAP_SERVER")

# Ak je SHIFT_DEBUG nastavený na True, budeme vypisovať viac logov
SHIFT_DEBUG = os.getenv("SHIFT_DEBUG", "False").lower() in ["true", "1"]

lock = threading.Lock()

###############################################################################
#                           DATABASE INIT & HELPERS                           #
###############################################################################
def get_db_connection():
    return sqlite3.connect(DB_FILE)

def mark_booking_as_sent(booking_id: int):
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute("UPDATE appointments SET sended=1 WHERE id=?", (booking_id,))
        conn.commit()

def init_db():
    with get_db_connection() as conn:
        c = conn.cursor()
        # Tabuľka pre lokálne "appointments"
        c.execute('''
            CREATE TABLE IF NOT EXISTS appointments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                date TEXT NOT NULL,
                timeSlot TEXT NOT NULL,
                sended BOOLEAN DEFAULT 0
            )
        ''')
        # Tabuľka pre používateľov (Tesco credentials + specialpassword)
        c.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                password TEXT NOT NULL,
                priority INTEGER DEFAULT 1,
                specialpassword TEXT
            )
        ''')
        conn.commit()

init_db()

def format_time_without_seconds(time_str: str) -> str:
    """Napriklad '14:00:00' -> '14:00'."""
    return ":".join(time_str.split(":")[:2])

def normalize_date(db_date: str) -> str:
    """Napriklad '2025-03-13T14:00:00Z' -> '2025-03-13'."""
    try:
        dt = datetime.fromisoformat(db_date.replace("Z", "+00:00"))
        return dt.strftime("%Y-%m-%d")
    except ValueError:
        return db_date

###############################################################################
#                       SPECIAL PASSWORD AUTH FUNCTIONS                       #
###############################################################################
def get_db_user_by_id(user_id: int):
    """
    Získa údaje o používateľovi z DB: (id, username, specialpassword).
    Tesco credentials sú uložené v `username` a `password`,
    plus lokálny 'specialpassword' pre cookie-based login.
    """
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute("SELECT id, username, specialpassword FROM users WHERE id=?", (user_id,))
        row = c.fetchone()
    if row:
        return {
            "id": row[0],
            "username": row[1],
            "specialpassword": row[2]
        }
    return None

def encode_auth_cookie(user_id: int, specialpassword: str) -> str:
    """
    Vytvorí base64 token: base64("user_id:specialpassword:SESSION_SALT")
    Ktorý sa ukladá do HttpOnly cookie pre autentifikáciu.
    """
    raw = f"{user_id}:{specialpassword}:{SESSION_SALT}"
    return base64.b64encode(raw.encode("utf-8")).decode("utf-8")

def decode_auth_cookie(token: str):
    """
    Dekóduje cookie token, vráti (user_id_str, specialpassword) alebo (None, None).
    Musí sa zhodovať so zadaným salt.
    """
    try:
        decoded = base64.b64decode(token.encode("utf-8")).decode("utf-8")
        parts = decoded.split(":")
        if len(parts) != 3:
            return None, None
        if parts[2] != SESSION_SALT:
            return None, None
        return parts[0], parts[1]
    except:
        return None, None

def require_auth(func):
    """
    Dekorátor, ktorý zabezpečí prítomnosť platnej AuthToken cookie.
    Ak je cookie platná, pripojí user_id do flask.g pre použitie v routách.
    """
    from functools import wraps
    from flask import g

    @wraps(func)
    def wrapper(*args, **kwargs):
        token = request.cookies.get("AuthToken")
        if not token:
            return jsonify({"error": "❌ Unauthorized. No auth cookie."}), 401

        user_id_str, spass = decode_auth_cookie(token)
        if not user_id_str or not spass:
            return jsonify({"error": "❌ Unauthorized. Bad cookie data."}), 401

        # Overenie v DB
        user_data = get_db_user_by_id(int(user_id_str))
        if not user_data or user_data["specialpassword"] != spass:
            return jsonify({"error": "❌ Unauthorized. Invalid user or specialpassword."}), 401

        g.user_id = int(user_id_str)
        return func(*args, **kwargs)
    return wrapper

###############################################################################
#                         DTube SHIFT-RELATED FUNCTIONS                       #
###############################################################################
def auth_me_for_user(tesco_username: str, tesco_password: str):
    """
    Vykoná DTube autentifikáciu s Tesco credentials.
    Vráti token (string) ak uspeje, inak None.
    """
    if SHIFT_DEBUG:
        print(f"🔑 [DEBUG] Authenticating '{tesco_username}' with DTube...")

    # Combine username and password with a colon
    credentials = f"{tesco_username}:{tesco_password}"

    # Encode to Base64
    encoded_credentials = base64.b64encode(credentials.encode()).decode()

    #Construct headers with Basic Auth
    headers = {
        "Authorization": f"Basic {encoded_credentials}",
        "Content-Type": "application/json",
        "Accept": "application/json"
    }

    payload = {
        "username": tesco_username,
        "password": tesco_password
    }

    resp = requests.post(
        "https://dtube.tesco-europe.com/DTUBE_RESTAPI/jaxrs/USER/authenticateUser",
        headers=headers, json=payload
    )
    if SHIFT_DEBUG:
        print(f"🔑 [DEBUG] auth_me_for_user -> code={resp.status_code}, body={resp.text}")

    if resp.status_code == 200 and resp.json().get("RESMSG") == "Logged":
        token = resp.json()["RESMSGDET"]
        print(f"✅ [INFO] Authenticated user '{tesco_username}' with DTube.")
        return token
    else:
        print(f"❌ [ERROR] Could not auth user '{tesco_username}': {resp.text}")
        return None

def get_all_shifts_for_user(token: str):
    """
    Zavolá SHIFT/ShiftListWorker s user tokenom.
    Vráti zoznam shiftov alebo [] pri chybe.
    """
    resp = requests.post(
        "https://dtube.tesco-europe.com/DTUBE_RESTAPI/jaxrs/SHIFT/ShiftListWorker",
        json={"username": token, "datefrom": ""}
    )
    if SHIFT_DEBUG:
        print(f"📝 [DEBUG] get_all_shifts_for_user -> code={resp.status_code}, body={resp.text}")

    if resp.status_code in [200, 204]:
        data = resp.json() or {}
        return data.get("shifts", [])
    else:
        print("❌ [ERROR] Could not retrieve SHIFT data from DTube.")
        return []

def get_all_db_users():
    """
    Vráti všetkých používateľov z DB: {id, username, password, priority, specialpassword}
    """
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute("SELECT id, username, password, priority, specialpassword FROM users")
        rows = c.fetchall()

    result = []
    for r in rows:
        result.append({
            "id": r[0],
            "username": r[1],      # Tesco username
            "password": r[2],      # Tesco password
            "priority": r[3],
            "specialpassword": r[4]
        })
    return result

def get_bookings_for_user(user_id: int):
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute("SELECT id, date, timeSlot FROM appointments WHERE user_id=? AND sended=0", (user_id,))
        rows = c.fetchall()
    return [{"id": row[0], "date": row[1], "timeSlot": row[2]} for row in rows]

def claim_shift_for_user(token, shift, dtube_username):
    shift_id = shift.get("WKSHIFTID")
    from_time = shift.get("SHIFTFROM")
    to_time   = shift.get("SHIFTTO")

    resp = requests.post(
        "https://dtube.tesco-europe.com/DTUBE_RESTAPI/jaxrs/SHIFT/UpdateShiftWorker",
        json={
            "username": token,
            "shiftid": shift_id,
            "timefrom": from_time,
            "timeto": to_time,
            "action": "1"
        }
    )
    if SHIFT_DEBUG:
        print(f"🤝 [DEBUG] claim_shift_for_user -> code={resp.status_code}, body={resp.text}")

    if resp.status_code == 200:
        print(f"🎉 [INFO] user '{dtube_username}' shiftId={shift_id}: Claimed successfully!")
        return True
    else:
        print(f"❌ [ERROR] user '{dtube_username}' shiftId={shift_id}: Claim failed. {resp.text}")
        return False

def organize_shifts_for_user(token: str, shifts_list: list, user_bookings: list, dtube_username: str):
    claim_shifts = []
    for shift in shifts_list:
        if shift.get("STATUSSHIFT") == "5" or shift.get("STATUSSHIFT") == "3" or shift.get("STATUSSHIFT") == "1" or shift.get("STATUSSHIFT") == "7":
            if SHIFT_DEBUG:
                print(f"🟡 [DEBUG] SHIFT WKSHIFTID={shift.get('WKSHIFTID')} has STATUSSHIFT=5, skipping.")
            continue

        date_str = shift.get("SHIFTDATE")
        start    = format_time_without_seconds(shift.get("SHIFTFROM", "00:00:00"))
        end      = format_time_without_seconds(shift.get("SHIFTTO", "00:00:00"))
        shift_slot = f"{start}-{end}"

        for booking in user_bookings:
            local_date = normalize_date(booking["date"])
            local_slot = booking["timeSlot"]
            if local_date == date_str and local_slot == shift_slot:
                claim_shifts.append((shift, booking["id"]))

    if SHIFT_DEBUG:
        print(f"🔎 [DEBUG] user '{dtube_username}' => found {len(claim_shifts)} shift(s) to claim")

    for s, booking_id in claim_shifts:
        if claim_shift_for_user(token, s, dtube_username):
            mark_booking_as_sent(booking_id)

def run_shifts_for_all_users_in_db():
    """
    Multi-user SHIFT zber:
      1) Načíta všetkých používateľov z DB
      2) Pre každého používateľa vykoná DTube autentifikáciu
      3) Získa SHIFT údaje
      4) Porovná s lokálnymi rezerváciami
      5) Pokúsi sa rezervovať zodpovedajúce SHIFTy
    """
    users = get_all_db_users()
    if SHIFT_DEBUG:
        print(f"🌀 [DEBUG] run_shifts_for_all_users_in_db => {len(users)} user(s) found in DB.")

    for user in users:
        dtube_user = user["username"]
        dtube_pass = user["password"]
        dtube_token = auth_me_for_user(dtube_user, dtube_pass)

        if not dtube_token:
            print(f"❌ [ERROR] Could not authenticate user '{dtube_user}' in DTube. Skipping them.")
            continue

        shifts_list = get_all_shifts_for_user(dtube_token)
        if SHIFT_DEBUG:
            print(f"📝 [DEBUG] user '{dtube_user}' => fetched {len(shifts_list)} SHIFT(s) from DTube")

        user_bookings = get_bookings_for_user(user["id"])
        if SHIFT_DEBUG:
            print(f"📆 [DEBUG] user '{dtube_user}' => has {len(user_bookings)} local booking(s)")

        organize_shifts_for_user(dtube_token, shifts_list, user_bookings, dtube_user)

###############################################################################
#                              FLASK ROUTES                                   #
###############################################################################
@app.route("/")
def index():
    return render_template("index.html")

#########################
#       LOGIN / LOGOUT
#########################
@app.route("/login", methods=["POST"])
def login():
    """
    JSON: { "user_id": <int>, "specialpassword": <str> }
    Nastaví AuthToken cookie ak sú údaje platné.
    """
    data = request.get_json()
    user_id = data.get("user_id")
    spass   = data.get("specialpassword")

    user_data = get_db_user_by_id(user_id)
    if not user_data:
        return jsonify({"error": "Invalid user_id"}), 401

    if user_data["specialpassword"] != spass:
        return jsonify({"error": "Invalid special password"}), 401

    token = encode_auth_cookie(user_id, spass)
    resp = jsonify({"message": "🔐 Logged in successfully!"})
    resp.set_cookie("AuthToken", token, httponly=True)
    return resp

@app.route("/logout", methods=["POST"])
def logout():
    resp = jsonify({"message": "👋 Logged out!"})
    resp.set_cookie("AuthToken", "", expires=0)
    return resp

#########################
#     BOOKINGS API      #
#########################
from flask import g

@app.route("/api/bookings", methods=["GET"], endpoint="get_booked_shifts")
@require_auth
def get_booked_shifts():
    user_id = g.user_id
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute("SELECT id, user_id, date, timeSlot, sended FROM appointments WHERE user_id=?", (user_id,))
        rows = c.fetchall()

    result = []
    for r in rows:
        result.append({
            "id": r[0],
            "user_id": r[1],
            "date": r[2],
            "timeSlot": r[3],
            "sended": r[4]
        })
    return jsonify(result)


@app.route("/api/bookings", methods=["POST"], endpoint="create_booking")
@require_auth
def create_booking():
    data = request.get_json()
    valid_time_slots = ["6:00-9:00", "10:00-13:00", "14:00-21:30"]
    if data.get("timeSlot") not in valid_time_slots:
        return jsonify({"message": "❌ Invalid time slot!"}), 400

    user_id = g.user_id
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute(
            "INSERT INTO appointments (user_id, date, timeSlot) VALUES (?, ?, ?)",
            (user_id, data.get("date"), data.get("timeSlot"))
        )
        conn.commit()

    return jsonify({"message": "✅ Booking added successfully"}), 201


@app.route("/api/bookings/<int:booking_id>", methods=["DELETE"])
@require_auth
def delete_booking(booking_id):
    """
    Vymaže rezerváciu, ak patrí aktuálne autentifikovanému používateľovi.
    """
    user_id = g.user_id
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute("SELECT user_id FROM appointments WHERE id=?", (booking_id,))
        row = c.fetchone()
        if not row:
            return jsonify({"error": "No such booking"}), 404
        if row[0] != user_id:
            return jsonify({"error": "You do not own this booking"}), 403

        c.execute("DELETE FROM appointments WHERE id=?", (booking_id,))
        conn.commit()

    return jsonify({"message": "✅ Booking deleted successfully"})

#########################
#   SHIFT COLLECTING
#########################
@app.route("/api/collect_shifts", methods=["POST"])
@require_auth
def collect_shifts():
    """
    Demonstrácia multi-user SHIFT zberu.
    """
    print("🌐 [INFO] /api/collect_shifts called. Starting run_shifts_for_all_users_in_db()...")
    run_shifts_for_all_users_in_db()
    return jsonify({"message": "🚀 SHIFT collection started for all users!"}), 200

###############################################################################
#                    EMAIL CHECKING FUNKCIE (pre import v listener)           #
###############################################################################
def connect_to_gmail():
    try:
        mail = imaplib.IMAP4_SSL(IMAP_SERVER)
        mail.login(IMAP_EMAIL, IMAP_PASSWORD)
        return mail
    except Exception as e:
        print(f"❌ [ERROR] Gmail connection: {e}")
        return None

def process_email(subject):
    if "nová zmena v ponuke" in subject.lower():
        run_shifts_for_all_users_in_db()

def check_inbox():
    mail = connect_to_gmail()
    if not mail:
        return
    try:
        mail.select("inbox")
        status, messages = mail.search(None, 'UNSEEN')
        if status == "OK":
            for msg_id in messages[0].split():
                _, msg_data = mail.fetch(msg_id, "(RFC822)")
                for response in msg_data:
                    if isinstance(response, tuple):
                        msg_obj = email.message_from_bytes(response[1])
                        subj = decode_header(msg_obj.get("Subject"))[0][0]
                        if isinstance(subj, bytes):
                            subj = subj.decode()
                        process_email(subj)
    except Exception as e:
        print(f"❌ [ERROR] Checking inbox: {e}")
    finally:
        mail.logout()

def start_email_checking():
    with app.app_context():
        while True:
            try:
                check_inbox()
                time.sleep(5)
            except Exception as e:
                print(f"❌ [ERROR] Fatal email checking error: {e}")

if __name__ == "__main__":
    # Pre lokálne spustenie aplikácie
    app.run(debug=SHIFT_DEBUG)
