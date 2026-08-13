# AURUM Dental Studio - backend
# Flask + SQLite project for the web security assignment.
# All the password checks (strength, policy, hashes, breach check, generator)
# run here in Python, the frontend just shows the result.
#
# how to run:
#   pip install -r requirements.txt
#   python app.py
# then open http://127.0.0.1:5000 in the browser

import os
import re
import hashlib
import secrets
import sqlite3
from datetime import datetime, date
import time 

import requests
from flask import Flask, render_template, request, jsonify, session, redirect, url_for, g
from werkzeug.security import generate_password_hash, check_password_hash
from zxcvbn import zxcvbn

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "aurum.db")

app = Flask(__name__)
app.secret_key = "dev-secret-change-me"   # just for the project, not real deployment


# NEW: Dictionary to store failed login attempts in memory
FAILED_LOGINS = {}
MAX_FAILURES = 5
LOCKOUT_TIME = 900  # 15 minutes in seconds
# ------------------------------- database stuff -------------------------------

def get_db():
    # keep one connection per request
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(exception=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS bookings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            patient_id INTEGER,
            name TEXT NOT NULL,
            phone TEXT NOT NULL,
            service TEXT NOT NULL,
            appt_date TEXT NOT NULL,
            appt_time TEXT NOT NULL,
            notes TEXT,
            status TEXT NOT NULL DEFAULT 'pending',
            created_at TEXT NOT NULL,
            FOREIGN KEY (patient_id) REFERENCES users(id)
        )
    """)
    conn.commit()
    conn.close()


def current_user():
    uid = session.get("user_id")
    if not uid:
        return None
    row = get_db().execute(
        "SELECT id, name, email, created_at FROM users WHERE id = ?", (uid,)
    ).fetchone()
    if row is None:
        return None
    return dict(row)


@app.context_processor
def inject_user():
    # so templates can just use {{ current_user }}
    return dict(current_user=current_user())


# ------------------------------- password checking stuff -------------------------------

# list of rules used for the policy checklist on the signup page
def rule_len8(pw):
    return len(pw) >= 8

def rule_len12(pw):
    return len(pw) >= 12

def rule_upper(pw):
    return re.search(r"[A-Z]", pw) is not None

def rule_lower(pw):
    return re.search(r"[a-z]", pw) is not None

def rule_num(pw):
    return re.search(r"[0-9]", pw) is not None

def rule_sym(pw):
    return re.search(r"[^A-Za-z0-9]", pw) is not None

def rule_nospace(pw):
    if len(pw) == 0:
        return False
    return re.search(r"\s", pw) is None

def rule_norepeat(pw):
    return re.search(r"(.)\1\1", pw) is None


POLICIES = [
    ("len8", "At least 8 characters", rule_len8),
    ("len12", "At least 12 characters (recommended)", rule_len12),
    ("upper", "At least one uppercase letter", rule_upper),
    ("lower", "At least one lowercase letter", rule_lower),
    ("num", "At least one number", rule_num),
    ("sym", "At least one special symbol", rule_sym),
    ("nospace", "No spaces", rule_nospace),
    ("norepeat", "No 3+ repeated characters in a row", rule_norepeat),
]

# these 4 are required to actually be able to sign up, the rest are just recommendations
CRITICAL_POLICY_IDS = ["len8", "upper", "lower", "num"]

# zxcvbn gives back a warning message in english, we translate/rewrite it to
# something a bit friendlier for the UI
WARNING_MAP = {
    "this is a top-10 common password": "This is one of the top 10 most-used passwords in the world - extremely easy to guess.",
    "this is a top-100 common password": "This is among the top 100 most-used passwords - known to every guessing tool.",
    "this is a very common password": "This is a very common password found in ready-made guessing lists.",
    "this is similar to a commonly used password": "This is very close to a common password and can be guessed the same way.",
    "a word by itself is easy to guess": "A single word by itself is easy to guess, even if it's not common.",
    "names and surnames by themselves are easy to guess": "Names by themselves (whether a country or a person) are easy to guess.",
    "common names and surnames are easy to guess": "Common names and surnames are very easy to guess.",
    "straight rows of keys are easy to guess": "A straight run of keys on the keyboard (like qwerty) is a known, easily guessed pattern.",
    "short keyboard patterns are easy to guess": "A short keyboard pattern is also easy to guess.",
    'repeats like "aaa" are easy to guess': "Repeating a single character multiple times (aaa) greatly reduces security.",
    'repeats like "abcabcabc" are only slightly harder to guess than "abcabc"': "Repeating a short pattern doesn't add real security.",
    "sequences like abc or 6543 are easy to guess": "Sequences like abc or 1234 are well known and predictable.",
    "recent years are easy to guess": "Recent years (like 2023, 2024) are easily guessed.",
    "dates are often easy to guess": "Dates (like a birthdate) are easy to guess if someone knows something about you.",
}

SCORE_WORDS = ["Very Weak", "Weak", "Medium", "Strong", "Very Strong"]


def format_crack_time(seconds):
    seconds = float(seconds)
    if seconds < 1:
        return "less than a second"

    # (seconds in unit, label)
    units = [
        (31536000000, "centuries"),
        (31536000, "years"),
        (2592000, "months"),
        (86400, "days"),
        (3600, "hours"),
        (60, "minutes"),
        (1, "seconds"),
    ]
    for unit_seconds, label in units:
        if seconds >= unit_seconds:
            value = round(seconds / unit_seconds)
            return "{:,} {}".format(value, label)

    return "moments"


def explain_weakness(pw, result):
    reasons = []

    feedback = result.get("feedback")
    if feedback and feedback.get("warning"):
        warning_text = feedback["warning"]
        key = warning_text.strip().rstrip(".").lower()
        if key in WARNING_MAP:
            reasons.append(WARNING_MAP[key])
        else:
            reasons.append(warning_text)

    if len(pw) < 8:
        reasons.append("Short length - under 8 characters makes brute-force cracking much easier.")
    if re.search(r"[A-Z]", pw) is None:
        reasons.append("No uppercase letters (A-Z) - this reduces the number of possible combinations.")
    if re.search(r"[0-9]", pw) is None:
        reasons.append("No numbers - this makes guessing tools' job easier.")
    if re.search(r"[^A-Za-z0-9]", pw) is None:
        reasons.append("No special symbols (!@#$) - these add complexity.")

    for match in result.get("sequence", []):
        if match.get("pattern") == "dictionary" and match.get("dictionary_name"):
            token = match.get("token")
            dict_name = match.get("dictionary_name")
            reasons.append('The part "' + token + '" is found in a dictionary (' + dict_name + ') - this is guessed quickly.')

    return reasons


def analyze_password(pw, name="", email=""):
    if not pw:
        empty_policy = {}
        for pid, label, test in POLICIES:
            empty_policy[pid] = False
        return {
            "score": None,
            "score_word": "-",
            "crack_time": "-",
            "reasons": [],
            "policy": empty_policy,
            "hashes": {},
        }
    
        # Put them in a list, making sure we don't pass empty strings
    user_inputs = []
    if name:
        # Split the full name by spaces so each name is checked individually!
        user_inputs.extend(name.lower().split())
    if email:
        user_inputs.append(email.lower())
        # Split the email by @ and . to check the username part
        import re
        user_inputs.extend(re.split(r'[@.]', email.lower()))


        
   # Pass the user_inputs to zxcvbn
    result = zxcvbn(pw, user_inputs=user_inputs)


# NEW: Strict override for targeted guesses
    for match in result.get("sequence", []):
        if match.get("dictionary_name") == "user_inputs":
            result["score"] = 0
            result["crack_times_seconds"]["offline_slow_hashing_1e4_per_second"] = 0
    score = result["score"]
    crack_seconds = result["crack_times_seconds"]["offline_slow_hashing_1e4_per_second"]



    policy_result = {}
    for pid, label, test in POLICIES:
        policy_result[pid] = test(pw)

    hashes = {
        "md5": hashlib.md5(pw.encode()).hexdigest(),
        "sha1": hashlib.sha1(pw.encode()).hexdigest(),
        "sha256": hashlib.sha256(pw.encode()).hexdigest(),
    }

    return {
        "score": score,
        "score_word": SCORE_WORDS[score],
        "crack_time": format_crack_time(crack_seconds),
        "reasons": explain_weakness(pw, result),
        "policy": policy_result,
        "hashes": hashes,
    }


def passes_critical_policy(pw):
    for pid, label, test in POLICIES:
        if pid in CRITICAL_POLICY_IDS:
            if not test(pw):
                return False
    return True


def check_breach(pw):
    # HIBP k-anonymity check - we only send the first 5 chars of the sha1 hash
    sha1 = hashlib.sha1(pw.encode()).hexdigest().upper()
    prefix = sha1[:5]
    suffix = sha1[5:]

    try:
        resp = requests.get("https://api.pwnedpasswords.com/range/" + prefix, timeout=6)
        resp.raise_for_status()
    except requests.RequestException:
        return {"ok": False, "error": "Could not reach the breach-check service right now."}

    for line in resp.text.splitlines():
        parts = line.split(":")
        if len(parts) != 2:
            continue
        line_suffix, count_str = parts
        if line_suffix.strip() == suffix:
            return {"ok": True, "breached": True, "count": int(count_str)}

    return {"ok": True, "breached": False, "count": 0}


def generate_password(length, use_upper, use_lower, use_num, use_sym):
    upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    lower = "abcdefghijklmnopqrstuvwxyz"
    nums = "0123456789"
    syms = "!@#$%^&*()-_=+[]{}<>?"

    pool = ""
    required_sets = []

    if use_upper:
        pool += upper
        required_sets.append(upper)
    if use_lower:
        pool += lower
        required_sets.append(lower)
    if use_num:
        pool += nums
        required_sets.append(nums)
    if use_sym:
        pool += syms
        required_sets.append(syms)

    if pool == "":
        return None

    length = int(length)
    if length < len(required_sets):
        length = len(required_sets)
    if length > 64:
        length = 64

    chars = []
    for s in required_sets:
        chars.append(secrets.choice(s))

    while len(chars) < length:
        chars.append(secrets.choice(pool))

    secrets.SystemRandom().shuffle(chars)
    return "".join(chars)


# ------------------------------- normal pages -------------------------------

@app.route("/")
def home():
    return render_template("index.html")


@app.route("/services")
def services():
    return render_template("services.html")


@app.route("/booking")
def booking_page():
    return render_template("booking.html")


@app.route("/signup")
def signup_page():
    if current_user():
        return redirect(url_for("dashboard"))
    return render_template("signup.html")


@app.route("/login")
def login_page():
    if current_user():
        return redirect(url_for("dashboard"))
    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("home"))


@app.route("/dashboard")
def dashboard():
    user = current_user()
    if not user:
        return redirect(url_for("login_page"))

    rows = get_db().execute(
        "SELECT * FROM bookings WHERE patient_id = ? ORDER BY appt_date, appt_time",
        (user["id"],),
    ).fetchall()

    bookings = []
    for r in rows:
        bookings.append(dict(r))

    return render_template("dashboard.html", bookings=bookings)


# ------------------------------- password toolkit API -------------------------------

@app.route("/api/password/analyze", methods=["POST"])
def api_password_analyze():
    body = request.get_json(silent=True)
    if body is None:
        body = {}
    pw = body.get("password", "")

    # NEW: Extract name and email
    name = body.get("name", "")
    email = body.get("email", "")
    
    # Update this call to pass the new variables
    return jsonify(analyze_password(pw, name, email))


@app.route("/api/password/breach", methods=["POST"])
def api_password_breach():
    body = request.get_json(silent=True)
    if body is None:
        body = {}
    pw = body.get("password", "")
    if not pw:
        return jsonify({"ok": False, "error": "Type a password first."}), 400
    return jsonify(check_breach(pw))


@app.route("/api/password/generate", methods=["POST"])
def api_password_generate():
    body = request.get_json(silent=True)
    if body is None:
        body = {}

    pw = generate_password(
        body.get("length", 16),
        body.get("upper", True),
        body.get("lower", True),
        body.get("num", True),
        body.get("sym", True),
    )
    if pw is None:
        return jsonify({"ok": False, "error": "Select at least one character type."}), 400
    return jsonify({"ok": True, "password": pw})


# ------------------------------- auth API -------------------------------

@app.route("/api/signup", methods=["POST"])
def api_signup():
    body = request.get_json(silent=True)
    if body is None:
        body = {}

    name = (body.get("name") or "").strip()
    email = (body.get("email") or "").strip().lower()
    pw = body.get("password") or ""

    if not name or not email or not pw:
        return jsonify({"ok": False, "error": "Name, email and password are all required."}), 400

    if re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email) is None:
        return jsonify({"ok": False, "error": "Enter a valid email address."}), 400

      # NEW: Analyze the password using our updated function (which catches names/emails!)
    analysis = analyze_password(pw, name, email)
    if analysis["score"] < 3:
        return jsonify({"ok": False, "error": "Password is too weak. Please choose a Strong or Very Strong password."}), 400




    db = get_db()
    existing = db.execute("SELECT 1 FROM users WHERE email = ?", (email,)).fetchone()
    if existing:
        return jsonify({"ok": False, "error": "An account with this email already exists."}), 409

    # this is the real hash that gets saved (PBKDF2-SHA256, salted).
    # the MD5/SHA1/SHA256 shown in the toolkit are only there to demonstrate
    # why those aren't good enough for storing passwords.
    pw_hash = generate_password_hash(pw)

    db.execute(
        "INSERT INTO users (name, email, password_hash, created_at) VALUES (?, ?, ?, ?)",
        (name, email, pw_hash, datetime.utcnow().isoformat()),
    )
    db.commit()

    new_user = db.execute("SELECT id FROM users WHERE email = ?", (email,)).fetchone()
    session["user_id"] = new_user["id"]

    return jsonify({"ok": True, "redirect": url_for("dashboard")})


@app.route("/api/login", methods=["POST"])
def api_login():
    body = request.get_json(silent=True)
    if body is None:
        body = {}

    email = (body.get("email") or "").strip().lower()
    pw = body.get("password") or ""

    # NEW: Check if this email is currently locked out BEFORE checking the database
    current_time = time.time()
    record = FAILED_LOGINS.get(email, {"attempts": 0, "locked_until": 0})
    
    if current_time < record["locked_until"]:
        remaining_minutes = max(1, int((record["locked_until"] - current_time) / 60))
        return jsonify({"ok": False, "error": f"Account locked due to too many failed attempts. Try again in {remaining_minutes} minutes."}), 429

    db = get_db()
    row = db.execute("SELECT id, password_hash FROM users WHERE email = ?", (email,)).fetchone()

    # If the login fails (wrong email or wrong password)
    if row is None or not check_password_hash(row["password_hash"], pw):
        # NEW: Record the failure
        record["attempts"] += 1
        if record["attempts"] >= MAX_FAILURES:
            record["locked_until"] = current_time + LOCKOUT_TIME
            record["attempts"] = 0  # reset count for when the timer expires
        
        FAILED_LOGINS[email] = record
        return jsonify({"ok": False, "error": "Incorrect email or password."}), 401

    # NEW: If the login succeeds, clear any bad history
    if email in FAILED_LOGINS:
        del FAILED_LOGINS[email]

    session["user_id"] = row["id"]
    return jsonify({"ok": True, "redirect": url_for("dashboard")})


# ------------------------------- booking API -------------------------------

@app.route("/api/booking", methods=["POST"])
def api_booking():
    body = request.get_json(silent=True)
    if body is None:
        body = {}

    name = (body.get("name") or "").strip()
    phone = (body.get("phone") or "").strip()
    service = (body.get("service") or "General consultation").strip()
    appt_date = (body.get("date") or "").strip()
    appt_time = (body.get("time") or "").strip()
    notes = (body.get("notes") or "").strip()

    if not name or not phone or not appt_date:
        return jsonify({"ok": False, "error": "Name, phone and date are required."}), 400

    try:
        picked_date = date.fromisoformat(appt_date)
    except ValueError:
        return jsonify({"ok": False, "error": "Invalid date."}), 400

    if picked_date < date.today():
        return jsonify({"ok": False, "error": "Pick a date from today onward."}), 400

    user = current_user()
    patient_id = user["id"] if user else None

    db = get_db()
    db.execute(
        "INSERT INTO bookings (patient_id, name, phone, service, appt_date, appt_time, notes, status, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, 'pending', ?)",
        (patient_id, name, phone, service, appt_date, appt_time, notes, datetime.utcnow().isoformat()),
    )
    db.commit()

    return jsonify({"ok": True})


if __name__ == "__main__":
    init_db()
    app.run(debug=True)
