import logging
import hashlib
import re
import io
from fastapi import FastAPI, HTTPException, Depends, Query, Body, Request, File, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel, EmailStr
import json
from openai import OpenAI
from datetime import datetime, timedelta
from jose import JWTError, jwt
from typing import Optional, Literal
from dotenv import load_dotenv
import os
import sqlite3
from passlib.context import CryptContext
import requests
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes  # noqa
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC  # noqa
import secrets
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from twilio.rest import Client
from PIL import Image, ImageOps, ImageFilter
import pytesseract
from difflib import get_close_matches

# Optional: use OpenCV/Numpy if available (fallbacks if not)
try:
    import numpy as np
    import cv2
except Exception:
    np = None
    cv2 = None

load_dotenv()
EMAIL_HOST = os.getenv("EMAIL_HOST", "mail.privateemail.com")
EMAIL_PORT = int(os.getenv("EMAIL_PORT", 465))
EMAIL_USE_SSL = os.getenv("EMAIL_USE_SSL", "true").lower() == "true"
EMAIL_USE_TLS = os.getenv("EMAIL_USE_TLS", "false").lower() == "true"
EMAIL_HOST_USER = os.getenv("EMAIL_HOST_USER", "")
EMAIL_HOST_PASSWORD = os.getenv("EMAIL_HOST_PASSWORD", "")
EMAIL_FROM = os.getenv("EMAIL_FROM", EMAIL_HOST_USER)

# ---- Twilio / SMS Config ----
TWILIO_ACCOUNT_SID = os.getenv("TWILIO_ACCOUNT_SID", "")
TWILIO_AUTH_TOKEN = os.getenv("TWILIO_AUTH_TOKEN", "")
TWILIO_FROM_NUMBER = os.getenv("TWILIO_FROM_NUMBER", "")  # e.g. "+12025551234"
# If users enter local numbers without +countrycode, we’ll prefix this:
SMS_DEFAULT_COUNTRY_CODE = os.getenv("SMS_DEFAULT_COUNTRY_CODE", "+1")  # set to "+91" etc.

# ---------------- JWT Configuration ----------------
SECRET_KEY = os.getenv("SECRET_KEY", "your-secret-key-change-this-in-production")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")  # legacy compatibility

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=401,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email = payload.get("sub")
        if not email:
            raise credentials_exception
        return email
    except JWTError:
        raise credentials_exception

# ---------------- App / CORS ----------------
logging.basicConfig(filename='app.log', level=logging.DEBUG,
                    format='%(asctime)s %(levelname)s:%(message)s')

app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # tighten in prod
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

DATABASE_URL = "users.db"
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")  # legacy only

def get_db_connection():
    conn = sqlite3.connect(DATABASE_URL, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def init_user_db():
    conn = get_db_connection()
    try:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL,
                mobile INT NOT NULL,
                password_hash TEXT
            )
        """)
        # Add password_hash column if not exists (for existing tables)
        try:
            conn.execute("ALTER TABLE users ADD COLUMN password_hash TEXT")
        except sqlite3.OperationalError:
            pass  # Column already exists

        # Check if otp_codes table exists and has old CHECK constraint
        row = conn.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name='otp_codes'").fetchone()
        if row and "'password_reset'" not in row['sql']:
            # Migrate: rename old table, create new, copy data, drop old
            conn.execute("ALTER TABLE otp_codes RENAME TO otp_codes_old")
            conn.execute("""
                CREATE TABLE otp_codes (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    email TEXT,
                    mobile TEXT,
                    otp_code TEXT NOT NULL,
                    type TEXT NOT NULL CHECK(type IN ('email', 'sms', 'password_reset')),
                    expires_at DATETIME NOT NULL,
                    used BOOLEAN DEFAULT 0,
                    attempts INTEGER DEFAULT 0,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (email) REFERENCES users(email)
                )
            """)
            conn.execute("""
                INSERT INTO otp_codes (id, email, mobile, otp_code, type, expires_at, used, attempts, created_at)
                SELECT id, email, mobile, otp_code, type, expires_at, used, attempts, created_at FROM otp_codes_old
            """)
            conn.execute("DROP TABLE otp_codes_old")

        conn.execute("""
            CREATE TABLE IF NOT EXISTS otp_codes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT,
                mobile TEXT,
                otp_code TEXT NOT NULL,
                type TEXT NOT NULL CHECK(type IN ('email', 'sms', 'password_reset')),
                expires_at DATETIME NOT NULL,
                used BOOLEAN DEFAULT 0,
                attempts INTEGER DEFAULT 0,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (email) REFERENCES users(email)
            )
        """)

        conn.execute(""" 
        CREATE TABLE IF NOT EXISTS family_members (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,

            member1_firstName TEXT,
            member1_lastName TEXT,
            member1_dob TEXT,
            member1_race TEXT,
            member1_gender TEXT,
            member1_height TEXT,
            member1_weight TEXT,
            member1_a1c TEXT,
            member1_bloodPressure TEXT,
            member1_medicine TEXT,
            member1_zip_code TEXT,
            member1_bmi TEXT,
            member1_tokens INTEGER DEFAULT 0,

            member2_firstName TEXT,
            member2_lastName TEXT,
            member2_dob TEXT,
            member2_race TEXT,
            member2_gender TEXT,
            member2_height TEXT,
            member2_weight TEXT,
            member2_a1c TEXT,
            member2_bloodPressure TEXT,
            member2_medicine TEXT,
            member2_zip_code TEXT,
            member2_bmi TEXT,
            member2_tokens INTEGER DEFAULT 0,

            member3_firstName TEXT,
            member3_lastName TEXT,
            member3_dob TEXT,
            member3_race TEXT,
            member3_gender TEXT,
            member3_height TEXT,
            member3_weight TEXT,
            member3_a1c TEXT,
            member3_bloodPressure TEXT,
            member3_medicine TEXT,
            member3_zip_code TEXT,
            member3_bmi TEXT,
            member3_tokens INTEGER DEFAULT 0,

            member4_firstName TEXT,
            member4_lastName TEXT,
            member4_dob TEXT,
            member4_race TEXT,
            member4_gender TEXT,
            member4_height TEXT,
            member4_weight TEXT,
            member4_a1c TEXT,
            member4_bloodPressure TEXT,
            member4_medicine TEXT,
            member4_zip_code TEXT,
            member4_bmi TEXT,
            member4_tokens INTEGER DEFAULT 0
        )
        """)
        # Helpful indexes
        conn.execute("CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_users_mobile ON users(mobile)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_otp_codes_email ON otp_codes(email)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_otp_codes_type_email ON otp_codes(type,email)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_otp_codes_exp ON otp_codes(expires_at)")
        conn.commit()
    finally:
        conn.close()

init_user_db()

# ---------------- Email helpers (hardened) ----------------
def _smtp_client():
    """
    Returns a connected, authenticated SMTP or SMTP_SSL client, or raises.
    Prefers SSL on 465; supports STARTTLS on 587.
    """
    if not EMAIL_HOST:
        raise RuntimeError("EMAIL_HOST is not set")
    if not (EMAIL_USE_SSL or EMAIL_USE_TLS):
        # Allow explicit non-TLS only in dev, but warn loudly
        logging.warning("EMAIL_USE_SSL/TLS are both false. This is not recommended for production.")
    if not EMAIL_HOST_USER or not EMAIL_HOST_PASSWORD:
        # Dev print mode
        logging.warning("SMTP credentials missing; using DEV PRINT mode.")
        return None

    if EMAIL_USE_SSL:
        server = smtplib.SMTP_SSL(EMAIL_HOST, EMAIL_PORT, timeout=30)
        server.login(EMAIL_HOST_USER, EMAIL_HOST_PASSWORD)
        return server

    server = smtplib.SMTP(EMAIL_HOST, EMAIL_PORT, timeout=30)
    if EMAIL_USE_TLS:
        server.ehlo()
        server.starttls()
        server.ehlo()
    server.login(EMAIL_HOST_USER, EMAIL_HOST_PASSWORD)
    return server

def send_email(to_email: str, subject: str, body: str, html: Optional[str] = None) -> bool:
    """
    Send an email via SMTP. Returns True on success.
    In DEV PRINT mode (no creds), logs the message and returns True.
    """
    try:
        server = _smtp_client()
        if server is None:
            # DEV PRINT mode
            logging.info(f"[DEV EMAIL] To: {to_email}\nSubject: {subject}\n\n{body}")
            if html:
                logging.info(f"[DEV EMAIL HTML]\n{html}")
            return True

        msg = MIMEMultipart("alternative")
        msg["From"] = EMAIL_FROM or EMAIL_HOST_USER
        msg["To"] = to_email
        msg["Subject"] = subject
        msg.attach(MIMEText(body, "plain"))
        if html:
            msg.attach(MIMEText(html, "html"))

        server.send_message(msg)
        server.quit()
        logging.info(f"Email sent successfully to {to_email}")
        return True

    except Exception as e:
        logging.error(f"send_email failed: {e}", exc_info=True)
        return False

# ---------------- Simple lookups ----------------
@app.get("/medlifeV21/get-username")
async def get_username(email: str = Query(...)):
    conn = get_db_connection()
    try:
        row = conn.execute("SELECT username FROM users WHERE email = ?", (email,)).fetchone()
        return {"username": row["username"]} if row else {"username": None}
    finally:
        conn.close()

@app.get("/medlifeV21/get-user-gender")
async def get_user_gender(email: str = Query(...)):
    conn = get_db_connection()
    try:
        row = conn.execute("SELECT member1_gender FROM family_members WHERE email = ?", (email,)).fetchone()
        return {"gender": row["member1_gender"]} if row and row["member1_gender"] else {"gender": None}
    finally:
        conn.close()

# ---------------- Auth models / endpoints ----------------
class UserSignup(BaseModel):
    username: str
    email: str
    mobile: int
    password: str

class CheckUserExistsRequest(BaseModel):
    login: str  # email or phone

class CheckUserExistsResponse(BaseModel):
    exists: bool
    login_type: str  # 'email' or 'phone'

# Legacy token endpoint (left intact for compatibility; not used in OTP login)
@app.post("/medlifeV21/token")
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    conn = get_db_connection()
    try:
        row = conn.execute(
            "SELECT email, password_hash FROM users WHERE email = ? OR username = ?",
            (form_data.username, form_data.username)
        ).fetchone()
        if not row or not pwd_context.verify(form_data.password, row["password_hash"]):
            raise HTTPException(status_code=401, detail="Incorrect email/username or password")
        access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = create_access_token(data={"sub": row["email"]}, expires_delta=access_token_expires)
        return {"access_token": access_token, "token_type": "bearer", "email": row["email"]}
    finally:
        conn.close()

@app.post("/medlifeV21/signup")
def signup(user: UserSignup):
    # email validation
    if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[A-Za-z]{2,}$', user.email):
        raise HTTPException(status_code=400, detail="Invalid email format")

    # mobile validation (basic)
    mobile_str = str(user.mobile)
    if not re.match(r'^\d{7,15}$', mobile_str):
        raise HTTPException(status_code=400, detail="Invalid mobile number")

    # password validation
    if not re.match(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^\w\s])[\w\S]{8,}$', user.password):
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters long and contain at least one lowercase letter, one uppercase letter, one digit, and one special character.")

    conn = get_db_connection()
    try:
        exists = conn.execute("SELECT 1 FROM users WHERE email = ?", (user.email,)).fetchone()
        if exists:
            raise HTTPException(status_code=409, detail="Email already registered")

        # Hash the password
        hashed_password = pwd_context.hash(user.password)

        # Insert user with password_hash
        with conn:
            conn.execute(
                "INSERT INTO users (username, email, mobile, password_hash) VALUES (?, ?, ?, ?)",
                (user.username, user.email, user.mobile, hashed_password)
            )
            fam = conn.execute("SELECT 1 FROM family_members WHERE email = ?", (user.email,)).fetchone()
            if not fam:
                conn.execute("INSERT INTO family_members (email) VALUES (?)", (user.email,))
        return {"message": "User registered successfully", "email": user.email}
    except sqlite3.Error as e:
        logging.error(f"Database error during signup: {e}")
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        conn.close()

# ---------------- Data model for member payload ----------------
class Data(BaseModel):
    firstName: str
    lastName: str
    dob: str
    race: str
    gender: str
    height: str
    weight: str
    a1c: str
    bloodPressure: str
    medicine: str
    email: str
    zip_code: str
    bmi: str

# ---------------- OTP Models ----------------
class SendOTPRequest(BaseModel):
    type: str  # 'email' or 'sms'
    identifier: str  # email or mobile number

class VerifyOTPRequest(BaseModel):
    type: str  # 'email' or 'sms'
    identifier: str  # email or mobile number
    otp_code: str

# OTP-based login flow models
class SignInStart(BaseModel):
    type: Literal["email", "sms"]
    identifier: str
    password: str

class VerifyLoginOTP(BaseModel):
    type: Literal["email", "sms"]
    identifier: str
    otp_code: str

class ForgotPasswordRequest(BaseModel):
    email: EmailStr

class ResetPasswordRequest(BaseModel):
    email: EmailStr
    otp_code: str
    new_password: str

@app.post("/medlifeV21/forgot-password")
def forgot_password(request: ForgotPasswordRequest):
    email = request.email
    conn = get_db_connection()
    try:
        user = conn.execute("SELECT email FROM users WHERE email = ?", (email,)).fetchone()
        if not user:
            raise HTTPException(status_code=404, detail="Email not registered")

        # Generate OTP for password reset
        otp_code = generate_otp()
        expires_at = datetime.utcnow() + timedelta(minutes=5)

        # Insert OTP with type 'password_reset'
        conn.execute(
            """
            INSERT INTO otp_codes (email, otp_code, type, expires_at)
            VALUES (?, ?, 'password_reset', ?)
            """,
            (email, otp_code, expires_at)
        )
        conn.commit()

        # Send email with OTP and instructions
        body = f"""Dear User,

You requested to reset your password. Your password reset code is: {otp_code}

This code will expire in 5 minutes. Please use it to reset your password.

If you did not request this, please ignore this email or contact support.

Best regards,

MedLife AI Team
"""
        html = f"""
        <p>Dear User,</p>
        <p>You requested to reset your password. Your password reset code is:</p>
        <h2>{otp_code}</h2>
        <p>This code will expire in 5 minutes.</p>
        <p>If you did not request this, please ignore this email or contact support.</p>
        <p>Best regards,<br/>MedLife AI Team</p>
        """
        success = send_email(email, "MedLife Password Reset Code", body, html)
        if not success:
            raise HTTPException(status_code=500, detail="Failed to send password reset email")

        return {"message": "Password reset code sent to your email"}

    finally:
        conn.close()

@app.post("/medlifeV21/reset-password")
def reset_password(request: ResetPasswordRequest):
    email = request.email
    otp_code = request.otp_code
    new_password = request.new_password

    # Validate new password with same rules as signup
    if not re.match(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^\w\s])[\w\S]{8,}$', new_password):
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters long and contain at least one lowercase letter, one uppercase letter, one digit, and one special character.")

    conn = get_db_connection()
    try:
        # Verify OTP
        otp_row = conn.execute(
            """
            SELECT * FROM otp_codes
            WHERE email = ? AND otp_code = ? AND type = 'password_reset' AND used = 0 AND expires_at > ? AND attempts < 3
            """,
            (email, otp_code, datetime.utcnow())
        ).fetchone()

        if not otp_row:
            # Increment attempts if possible
            conn.execute(
                """
                UPDATE otp_codes
                SET attempts = attempts + 1
                WHERE email = ? AND otp_code = ? AND type = 'password_reset' AND used = 0
                """,
                (email, otp_code)
            )
            conn.commit()
            raise HTTPException(status_code=400, detail="Invalid or expired password reset code")

        # Hash new password
        hashed_password = pwd_context.hash(new_password)

        # Update user's password_hash
        conn.execute(
            "UPDATE users SET password_hash = ? WHERE email = ?",
            (hashed_password, email)
        )

        # Mark OTP as used
        conn.execute("UPDATE otp_codes SET used = 1 WHERE id = ?", (otp_row["id"],))

        conn.commit()

        return {"message": "Password has been reset successfully"}

    finally:
        conn.close()

# ---------------- OTP Service Functions ----------------
def generate_otp():
    return str(secrets.randbelow(900000) + 100000)

def send_email_otp(email: str, otp: str) -> bool:
    """
    Send OTP via email using your PrivateEmail SMTP settings.
    Falls back to dev print if credentials are missing.
    """
    body = f"""Dear User,

Your MedLife AI verification code is: {otp}

This code will expire in 5 minutes. Please use it to complete your login process.

If you didn't request this code, please ignore this email or contact our support team.

Best regards,

MedLife AI Team
"""
    html = f"""
    <p>Dear User,</p>
    <p>Your MedLife AI verification code is:</p>
    <h2>{otp}</h2>
    <p>This code will expire in 5 minutes.</p>
    <p>If you didn't request this code, please ignore this email.</p>
    <p>Best regards,<br/>MedLife AI Team</p>
    """
    return send_email(email, "Your MedLife OTP Code - Secure Login", body, html)

def to_e164(number: str) -> str:
    """Best-effort convert a user-entered number to E.164."""
    if not number:
        return number
    cleaned = re.sub(r"[^\d+]", "", number)
    if cleaned.startswith("+"):
        return cleaned
    return f"{SMS_DEFAULT_COUNTRY_CODE}{cleaned}"

def send_sms_otp(mobile: str, otp: str) -> bool:
    """
    Send OTP via SMS to the *user-entered* mobile number.
    Uses Twilio if env vars are present, else dev-print.
    """
    try:
        if not (TWILIO_ACCOUNT_SID and TWILIO_AUTH_TOKEN and TWILIO_FROM_NUMBER):
            logging.warning("Twilio not configured; printing OTP (dev mode)")
            print(f"[DEV SMS] To: {mobile} | OTP: {otp}")
            return True

        to_number = to_e164(mobile)
        client = Client(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN)
        body = f"Your MedLife AI verification code is {otp}. It expires in 5 minutes."
        msg = client.messages.create(body=body, from_=to_e164(TWILIO_FROM_NUMBER), to=to_number)
        logging.info(f"SMS OTP sent to {to_number}; Twilio SID: {msg.sid}")
        return True

    except Exception as e:
        logging.error(f"Failed to send SMS OTP to {mobile}: {e}")
        return False

def cleanup_expired_otps():
    conn = get_db_connection()
    try:
        conn.execute(
            "DELETE FROM otp_codes WHERE expires_at < ? OR attempts >= 3",
            (datetime.utcnow(),)
        )
        conn.commit()
    finally:
        conn.close()

# ---------------- Simple ping ----------------
@app.get("/medlifeV21/ai")
def read_root():
    return {"Hello": "World"}

# ---------------- Provider utilities (unchanged) ----------------
def get_provider_config(provider: str):
    configs = {
        "openai": {
            "name": "OpenAI",
            "base_url": "https://api.openai.com/v1",
            "models": ["gpt-3.5-turbo", "gpt-4", "gpt-4-turbo-preview"]
        },
        "gemini": {
            "name": "Google Gemini",
            "base_url": "https://generativelanguage.googleapis.com/v1beta",
            "models": ["gemini-2.0-flash", "gemini-2.0", "gemini-pro"]
        },
        "mistral": {
            "name": "Mistral AI",
            "base_url": "https://api.mistral.ai/v1",
            "models": ["mistral-small-latest", "mistral-large-latest", "open-mistral-7b"]
        },
        "claude": {
            "name": "Anthropic Claude",
            "base_url": "https://api.anthropic.com/v1",
            "models": ["claude-3-haiku-20240307", "claude-3-5-sonnet-latest", "claude-3-opus-20240229"]
        },
    }
    return configs.get(provider, configs["openai"])

def encrypt_api_key(api_key: str, email: str) -> str:
    key = base64.urlsafe_b64encode(hashlib.sha256(email.encode()).digest()[:32])
    return Fernet(key).encrypt(api_key.encode()).decode()

def decrypt_api_key(encrypted_key: str, email: str) -> str:
    try:
        key = base64.urlsafe_b64encode(hashlib.sha256(email.encode()).digest()[:32])
        return Fernet(key).decrypt(encrypted_key.encode()).decode()
    except Exception:
        return encrypted_key

def ask_openai(question, api_key, provider="openai", model=None):
    if not api_key:
        raise ValueError("OpenAI API key is required")
    client = OpenAI(api_key=api_key)
    model = model or "gpt-3.5-turbo"
    messages = [
        {"role": "system", "content": "You are a helpful healthcare AI assistant. Provide accurate, helpful medical information while reminding users to consult healthcare professionals for medical advice."},
        {"role": "user", "content": question}
    ]
    try:
        completion = client.chat.completions.create(
            messages=messages, model=model, max_tokens=1000, temperature=0.7
        )
        return completion.choices[0].message.content
    except Exception as e:
        raise ValueError(f"OpenAI API error: {str(e)}")

def ask_gemini(question, api_key, model="gemini-2.0-flash"):
    if not api_key:
        raise ValueError("Google Gemini API key is required")
    import socket, time  # noqa
    url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash-exp:generateContent"
    headers = {"Content-Type": "application/json", "X-goog-api-key": api_key}
    payload = {
        "contents": [{"parts": [{"text": f"You are a helpful healthcare AI assistant. Provide accurate, helpful medical information while reminding users to consult healthcare professionals for medical advice.\n\nQuestion: {question}"}]}],
        "generationConfig": {"temperature": 0.7, "topP": 0.8, "maxOutputTokens": 1000}
    }
    max_retries = 3
    retry_delay = 1
    for attempt in range(max_retries):
        try:
            try:
                socket.gethostbyname('generativelanguage.googleapis.com')
            except socket.gaierror as dns_error:
                logging.error(f"DNS resolution failed for generativelanguage.googleapis.com: {dns_error}")
                return f"DNS resolution failed. Please check your internet connection or DNS settings. Error: {str(dns_error)}"
            response = requests.post(url, json=payload, headers=headers, timeout=30)
            response.raise_for_status()
            data = response.json()
            if "candidates" in data and data["candidates"]:
                return data["candidates"][0]["content"]["parts"][0]["text"]
            return "No response received from the AI service."
        except requests.exceptions.ConnectionError as e:
            if "NameResolutionError" in str(e) or "getaddrinfo failed" in str(e):
                if attempt < max_retries - 1:
                    time.sleep(retry_delay * (2 ** attempt))
                    continue
                return "DNS resolution failed. Please check your DNS settings or internet connection."
            return "Unable to connect to the AI service. Please check your internet connection."
        except requests.exceptions.Timeout:
            if attempt < max_retries - 1:
                time.sleep(retry_delay * (2 ** attempt))
                continue
            return "Request timeout. The AI service is taking longer than expected to respond."
        except requests.exceptions.HTTPError as e:
            r = e.response
            if r and r.status_code == 429:
                return "API rate limit exceeded. Please try again later."
            if r and r.status_code == 401:
                return "Invalid API key. Please check your Google Gemini API key."
            if r and r.status_code == 500:
                return "Google Gemini service is temporarily unavailable. Please try again later."
            return f"AI service error: {str(e)}"
        except Exception as e:
            logging.error(f"Unexpected error in ask_gemini: {e}")
            return "An unexpected error occurred while processing your request. Please try again later."
    return "Maximum retry attempts reached. Please try again later."

def ask_mistral(question, api_key, model="mistral-small-latest"):
    if not api_key:
        raise ValueError("Mistral API key is required")
    import socket, time  # noqa
    url = "https://api.mistral.ai/v1/chat/completions"
    headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": "You are a helpful healthcare AI assistant. Provide accurate, helpful medical information while reminding users to consult healthcare professionals for medical advice."},
            {"role": "user", "content": question}
        ],
        "max_tokens": 1000,
        "temperature": 0.7
    }
    max_retries = 3
    retry_delay = 1
    for attempt in range(max_retries):
        try:
            try:
                socket.gethostbyname('api.mistral.ai')
            except socket.gaierror as dns_error:
                logging.error(f"DNS resolution failed for api.mistral.ai: {dns_error}")
                return f"DNS resolution failed. Please check your internet connection or DNS settings. Error: {str(dns_error)}"
            response = requests.post(url, json=payload, headers=headers, timeout=30)
            if response.status_code == 401:
                return "Invalid Mistral API key. Please check your API key and try again."
            if response.status_code == 429:
                return "Mistral API rate limit exceeded. Please try again later."
            if response.status_code == 500:
                return "Mistral service is temporarily unavailable. Please try again later."
            if response.status_code == 400:
                try:
                    err = response.json()
                except Exception:
                    err = {"message": response.text}
                logging.error(f"Mistral 400 error: {err}")
                return f"Mistral request was invalid. Details: {err}"
            response.raise_for_status()
            data = response.json()
            if "choices" in data and data["choices"]:
                return data["choices"][0]["message"]["content"]
            return "No response received from the Mistral AI service."
        except requests.exceptions.ConnectionError as e:
            if "NameResolutionError" in str(e) or "getaddrinfo failed" in str(e):
                if attempt < max_retries - 1:
                    time.sleep(retry_delay * (2 ** attempt))
                    continue
                return "DNS resolution failed. Please check your DNS settings or internet connection."
            return "Unable to connect to the Mistral AI service. Please check your internet connection."
        except requests.exceptions.Timeout:
            if attempt < max_retries - 1:
                time.sleep(retry_delay * (2 ** attempt))
                continue
            return "Request timeout. The Mistral AI service is taking longer than expected to respond."
        except requests.exceptions.HTTPError as e:
            r = e.response
            if r and r.status_code == 429:
                return "Mistral API rate limit exceeded. Please try again later."
            if r and r.status_code == 401:
                return "Invalid Mistral API key. Please check your API key."
            if r and r.status_code == 500:
                return "Mistral service is temporarily unavailable. Please try again later."
            return f"Mistral AI service error: {str(e)}"
        except Exception as e:
            logging.error(f"Unexpected error in ask_mistral: {e}")
            return "An unexpected error occurred while processing your request. Please try again later."
    return "Maximum retry attempts reached. Please try again later."

def ask_claude(question, api_key, model="claude-3-haiku-20240307", _fallback=None):
    if not api_key:
        raise ValueError("Claude API key is required")
    import socket, time  # noqa
    url = "https://api.anthropic.com/v1/messages"
    headers = {
        "x-api-key": api_key,
        "Content-Type": "application/json",
        "anthropic-version": "2023-06-01"
    }
    payload = {
        "model": model,
        "max_tokens": 256,
        "temperature": 0.7,
        "system": "You are a helpful healthcare AI assistant. Provide accurate, helpful medical information while reminding users to consult healthcare professionals for medical advice.",
        "messages": [{"role": "user", "content": question}]
    }
    max_retries = 3
    retry_delay = 1
    for attempt in range(max_retries):
        try:
            try:
                socket.gethostbyname('api.anthropic.com')
            except socket.gaierror as dns_error:
                logging.error(f"DNS resolution failed for api.anthropic.com: {dns_error}")
                return f"DNS resolution failed. Please check your internet connection or DNS settings. Error: {str(dns_error)}"
            response = requests.post(url, json=payload, headers=headers, timeout=30)
            if response.status_code in (400, 401, 429, 500):
                try:
                    err = response.json()
                except Exception:
                    err = {"message": response.text}
                msg = ""
                if isinstance(err, dict):
                    error_obj = err.get("error", {})
                    if isinstance(error_obj, dict):
                        msg = error_obj.get("message", "")
                if response.status_code == 401:
                    return "Invalid Claude API key. Please check your API key."
                if response.status_code == 429:
                    return "Claude API rate limit exceeded. Please try again later."
                if response.status_code == 500:
                    return "Claude service is temporarily unavailable. Please try again later."
                if response.status_code == 400 and "credit balance is too low" in (msg or "").lower():
                    return ("Claude is unavailable for this account right now (insufficient credits). "
                            "Add credits in Anthropic Billing or pass a fallback_provider to continue.")
                logging.error(f"Claude 400 error: {err}")
                return f"Claude request was invalid. Details: {err}"
            response.raise_for_status()
            data = response.json()
            if "content" in data and isinstance(data["content"], list) and data["content"]:
                texts = [b.get("text", "") for b in data["content"] if isinstance(b, dict)]
                return " ".join([t for t in texts if t]).strip() or "No response received from the Claude AI service."
            return "No response received from the Claude AI service."
        except requests.exceptions.ConnectionError as e:
            if "NameResolutionError" in str(e) or "getaddrinfo failed" in str(e):
                if attempt < max_retries - 1:
                    time.sleep(retry_delay * (2 ** attempt))
                    continue
                return "DNS resolution failed. Please check your DNS settings or internet connection."
            return "Unable to connect to the Claude AI service. Please check your internet connection."
        except requests.exceptions.Timeout:
            if attempt < max_retries - 1:
                time.sleep(retry_delay * (2 ** attempt))
                continue
            return "Request timeout. The Claude AI service is taking longer than expected to respond."
        except requests.exceptions.HTTPError as e:
            r = e.response
            if r and r.status_code == 429:
                return "Claude API rate limit exceeded. Please try again later."
            if r and r.status_code == 401:
                return "Invalid Claude API key. Please check your API key."
            if r and r.status_code == 500:
                return "Claude service is temporarily unavailable. Please try again later."
            return f"Claude AI service error: {str(e)}"
        except Exception as e:
            logging.error(f"Unexpected error in ask_claude: {e}")
            return "An unexpected error occurred while processing your request. Please try again later."
    return "Maximum retry attempts reached. Please try again later."

def ask_provider(question, api_key, provider="openai", model=None, fallback=None):
    providers = {
        "openai": ask_openai,
        "gemini": ask_gemini,
        "mistral": ask_mistral,
        "claude": ask_claude,
    }
    if provider not in providers:
        raise ValueError(f"Unsupported provider: {provider}")
    primary = providers[provider](question, api_key, model)
    if (provider == "claude" and isinstance(primary, str)
            and "insufficient credits" in primary.lower()
            and fallback in providers):
        fb_key = os.getenv(f"{fallback.upper()}_API_KEY")
        if not fb_key:
            return primary
        try:
            return providers[fallback](question, fb_key, None)
        except Exception:
            return primary
    return primary

@app.post("/medlifeV21/addmember")
async def add_member(data: Data = Body(...)):
    email = data.email
    conn = get_db_connection()
    try:
        record = conn.execute("SELECT * FROM family_members WHERE email = ?", (email,)).fetchone()
        if not record:
            conn.execute(
                """
                INSERT INTO family_members (
                    email,
                    member1_firstName, member1_lastName, member1_dob, member1_race, member1_gender,
                    member1_height, member1_weight, member1_a1c, member1_bloodPressure, member1_medicine,
                    member1_zip_code, member1_bmi
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    email,
                    data.firstName, data.lastName, data.dob, data.race, data.gender,
                    data.height, data.weight, data.a1c, data.bloodPressure, data.medicine,
                    data.zip_code, data.bmi
                )
            )
            conn.commit()
            return {"message": "member1 added successfully"}
        else:
            for i in range(1, 5):
                if not record[f"member{i}_firstName"]:
                    conn.execute(
                        f"""
                        UPDATE family_members SET
                            member{i}_firstName = ?,
                            member{i}_lastName = ?,
                            member{i}_dob = ?,
                            member{i}_race = ?,
                            member{i}_gender = ?,
                            member{i}_height = ?,
                            member{i}_weight = ?,
                            member{i}_a1c = ?,
                            member{i}_bloodPressure = ?,
                            member{i}_medicine = ?,
                            member{i}_zip_code = ?,
                            member{i}_bmi = ?
                        WHERE email = ?
                        """,
                        (
                            data.firstName, data.lastName, data.dob, data.race, data.gender,
                            data.height, data.weight, data.a1c, data.bloodPressure, data.medicine,
                            data.zip_code, data.bmi,
                            email
                        )
                    )
                    conn.commit()
                    return {"message": f"member{i} added successfully"}
            raise HTTPException(status_code=400, detail="Maximum of 4 members allowed per user.")
    finally:
        conn.close()

@app.post("/medlifeV21/editmember")
async def edit_member(member_index: int = Query(..., ge=1, le=4), data: Data = Body(...)):
    email = data.email
    conn = get_db_connection()
    try:
        row = conn.execute("SELECT * FROM family_members WHERE email = ?", (email,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="User not found")

        conn.execute(
            f"""
            UPDATE family_members
            SET 
                member{member_index}_firstName = ?,
                member{member_index}_lastName = ?,
                member{member_index}_dob = ?,
                member{member_index}_race = ?,
                member{member_index}_gender = ?,
                member{member_index}_height = ?,
                member{member_index}_weight = ?,
                member{member_index}_a1c = ?,
                member{member_index}_bloodPressure = ?,
                member{member_index}_medicine = ?,
                member{member_index}_zip_code = ?,
                member{member_index}_bmi = ?
            WHERE email = ?
            """,
            (
                data.firstName, data.lastName, data.dob, data.race, data.gender,
                data.height, data.weight, data.a1c, data.bloodPressure, data.medicine,
                data.zip_code, data.bmi,
                email
            )
        )
        conn.commit()
        return {"message": "Member updated successfully"}
    finally:
        conn.close()

@app.get("/medlifeV21/getmember")
async def get_member(email: str = Query(...)):
    conn = get_db_connection()
    try:
        row = conn.execute("SELECT * FROM family_members WHERE email = ?", (email,)).fetchone()
        if not row:
            return {"members": []}
        members = []
        for i in range(1, 5):
            p = f"member{i}_"
            if row[p + "firstName"]:
                members.append({
                    "firstName": row[p + "firstName"],
                    "lastName": row[p + "lastName"],
                    "dob": row[p + "dob"],
                    "race": row[p + "race"],
                    "gender": row[p + "gender"],
                    "height": row[p + "height"],
                    "weight": row[p + "weight"],
                    "a1c": row[p + "a1c"],
                    "bloodPressure": row[p + "bloodPressure"],
                    "medicine": row[p + "medicine"],
                    "zip_code": row[p + "zip_code"],
                    "bmi": row[p + "bmi"],
                })
        return {"members": members}
    finally:
        conn.close()

# ---------------- Delete Member (with shift up) ----------------
@app.delete("/medlifeV21/deletemember")
async def delete_member(email: str = Query(...), member_index: int = Query(..., ge=1, le=4)):
    conn = get_db_connection()
    try:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute(
            "SELECT * FROM family_members WHERE email = ?", (email,)
        ).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="User not found")

        prefix = f"member{member_index}_"
        if not row[prefix + "firstName"]:
            raise HTTPException(status_code=404, detail=f"Member {member_index} not found")

        for i in range(member_index, 4):
            curr_prefix = f"member{i}_"
            next_prefix = f"member{i+1}_"
            conn.execute(
                f"""
                UPDATE family_members SET
                    {curr_prefix}firstName     = ?,
                    {curr_prefix}lastName      = ?,
                    {curr_prefix}dob           = ?,
                    {curr_prefix}race          = ?,
                    {curr_prefix}gender        = ?,
                    {curr_prefix}height        = ?,
                    {curr_prefix}weight        = ?,
                    {curr_prefix}a1c           = ?,
                    {curr_prefix}bloodPressure = ?,
                    {curr_prefix}medicine      = ?,
                    {curr_prefix}zip_code      = ?,
                    {curr_prefix}bmi           = ?,
                    {curr_prefix}tokens        = COALESCE({next_prefix}tokens, 0)
                WHERE email = ?
                """,
                (
                    row[next_prefix + "firstName"],
                    row[next_prefix + "lastName"],
                    row[next_prefix + "dob"],
                    row[next_prefix + "race"],
                    row[next_prefix + "gender"],
                    row[next_prefix + "height"],
                    row[next_prefix + "weight"],
                    row[next_prefix + "a1c"],
                    row[next_prefix + "bloodPressure"],
                    row[next_prefix + "medicine"],
                    row[next_prefix + "zip_code"],
                    row[next_prefix + "bmi"],
                    email,
                ),
            )

        conn.execute(
            """
            UPDATE family_members SET
                member4_firstName = NULL,
                member4_lastName = NULL,
                member4_dob = NULL,
                member4_race = NULL,
                member4_gender = NULL,
                member4_height = NULL,
                member4_weight = NULL,
                member4_a1c = NULL,
                member4_bloodPressure = NULL,
                member4_medicine = NULL,
                member4_zip_code = NULL,
                member4_bmi = NULL,
                member4_tokens = 0
            WHERE email = ?
            """,
            (email,),
        )
        conn.commit()
        return {
            "message": f"Member {member_index} deleted and members shifted",
            "deleted_member_index": member_index,
            "email": email,
        }
    except sqlite3.Error as e:
        logging.error(f"Database error during member deletion: {e}")
        try:
            conn.rollback()
        except Exception:
            pass
        raise HTTPException(status_code=500, detail="Database error occurred")
    finally:
        conn.close()

# ---------------- Ask AI (sidebar) ----------------
@app.get("/medlifeV21/ask_ai/")
async def ask_ai(query: str, api_key: str, provider: str = "openai",
                 email: Optional[str] = None, member_data: Optional[str] = None,
                 fallback_provider: Optional[str] = None):
    prompt_text = "Act as a Healthcare AI assistant, answer health questions based on patient data. "
    if member_data and member_data != "undefined":
        try:
            member = json.loads(member_data)
            prompt_text += (
                f"\n\nPatient Details:\n"
                f"Name: {member.get('firstName', '')} {member.get('lastName', '')}\n"
                f"Date of Birth: {member.get('dob', '')}\n"
                f"Gender: {member.get('gender', '')}\n"
                f"Race: {member.get('race', '')}\n"
                f"Height: {member.get('height', '')}\n"
                f"Weight: {member.get('weight', '')}\n"
                f"A1C Level: {member.get('a1c', '')}\n"
                f"Blood Pressure: {member.get('bloodPressure', '')}\n"
                f"Current Medications: {member.get('medicine', '')}\n"
                f"Zip Code: {member.get('zip_code', '')}\n"
                f"bmi: {member.get('bmi', '')}\n"
            )
        except json.JSONDecodeError:
            pass
    prompt_text += f"\n\nQuestion: {query}"
    config = get_provider_config(provider)
    model = config["models"][0] if config and "models" in config else "gpt-3.5-turbo"
    try:
        return ask_provider(prompt_text, api_key, provider, model, fallback=fallback_provider)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

# ---------------- Prompt (chat area) ----------------
@app.get("/medlifeV21/prompt/")
async def prompt(query: str, api_key: str):
    if not api_key:
        raise HTTPException(status_code=400, detail="OpenAI API key is required")
    try:
        return ask_openai(
            f"Act as a Healthcare AI assistant. Only answer health-related questions. "
            f"The following contains patient details and a question: {query}",
            api_key
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

# ---------------- Tokens (per member) ----------------
@app.get("/medlifeV21/tokens/")
async def increment_tokens(email: str, member_name: str):
    conn = get_db_connection()
    try:
        row = conn.execute("SELECT * FROM family_members WHERE email = ?", (email,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="User not found")
        member_index = None
        for i in range(1, 5):
            if row[f"member{i}_firstName"] == member_name:
                member_index = i
                break
        if member_index is None:
            raise HTTPException(status_code=404, detail="Member not found")
        col = f"member{member_index}_tokens"
        current_tokens = row[col] or 0
        if current_tokens >= 100:
            raise HTTPException(status_code=400, detail="Question limit exceeded.")
        new_tokens = current_tokens + 1
        conn.execute(f"UPDATE family_members SET {col} = ? WHERE email = ?", (new_tokens, email))
        conn.commit()
        return {"message": str(new_tokens)}
    finally:
        conn.close()

@app.get("/medlifeV21/tokensCount/")
async def get_token_count(email: str, member_name: str):
    conn = get_db_connection()
    try:
        row = conn.execute("SELECT * FROM family_members WHERE email = ?", (email,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="User not found")
        member_index = None
        for i in range(1, 5):
            if row[f"member{i}_firstName"] == member_name:
                member_index = i
                break
        if member_index is None:
            raise HTTPException(status_code=404, detail="Member not found")
        tokens = row[f"member{member_index}_tokens"] or 0
        return {"message": str(tokens)}
    finally:
        conn.close()

@app.get("/medlifeV21/member-details/{email}/{member_index}")
async def get_member_details(email: str, member_index: int):
    if member_index < 1 or member_index > 4:
        raise HTTPException(status_code=400, detail="Invalid member index. Must be between 1 and 4")
    conn = get_db_connection()
    try:
        row = conn.execute("SELECT * FROM family_members WHERE email = ?", (email,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="User not found")
        p = f"member{member_index}_"
        if not row[p + "firstName"]:
            raise HTTPException(status_code=404, detail=f"Member {member_index} not found")
        return {
            "member": {
                "memberIndex": member_index,
                "firstName": row[p + "firstName"],
                "lastName": row[p + "lastName"],
                "dob": row[p + "dob"],
                "race": row[p + "race"],
                "gender": row[p + "gender"],
                "height": row[p + "height"],
                "weight": row[p + "weight"],
                "a1c": row[p + "a1c"],
                "bloodPressure": row[p + "bloodPressure"],
                "medicine": row[p + "medicine"],
                "zip_code": row[p + "zip_code"],
                "bmi": row[p + "bmi"],
                "fullName": f"{row[p + 'firstName']} {row[p + 'lastName']}"
            }
        }
    except sqlite3.Error as e:
        logging.error(f"Database error fetching member details: {e}")
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        conn.close()

# ---------------- Chat data FS storage ----------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CHAT_DATA_DIR = os.path.join(BASE_DIR, 'chat_data')
os.makedirs(CHAT_DATA_DIR, exist_ok=True)

def save_chat_data_to_file(email: str, member_name: str, chat_data: list):
    file_path = os.path.join(CHAT_DATA_DIR, f"{email}_{member_name}.json")
    with open(file_path, 'w') as f:
        json.dump(chat_data, f)

def load_chat_data_from_file(email: str, member_name: str):
    file_path = os.path.join(CHAT_DATA_DIR, f"{email}_{member_name}.json")
    if not os.path.exists(file_path):
        return []
    with open(file_path, 'r') as f:
        return json.load(f)

@app.get("/medlifeV21/fetchChat/")
async def fetch_chat(email: str, member_name: str):
    return {"chat": load_chat_data_from_file(email, member_name)}

@app.post("/medlifeV21/saveChat/")
async def save_chat(email: str, member_name: str, request: Request):
    data = await request.json()
    chat = data.get("chat", [])
    save_chat_data_to_file(email, member_name, chat)
    return {"message": "Chat data saved successfully"}

# ---------------- OTP API Endpoints (post-login for extra verification) ----------------
@app.post("/medlifeV21/send-otp")
async def send_otp(request: SendOTPRequest, current_user: str = Depends(get_current_user)):
    """
    Send OTP to email or mobile number AFTER user already has a JWT (extra verification).
    Ensures identifier belongs to the logged-in user.
    """
    conn = get_db_connection()
    try:
        cleanup_expired_otps()
        if request.type not in ["email", "sms"]:
            raise HTTPException(status_code=400, detail="Invalid type. Must be 'email' or 'sms'")

        user_row = conn.execute(
            "SELECT email, mobile FROM users WHERE email = ?", (current_user,)
        ).fetchone()
        if not user_row:
            raise HTTPException(status_code=404, detail="User not found")

        if request.type == "email" and request.identifier != user_row["email"]:
            raise HTTPException(status_code=400, detail="Email does not match logged in user")
        if request.type == "sms" and request.identifier != str(user_row["mobile"]):
            raise HTTPException(status_code=400, detail="Mobile number does not match logged in user")

        otp_code = generate_otp()
        expires_at = datetime.utcnow() + timedelta(minutes=5)
        conn.execute(
            """
            INSERT INTO otp_codes (email, mobile, otp_code, type, expires_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                user_row["email"] if request.type == "email" else None,
                user_row["mobile"] if request.type == "sms" else None,
                otp_code,
                request.type,
                expires_at
            )
        )
        conn.commit()

        success = send_email_otp(request.identifier, otp_code) if request.type == "email" else send_sms_otp(request.identifier, otp_code)
        if not success:
            raise HTTPException(status_code=500, detail="Failed to send OTP")

        return {"message": f"OTP sent successfully via {request.type}", "expires_in": 300}
    except HTTPException:
        raise
    except Exception as e:
        logging.error(f"Error sending OTP: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")
    finally:
        conn.close()

@app.post("/medlifeV21/verify-otp")
async def verify_otp(request: VerifyOTPRequest, current_user: str = Depends(get_current_user)):
    """
    Verify OTP for the logged-in user (extra verification step).
    """
    conn = get_db_connection()
    try:
        user_row = conn.execute(
            "SELECT email, mobile FROM users WHERE email = ?", (current_user,)
        ).fetchone()
        if not user_row:
            raise HTTPException(status_code=404, detail="User not found")

        if request.type == "email" and request.identifier != user_row["email"]:
            raise HTTPException(status_code=400, detail="Email does not match logged in user")
        if request.type == "sms" and request.identifier != str(user_row["mobile"]):
            raise HTTPException(status_code=400, detail="Mobile number does not match logged in user")

        otp_row = conn.execute(
            """
            SELECT * FROM otp_codes 
            WHERE type = ? AND 
                  ((type = 'email' AND email = ?) OR (type = 'sms' AND mobile = ?)) AND
                  otp_code = ? AND
                  used = 0 AND
                  expires_at > ? AND
                  attempts < 3
            """,
            (request.type, request.identifier, request.identifier, request.otp_code, datetime.utcnow())
        ).fetchone()

        if not otp_row:
            conn.execute(
                """
                UPDATE otp_codes 
                SET attempts = attempts + 1 
                WHERE type = ? AND 
                      ((type = 'email' AND email = ?) OR (type = 'sms' AND mobile = ?)) AND
                      otp_code = ? AND
                      used = 0
                """,
                (request.type, request.identifier, request.identifier, request.otp_code)
            )
            conn.commit()
            raise HTTPException(status_code=400, detail="Invalid or expired OTP")

        conn.execute("UPDATE otp_codes SET used = 1 WHERE id = ?", (otp_row["id"],))
        conn.commit()
        return {"message": "OTP verified successfully", "verified": True}
    except HTTPException:
        raise
    except Exception as e:
        logging.error(f"Error verifying OTP: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")
    finally:
        conn.close()

@app.get("/medlifeV21/otp-status")
async def get_otp_status(type: str, identifier: str, current_user: str = Depends(get_current_user)):
    conn = get_db_connection()
    try:
        if type not in ["email", "sms"]:
            raise HTTPException(status_code=400, detail="Invalid type. Must be 'email' or 'sms'")

        user_row = conn.execute(
            "SELECT email, mobile FROM users WHERE email = ?", (current_user,)
        ).fetchone()
        if not user_row:
            raise HTTPException(status_code=404, detail="User not found")

        if type == "email" and identifier != user_row["email"]:
            raise HTTPException(status_code=400, detail="Email does not match logged in user")
        if type == "sms" and identifier != str(user_row["mobile"]):
            raise HTTPException(status_code=400, detail="Mobile number does not match logged in user")

        active_otp = conn.execute(
            """
            SELECT * FROM otp_codes 
            WHERE type = ? AND 
                  ((type = 'email' AND email = ?) OR (type = 'sms' AND mobile = ?)) AND
                  used = 0 AND
                  expires_at > ? AND
                  attempts < 3
            """,
            (type, identifier, identifier, datetime.utcnow())
        ).fetchone()

        if active_otp:
            return {"has_active_otp": True, "expires_at": active_otp["expires_at"], "attempts": active_otp["attempts"]}
        else:
            return {"has_active_otp": False}
    except HTTPException:
        raise
    except Exception as e:
        logging.error(f"Error checking OTP status: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")
    finally:
        conn.close()

# ---------------- OTP-based SIGN-IN (passwordless) ----------------
@app.post("/medlifeV21/check-user", response_model=CheckUserExistsResponse)
def check_user_exists(payload: CheckUserExistsRequest):
    """
    OPTIONAL helper: front-end can call this before /signin
    to know if the email/phone exists and what type it is.
    """
    login = payload.login.strip()
    conn = get_db_connection()
    try:
        if re.match(r'^[^@]+@[^@]+\.[^@]+$', login):
            row = conn.execute("SELECT 1 FROM users WHERE email = ?", (login,)).fetchone()
            return {"exists": bool(row), "login_type": "email"}
        else:
            # numeric phone
            try:
                mobile_int = int(login)
            except ValueError:
                return {"exists": False, "login_type": "phone"}
            row = conn.execute("SELECT 1 FROM users WHERE mobile = ?", (mobile_int,)).fetchone()
            return {"exists": bool(row), "login_type": "phone"}
    finally:
        conn.close()

@app.post("/medlifeV21/signin")
def signin_start(payload: SignInStart):
    """
    Start OTP login by sending an OTP to the provided email or mobile.
    Ensures the identifier exists in DB before sending OTP.
    """
    cleanup_expired_otps()
    if payload.type not in ("email", "sms"):
        raise HTTPException(status_code=400, detail="Invalid type. Use 'email' or 'sms'.")

    conn = get_db_connection()
    try:
        if payload.type == "email":
            user_row = conn.execute(
                "SELECT email, mobile, password_hash FROM users WHERE email = ?",
                (payload.identifier,)
            ).fetchone()
            if not user_row:
                raise HTTPException(status_code=404, detail="Email not registered")
            if not pwd_context.verify(payload.password, user_row["password_hash"]):
                raise HTTPException(status_code=401, detail="Incorrect password")
        else:
            try:
                mobile_int = int(payload.identifier)
            except ValueError:
                raise HTTPException(status_code=400, detail="Invalid mobile format")
            user_row = conn.execute(
                "SELECT email, mobile FROM users WHERE mobile = ?",
                (mobile_int,)
            ).fetchone()
            if not user_row:
                raise HTTPException(status_code=404, detail="Mobile not registered")

        otp_code = generate_otp()
        expires_at = datetime.utcnow() + timedelta(minutes=5)
        conn.execute(
            """
            INSERT INTO otp_codes (email, mobile, otp_code, type, expires_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                user_row["email"] if payload.type == "email" else None,
                user_row["mobile"] if payload.type == "sms" else None,
                otp_code,
                payload.type,
                expires_at
            )
        )
        conn.commit()

        ok = send_email_otp(payload.identifier, otp_code) if payload.type == "email" else send_sms_otp(payload.identifier, otp_code)
        if not ok:
            raise HTTPException(status_code=502, detail="Failed to send OTP")

        return {"message": f"OTP sent to {payload.type}", "expires_in": 300}
    except HTTPException:
        raise
    except Exception as e:
        logging.error(f"signin_start error: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")
    finally:
        conn.close()

@app.post("/medlifeV21/verify-login-otp")
def verify_login_otp(payload: VerifyLoginOTP):
    """
    Verify OTP for login and return a JWT access token upon success.
    """
    conn = get_db_connection()
    try:
        # Resolve user by identifier
        if payload.type == "email":
            user_row = conn.execute(
                "SELECT email, mobile FROM users WHERE email = ?",
                (payload.identifier,)
            ).fetchone()
        else:
            try:
                mobile_int = int(payload.identifier)
            except ValueError:
                raise HTTPException(status_code=400, detail="Invalid mobile format")
            user_row = conn.execute(
                "SELECT email, mobile FROM users WHERE mobile = ?",
                (mobile_int,)
            ).fetchone()

        if not user_row:
            raise HTTPException(status_code=404, detail="User not found")

        # Find valid OTP (not used, not expired, attempts < 3)
        otp_row = conn.execute(
            """
            SELECT * FROM otp_codes 
            WHERE type = ?
              AND ((type='email' AND email=?) OR (type='sms' AND mobile=?))
              AND otp_code = ?
              AND used = 0
              AND expires_at > ?
              AND attempts < 3
            """,
            (
                payload.type,
                payload.identifier if payload.type == "email" else None,
                payload.identifier if payload.type == "sms" else None,
                payload.otp_code,
                datetime.utcnow()
            )
        ).fetchone()

        if not otp_row:
            # bump attempt count (best effort)
            conn.execute(
                """
                UPDATE otp_codes
                SET attempts = attempts + 1
                WHERE type = ?
                  AND ((type='email' AND email=?) OR (type='sms' AND mobile=?))
                  AND otp_code = ?
                  AND used = 0
                """,
                (
                    payload.type,
                    payload.identifier if payload.type == "email" else None,
                    payload.identifier if payload.type == "sms" else None,
                    payload.otp_code
                )
            )
            conn.commit()
            raise HTTPException(status_code=400, detail="Invalid or expired OTP")

        # Mark OTP as used
        conn.execute("UPDATE otp_codes SET used = 1 WHERE id = ?", (otp_row["id"],))
        conn.commit()

        # Issue JWT for this user (sub = email)
        access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = create_access_token(
            data={"sub": user_row["email"]},
            expires_delta=access_token_expires
        )
        return {
            "message": "OTP verified",
            "access_token": access_token,
            "token_type": "bearer",
            "email": user_row["email"]
        }
    except HTTPException:
        raise
    except Exception as e:
        logging.error(f"verify_login_otp error: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")
    finally:
        conn.close()


# ---------------- OCR: /medlifeV21/ocr ----------------
# deps: pip install boto3 pillow pillow-heif (optional)
# =========================
# OCR helpers & endpoint (single-endpoint in same app.py)
# =========================
# medlife_vision.py
# FastAPI endpoint: send an image, get back medicine label(s) using OpenAI Vision (gpt-4o-mini).
# No Textract, no OCR loops. Safer + faster than putting your API key in the frontend.
# ---------- Medlife Vision Imports (safe to repeat) ----------
import io, os, re, json, base64
from typing import List, Dict
from fastapi import UploadFile, File, HTTPException
from PIL import Image
from openai import OpenAI

# ---------- OpenAI client (init once) ----------
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY") or os.getenv("OPENAI_APIKEY")
if not OPENAI_API_KEY:
    raise RuntimeError("Set OPENAI_API_KEY")  # e.g., export OPENAI_API_KEY=sk-...
OPENAI_VISION_MODEL = os.getenv("OPENAI_VISION_MODEL", "gpt-4o-mini")
_openai_client = OpenAI(api_key=OPENAI_API_KEY)

# ---------- Utils ----------
def _mv_clean_flat(s: str) -> str:
    if not s: 
        return ""
    s = s.replace("\r", "\n")
    s = re.sub(r"\n+", " ", s)
    s = re.sub(r"[ \t]+", " ", s)
    s = re.sub(r"[^\x20-\x7E]", " ", s)
    return s.strip()

def _mv_jpegify(raw: bytes, short_edge: int = 900, quality: int = 85) -> bytes:
    """Downscale + JPEG for smaller payload & faster model ingest."""
    try:
        img = Image.open(io.BytesIO(raw))
        if img.mode not in ("RGB", "L"):
            img = img.convert("RGB")
        w, h = img.size
        short = min(w, h)
        if short > short_edge:
            scale = short_edge / short
            img = img.resize((int(w * scale), int(h * scale)))
        buf = io.BytesIO()
        img.save(buf, format="JPEG", quality=quality, optimize=True)
        return buf.getvalue()
    except Exception:
        return raw

def _mv_format_labels(items: List[Dict[str, str]]) -> List[str]:
    """[{brand, strength_form?, generic?}] → ['Brand Strength (Generic)']"""
    out, seen = [], set()
    for it in items or []:
        brand = (it.get("brand") or "").strip()
        generic = (it.get("generic") or "").strip()
        sf = (it.get("strength_form") or "").strip()
        if not brand and not sf and not generic:
            continue
        base = brand if brand else (sf if sf else "Unknown")
        if brand and sf:
            base = f"{brand} {sf}"
        label = f"{base} ({generic})" if generic else base
        k = label.lower()
        if k not in seen:
            seen.add(k)
            out.append(label)
    return out

# ---------- Vision prompt ----------
__MV_SYSTEM = (
    "You read medicine/package/prescription images and extract the primary medicine. "
    "Return a short JSON only (no prose). If uncertain, leave fields blank."
)
__MV_USER = (
    "From this image, extract the single most likely medicine entry.\n"
    "Rules:\n"
    "- brand: printed brand name on pack/label; short and exact.\n"
    "- strength_form: like '500 mg Tablet', '125 mg/5ml Syrup', etc.\n"
    "- generic: composition or active ingredient(s). If combo, join with ' + '.\n"
    "- Do NOT include Rx numbers, patient names, addresses, or pharmacy text.\n"
    'Respond ONLY as JSON: {"items":[{"brand":"","strength_form":"","generic":""}]}\n'
)

def _mv_ask_vision_json(data_url: str) -> Dict:
    resp = _openai_client.chat.completions.create(
        model=OPENAI_VISION_MODEL,
        temperature=0,
        max_tokens=200,
        messages=[
            {"role": "system", "content": __MV_SYSTEM},
            {"role": "user", "content": [
                {"type": "text", "text": __MV_USER},
                {"type": "image_url", "image_url": {"url": data_url}},
            ]},
        ],
    )
    msg = resp.choices[0].message
    txt = (msg.content or "").strip()

    # Parse JSON directly; if wrapped, salvage the first JSON block
    try:
        return json.loads(txt)
    except Exception:
        m = re.search(r"\{[\s\S]*\}", txt)
        if m:
            try:
                return json.loads(m.group(0))
            except Exception:
                pass
    return {"items": []}

# ---------- Endpoint (attach to your existing `app`) ----------
@app.post("/medlifeV21/ocr")
async def medlife_vision(file: UploadFile = File(...)):
    """
    Upload a pack/blister/prescription image → returns:
    { "medicines": ["Brand Strength (Generic)"] }
    """
    raw = await file.read()
    if not raw:
        raise HTTPException(400, "No file data")

    # Compress for speed, then send as data URL to Vision
    jpg = _mv_jpegify(raw)
    b64 = base64.b64encode(jpg).decode("utf-8")
    data_url = f"data:image/jpeg;base64,{b64}"

    data = _mv_ask_vision_json(data_url)
    meds = _mv_format_labels(data.get("items", []))

    # Scrub obvious RX noise if any slipped in
    meds = [_mv_clean_flat(re.sub(r"(?i)\brx[#:\s]*\w+\b", "", m)).strip(" -") for m in meds]
    meds = [m for m in meds if m]

    if not meds:
        items = data.get("items") or []
        if items:
            meds = _mv_format_labels(items)

    if not meds:
        raise HTTPException(422, "Could not confidently extract medicine from image")

    return {"medicines": meds}
