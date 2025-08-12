import logging
import hashlib
import re
from fastapi import FastAPI,  HTTPException, Depends, Security
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
import json
from openai import OpenAI
import random
from datetime import datetime, timedelta
from jose import JWTError, jwt

from dotenv import load_dotenv
import os
import sqlite3
from passlib.context import CryptContext
import requests
import base64
from cryptography.fernet import Fernet
from cryptography   .hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import secrets
load_dotenv()

# JWT Configuration
SECRET_KEY = "your-secret-key-change-this-in-production"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

from typing import Optional
from datetime import datetime, timedelta

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta is not None:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=401,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email = payload.get("sub")
        if email is None:
            raise credentials_exception
        return email
    except JWTError:
        raise credentials_exception

logging.basicConfig(filename='app.log', level=logging.DEBUG, format='%(asctime)s %(levelname)s:%(message)s')

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

from fastapi import Query

@app.get("/api/get-username")
async def get_username(email: str = Query(...)):
    conn = get_db_connection()
    try:
        cursor = conn.execute("SELECT username FROM users WHERE email = ?", (email,))
        row = cursor.fetchone()
        if row:
            return {"username": row["username"]}
        else:
            return {"username": None}
    finally:
        conn.close()

@app.get("/api/get-user-gender")
async def get_user_gender(email: str = Query(...)):
    conn = get_db_connection()
    try:
        cursor = conn.execute("SELECT member1_gender FROM family_members WHERE email = ?", (email,))
        row = cursor.fetchone()
        if row and row["member1_gender"]:
            return {"gender": row["member1_gender"]}
        else:
            return {"gender": None}
    finally:
        conn.close()

# ---------- USER AUTH SETUP ----------
DATABASE_URL = "users.db"
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def get_db_connection():
    conn = sqlite3.connect(DATABASE_URL)
    conn.row_factory = sqlite3.Row
    return conn

def init_user_db():
    conn = get_db_connection()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        )
    """)
    # New family_members table with dedicated columns for each member
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
        member4_tokens INTEGER DEFAULT 0
    )
    """)
    conn.commit()
    conn.close()

init_user_db()

# DATA MODELS

# ---------------- AUTH ENDPOINTS -----------------
class UserSignup(BaseModel):
    username: str
    email: str
    password: str

class UserLogin(BaseModel):
    login: str  # username or email
    password: str

@app.post("/token")
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT email, password_hash FROM users WHERE email = ? OR username = ?",
        (form_data.username, form_data.username)
    )
    row = cursor.fetchone()
    if row is None:
        conn.close()
        raise HTTPException(status_code=401, detail="Incorrect email/username or password")
    email, password_hash = row
    if not pwd_context.verify(form_data.password, password_hash):
        conn.close()
        raise HTTPException(status_code=401, detail="Incorrect email/username or password")
    conn.close()
    
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": email}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer", "email": email}

@app.post("/signin")
def login(user: UserLogin):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT email, password_hash FROM users WHERE email = ? OR username = ?",
        (user.login, user.login)
    )
    row = cursor.fetchone()
    if row is None:
        conn.close()
        raise HTTPException(status_code=401, detail="Incorrect email/username or password")
    email, password_hash = row
    if not pwd_context.verify(user.password, password_hash):
        conn.close()
        raise HTTPException(status_code=401, detail="Incorrect email/username or password")
    conn.close()
    
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": email}, expires_delta=access_token_expires
    )
    return {"message": "Login successful", "email": email, "access_token": access_token}

@app.post("/signup")
def signup(user: UserSignup):
    logging.debug(f"Signup request received: {user}")
    
    # Validate email format
    email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    if not re.match(email_regex, user.email):
        raise HTTPException(status_code=400, detail="Invalid email format")
    
    # Validate password complexity
    password = user.password
    if len(password) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters long")
    if not re.search(r'[A-Z]', password):
        raise HTTPException(status_code=400, detail="Password must contain at least one uppercase letter")
    if not re.search(r'[a-z]', password):
        raise HTTPException(status_code=400, detail="Password must contain at least one lowercase letter")
    if not re.search(r'[0-9]', password):
        raise HTTPException(status_code=400, detail="Password must contain at least one numeric digit")
    if not re.search(r'[!@#$%^&*()_+\-=\[\]{};\':"\\|,.<>\/?]', password):
        raise HTTPException(status_code=400, detail="Password must contain at least one special character")
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Check if user already exists
    cursor.execute("SELECT * FROM users WHERE email = ?", (user.email,))
    user_exists = cursor.fetchone()
    if user_exists:
        logging.warning(f"Signup attempt with existing email: {user.email}")
        raise HTTPException(status_code=409, detail="Email already registered")
    
    password_hash = pwd_context.hash(user.password)
    
    try:
        # Insert user
        cursor.execute(
            "INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)",
            (user.username, user.email, password_hash)
        )
        
        # Ensure family_members entry exists with user's email
        cursor.execute(
            "SELECT * FROM family_members WHERE email = ?", (user.email,)
        )
        family_exists = cursor.fetchone()
        
        if not family_exists:
            cursor.execute(
                "INSERT INTO family_members (email) VALUES (?)",
                (user.email,)
            )
        
        conn.commit()
        logging.info(f"User registered successfully: {user.email}")
        
    except sqlite3.Error as e:
        logging.error(f"Database error during signup: {e}")
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        conn.close()
    
    return {"message": "User registered successfully", "email": user.email}

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
    tokens: int
    email: str



@app.get("/medlife/ai")
def read_root():
    return {"Hello": "World"}
#<<<<<<<<<<<<<<<<<JSON FILE OPENER>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
def load_family_data():
    try:
        with open("family_data.json", "r") as file:
            return json.load(file)
    except FileNotFoundError:
        return {}

def save_family_data(data):
    with open("family_data.json", "w") as file:
        json.dump(data, file)

#<<<<<<<<<<<<<<<<<AI FUNCTION>>>>>>>>>>>>>>>>>>

# Multi-provider API support functions
def get_provider_config(provider: str):
    """Get configuration for different AI providers"""
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
        # Claude ordered with the lowest-cost first to maximize “free” mileage
        "claude": {
            "name": "Anthropic Claude",
            "base_url": "https://api.anthropic.com/v1",
            "models": ["claude-3-haiku-20240307", "claude-3-5-sonnet-latest", "claude-3-opus-20240229"]
        },
    }
    return configs.get(provider, configs["openai"])

def encrypt_api_key(api_key: str, email: str) -> str:
    """Encrypt API key for secure storage"""
    key = base64.urlsafe_b64encode(
        hashlib.sha256(email.encode()).digest()[:32]
    )
    f = Fernet(key)
    return f.encrypt(api_key.encode()).decode()

def decrypt_api_key(encrypted_key: str, email: str) -> str:
    """Decrypt API key from secure storage"""
    try:
        key = base64.urlsafe_b64encode(
            hashlib.sha256(email.encode()).digest()[:32]
        )
        f = Fernet(key)
        return f.decrypt(encrypted_key.encode()).decode()
    except:
        return encrypted_key  # Fallback for legacy keys

def ask_openai(question, api_key, provider="openai", model=None):
    """OpenAI API integration"""
    if not api_key:
        raise ValueError("OpenAI API key is required")
    
    client = OpenAI(api_key=api_key)
    
    if not model:
        model = "gpt-3.5-turbo"
    
    messages = [
        {"role": "system", "content": "You are a helpful healthcare AI assistant. Provide accurate, helpful medical information while reminding users to consult healthcare professionals for medical advice."},
        {"role": "user", "content": question}
    ]
    
    try:
        completion = client.chat.completions.create(
            messages=messages,
            model=model,
            max_tokens=1000,
            temperature=0.7
        )
        return completion.choices[0].message.content
    except Exception as e:
        raise ValueError(f"OpenAI API error: {str(e)}")

def ask_gemini(question, api_key, model="gemini-2.0-flash"):
    "Google Gemini API integration with enhanced error handling"
    if not api_key:
        raise ValueError("Google Gemini API key is required")
    
    import socket
    import time
    
    url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash-exp:generateContent"
    headers = {
        "Content-Type": "application/json",
        "X-goog-api-key": api_key
    }
    payload = {
        "contents": [{
            "parts": [{
                "text": f"You are a helpful healthcare AI assistant. Provide accurate, helpful medical information while reminding users to consult healthcare professionals for medical advice.\n\nQuestion: {question}"
            }]
        }],
        "generationConfig": {
            "temperature": 0.7,
            "topP": 0.8,
            "maxOutputTokens": 1000
        }
    }
    
    # Retry mechanism with exponential backoff
    max_retries = 3
    retry_delay = 1
    
    for attempt in range(max_retries):
        try:
            # Test DNS resolution first
            try:
                socket.gethostbyname('generativelanguage.googleapis.com')
            except socket.gaierror as dns_error:
                logging.error(f"DNS resolution failed for generativelanguage.googleapis.com: {dns_error}")
                return f"DNS resolution failed. Please check your internet connection or DNS settings. Error: {str(dns_error)}"
            
            response = requests.post(
                url,
                json=payload,
                headers=headers,
                timeout=30
            )
            response.raise_for_status()
            data = response.json()
            
            if "candidates" in data and data["candidates"]:
                return data["candidates"][0]["content"]["parts"][0]["text"]
            else:
                return "No response received from the AI service."
                
        except requests.exceptions.ConnectionError as e:
            if "NameResolutionError" in str(e) or "getaddrinfo failed" in str(e):
                logging.error(f"DNS resolution error on attempt {attempt + 1}: {e}")
                if attempt < max_retries - 1:
                    time.sleep(retry_delay * (2 ** attempt))
                    continue
                return "DNS resolution failed. Please check your DNS settings or internet connection."
            else:
                logging.error(f"Connection error: {e}")
                return "Unable to connect to the AI service. Please check your internet connection."
                
        except requests.exceptions.Timeout:
            logging.error(f"Request timeout on attempt {attempt + 1}")
            if attempt < max_retries - 1:
                time.sleep(retry_delay * (2 ** attempt))
                continue
            return "Request timeout. The AI service is taking longer than expected to respond."
            
        except requests.exceptions.HTTPError as e:
            response = e.response  # Get response from exception
            if response and response.status_code == 429:
                return "API rate limit exceeded. Please try again later."
            elif response and response.status_code == 401:
                return "Invalid API key. Please check your Google Gemini API key."
            elif response and response.status_code == 500:
                return "Google Gemini service is temporarily unavailable. Please try again later."
            else:
                logging.error(f"HTTP error: {e}")
                return f"AI service error: {str(e)}"
                
        except Exception as e:
            logging.error(f"Unexpected error in ask_gemini: {e}")
            return "An unexpected error occurred while processing your request. Please try again later."
    
    return "Maximum retry attempts reached. Please try again later."

def ask_mistral(question, api_key, model="mistral-small-latest"):
    """Mistral AI API integration with comprehensive error handling"""
    if not api_key:
        raise ValueError("Mistral API key is required")
    
    import socket
    import time
    
    url = "https://api.mistral.ai/v1/chat/completions"
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json"
    }

    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": "You are a helpful healthcare AI assistant. Provide accurate, helpful medical information while reminding users to consult healthcare professionals for medical advice."},
            {"role": "user", "content": question}
        ],
        "max_tokens": 1000,
        "temperature": 0.7
    }
    
    # Retry mechanism with exponential backoff
    max_retries = 3
    retry_delay = 1
    
    for attempt in range(max_retries):
        try:
            # Test DNS resolution first
            try:
                socket.gethostbyname('api.mistral.ai')
            except socket.gaierror as dns_error:
                logging.error(f"DNS resolution failed for api.mistral.ai: {dns_error}")
                return f"DNS resolution failed. Please check your internet connection or DNS settings. Error: {str(dns_error)}"
            
            response = requests.post(
                url,
                json=payload,
                headers=headers,
                timeout=30
            )
            
            if response.status_code == 401:
                return "Invalid Mistral API key. Please check your API key and try again."
            elif response.status_code == 429:
                return "Mistral API rate limit exceeded. Please try again later."
            elif response.status_code == 500:
                return "Mistral service is temporarily unavailable. Please try again later."
            elif response.status_code == 400:
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
            else:
                return "No response received from the Mistral AI service."
                
        except requests.exceptions.ConnectionError as e:
            if "NameResolutionError" in str(e) or "getaddrinfo failed" in str(e):
                logging.error(f"DNS resolution error on attempt {attempt + 1}: {e}")
                if attempt < max_retries - 1:
                    time.sleep(retry_delay * (2 ** attempt))
                    continue
                return "DNS resolution failed. Please check your DNS settings or internet connection."
            else:
                logging.error(f"Connection error: {e}")
                return "Unable to connect to the Mistral AI service. Please check your internet connection."
                
        except requests.exceptions.Timeout:
            logging.error(f"Request timeout on attempt {attempt + 1}")
            if attempt < max_retries - 1:
                time.sleep(retry_delay * (2 ** attempt))
                continue
            return "Request timeout. The Mistral AI service is taking longer than expected to respond."
            
        except requests.exceptions.HTTPError as e:
            response = e.response
            if response and response.status_code == 429:
                return "Mistral API rate limit exceeded. Please try again later."
            elif response and response.status_code == 401:
                return "Invalid Mistral API key. Please check your API key and try again."
            elif response and response.status_code == 500:
                return "Mistral service is temporarily unavailable. Please try again later."
            else:
                logging.error(f"HTTP error: {e}")
                return f"Mistral AI service error: {str(e)}"
                
        except Exception as e:
            logging.error(f"Unexpected error in ask_mistral: {e}")
            return "An unexpected error occurred while processing your request. Please try again later."
    
    return "Maximum retry attempts reached. Please try again later."

def ask_claude(question, api_key, model="claude-3-haiku-20240307", _fallback=None):
    """Claude (Anthropic) integration using the Messages API schema, tuned for free/low-credit accounts."""
    if not api_key:
        raise ValueError("Claude API key is required")
    
    import socket
    import time
    
    url = "https://api.anthropic.com/v1/messages"
    headers = {
        "x-api-key": api_key,
        "Content-Type": "application/json",
        "anthropic-version": "2023-06-01"  # required header
    }

    payload = {
        "model": model,           # default to Haiku (cheapest)
        "max_tokens": 256,        # smaller to fit tight free budgets
        "temperature": 0.7,
        "system": "You are a helpful healthcare AI assistant. Provide accurate, helpful medical information while reminding users to consult healthcare professionals for medical advice.",
        "messages": [
            {"role": "user", "content": question}
        ]
    }
    
    # Retry mechanism with exponential backoff
    max_retries = 3
    retry_delay = 1
    
    for attempt in range(max_retries):
        try:
            # DNS check
            try:
                socket.gethostbyname('api.anthropic.com')
            except socket.gaierror as dns_error:
                logging.error(f"DNS resolution failed for api.anthropic.com: {dns_error}")
                return f"DNS resolution failed. Please check your internet connection or DNS settings. Error: {str(dns_error)}"
            
            response = requests.post(
                url,
                json=payload,
                headers=headers,
                timeout=30
            )

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
                # Translate common errors to clear app responses
                if response.status_code == 401:
                    return "Invalid Claude API key. Please check your API key."
                if response.status_code == 429:
                    return "Claude API rate limit exceeded. Please try again later."
                if response.status_code == 500:
                    return "Claude service is temporarily unavailable. Please try again later."
                if response.status_code == 400 and "credit balance is too low" in msg.lower():
                    # Keep it explicit so the UI can react
                    return ("Claude is unavailable for this account right now (insufficient credits). "
                            "Add credits in Anthropic Billing or pass a fallback_provider to continue.")
                logging.error(f"Claude 400 error: {err}")
                return f"Claude request was invalid. Details: {err}"
            
            response.raise_for_status()
            data = response.json()

            # Messages API returns list of content blocks
            if "content" in data and isinstance(data["content"], list) and data["content"]:
                for block in data["content"]:
                    if block.get("type") == "text" and "text" in block:
                        return block["text"]
                return " ".join([b.get("text", "") for b in data["content"] if isinstance(b, dict)]).strip() or "No response received from the Claude AI service."
            else:
                return "No response received from the Claude AI service."
                
        except requests.exceptions.ConnectionError as e:
            if "NameResolutionError" in str(e) or "getaddrinfo failed" in str(e):
                logging.error(f"DNS resolution error on attempt {attempt + 1}: {e}")
                if attempt < max_retries - 1:
                    time.sleep(retry_delay * (2 ** attempt))
                    continue
                return "DNS resolution failed. Please check your DNS settings or internet connection."
            else:
                logging.error(f"Connection error: {e}")
                return "Unable to connect to the Claude AI service. Please check your internet connection."
                
        except requests.exceptions.Timeout:
            logging.error(f"Request timeout on attempt {attempt + 1}")
            if attempt < max_retries - 1:
                time.sleep(retry_delay * (2 ** attempt))
                continue
            return "Request timeout. The Claude AI service is taking longer than expected to respond."
            
        except requests.exceptions.HTTPError as e:
            response = e.response
            if response and response.status_code == 429:
                return "Claude API rate limit exceeded. Please try again later."
            elif response and response.status_code == 401:
                return "Invalid Claude API key. Please check your API key."
            elif response and response.status_code == 500:
                return "Claude service is temporarily unavailable. Please try again later."
            else:
                logging.error(f"Claude HTTP error: {e}")
                return f"Claude AI service error: {str(e)}"
                
        except Exception as e:
            logging.error(f"Unexpected error in ask_claude: {e}")
            return "An unexpected error occurred while processing your request. Please try again later."
    
    return "Maximum retry attempts reached. Please try again later."

def ask_provider(question, api_key, provider="openai", model=None, fallback=None):
    """Unified function to handle all AI providers. Optional fallback keeps UX alive without changing defaults."""
    providers = {
        "openai": ask_openai,
        "gemini": ask_gemini,
        "mistral": ask_mistral,
        "claude": ask_claude,
    }
    if provider not in providers:
        raise ValueError(f"Unsupported provider: {provider}")

    primary = providers[provider](question, api_key, model)

    # If Claude is out of credits and a fallback is provided, try it
    if (provider == "claude"
        and isinstance(primary, str)
        and "insufficient credits" in primary.lower()
        and fallback in providers):
        fb_key = os.getenv(f"{fallback.upper()}_API_KEY")
        if not fb_key:
            # No env key? just return the primary message
            return primary
        try:
            return providers[fallback](question, fb_key, None)
        except Exception as _:
            return primary  # don't break existing behavior

    return primary

'''
myself means account holder email owner.
[{"abc@gmail.com":{myself:{firstName:'a',lastName:'b',dob:'1',race:'A',gender:'M',height:'5ft',weight:'55kg',a1c:'5',bloodPressure:'98',medicine:'paracetamol',tokens:45},member1:{},member2:{},member3:{}}},{}]
I also included token in this give obj.
'''
#<<<<<<<<<<<<<<<<<ADD FAMILY MEMBER>>>>>>>>>>>>>>>>>>>>
from fastapi import Depends

from fastapi import Body

@app.post("/medlife/addmember")
async def add_member(data: Data = Body(...)):
    email = data.email

    conn = get_db_connection()
    try:
        cursor = conn.execute("SELECT * FROM family_members WHERE email = ?", (email,))
        record = cursor.fetchone()

        if not record:
            conn.execute(
                """
                INSERT INTO family_members (
                    email,
                    member1_firstName, member1_lastName, member1_dob, member1_race, member1_gender,
                    member1_height, member1_weight, member1_a1c, member1_bloodPressure, member1_medicine, member1_tokens
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    email,
                    data.firstName, data.lastName, data.dob, data.race, data.gender,
                    data.height, data.weight, data.a1c, data.bloodPressure, data.medicine, data.tokens
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
                            member{i}_tokens = ?
                        WHERE email = ?
                        """,
                        (
                            data.firstName, data.lastName, data.dob, data.race, data.gender,
                            data.height, data.weight, data.a1c, data.bloodPressure, data.medicine, data.tokens,
                            email
                        )
                    )
                    conn.commit()
                    return {"message": f"member{i} added successfully"}
            raise HTTPException(status_code=400, detail="Maximum of 4 members allowed per user.")
    finally:
        conn.close()

#<<<<<<<<<<<<<<<<<edit FAMILY MEMBER>>>>>>>>>>>>>>>>>>>>

from fastapi import Body

@app.post("/medlife/editmember")
async def edit_member(member_index: int, data: Data = Body(...)):
    email = data.email
    conn = get_db_connection()
    try:
        cursor = conn.execute(
            "SELECT * FROM family_members WHERE email = ?", 
            (email,)
        )
        row = cursor.fetchone()
        
        if not row:
            raise HTTPException(status_code=404, detail="User not found")
        
        if member_index < 1 or member_index > 4:
            raise HTTPException(status_code=400, detail="Invalid member index")
        
        # Update the specific member with correct prefixed columns
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
                member{member_index}_tokens = ?
            WHERE email = ?
            """,
            (
                data.firstName,
                data.lastName,
                data.dob,
                data.race,
                data.gender,
                data.height,
                data.weight,
                data.a1c,
                data.bloodPressure,
                data.medicine,
                data.tokens,
                email
            )
        )
        conn.commit()
    finally:
        conn.close()
    return {"message": "Member updated successfully"}

#<<<<<<<<<<<<<<<<<GET FAMILY MEMBER>>>>>>>>>>>>>>>>>>>>
from fastapi import Depends

from fastapi import Query

@app.get("/medlife/getmember")
async def get_member(email: str = Query(...)):
    conn = get_db_connection()
    try:
        cursor = conn.execute(
            "SELECT * FROM family_members WHERE email = ?",
            (email,)
        )
        row = cursor.fetchone()
        if not row:
            return {"members": []}
        members = []
        for i in range(1, 5):
            prefix = f"member{i}_"
            if row[prefix + "firstName"]:
                member = {
                    "firstName": row[prefix + "firstName"],
                    "lastName": row[prefix + "lastName"],
                    "dob": row[prefix + "dob"],
                    "race": row[prefix + "race"],
                    "gender": row[prefix + "gender"],
                    "height": row[prefix + "height"],
                    "weight": row[prefix + "weight"],
                    "a1c": row[prefix + "a1c"],
                    "bloodPressure": row[prefix + "bloodPressure"],
                    "medicine": row[prefix + "medicine"],
                    "tokens": row[prefix + "tokens"] or 0
                }
                members.append(member)
    finally:
        conn.close()
    return {"members": members}

#<<<<<<<<<<<<<<<<<DELETE MEMBER ENDPOINT>>>>>>>>>>>>>>>>>>
class DeleteMemberRequest(BaseModel):
    email: str
    member_index: int  # 1-4 representing which member to delete

from fastapi import Query

@app.delete("/medlife/deletemember")
async def delete_member(email: str = Query(...), member_index: int = Query(...)):
    """
    Delete a specific family member from the database by member index (1-4)
    """
    conn = get_db_connection()
    try:
        cursor = conn.execute(
            "SELECT * FROM family_members WHERE email = ?", 
            (email,)
        )
        row = cursor.fetchone()
        
        if not row:
            raise HTTPException(status_code=404, detail="User not found")
        
        if member_index < 1 or member_index > 4:
            raise HTTPException(status_code=400, detail="Invalid member index. Must be between 1 and 4")
        
        # Check if the member exists
        prefix = f"member{member_index}_"
        if not row[prefix + "firstName"]:
            raise HTTPException(status_code=404, detail=f"Member {member_index} not found")
        
        # Shift members up after the deleted member
        for i in range(member_index, 4):
            next_prefix = f"member{i+1}_"
            current_prefix = f"member{i}_"
            conn.execute(
                f"""
                UPDATE family_members SET
                    {current_prefix}firstName = ?,
                    {current_prefix}lastName = ?,
                    {current_prefix}dob = ?,
                    {current_prefix}race = ?,
                    {current_prefix}gender = ?,
                    {current_prefix}height = ?,
                    {current_prefix}weight = ?,
                    {current_prefix}a1c = ?,
                    {current_prefix}bloodPressure = ?,
                    {current_prefix}medicine = ?,
                    {current_prefix}tokens = ?
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
                    row[next_prefix + "tokens"],
                    email
                )
            )
        
        # Clear the last member slot (member4)
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
                member4_tokens = 0
            WHERE email = ?
            """,
            (email,)
        )
        conn.commit()
        
        return {
            "message": f"Member {member_index} deleted successfully and members shifted",
            "deleted_member_index": member_index,
            "email": email
        }
        
    except sqlite3.Error as e:
        logging.error(f"Database error during member deletion: {e}")
        raise HTTPException(status_code=500, detail="Database error occurred")
    finally:
        conn.close()

#<<<<<<<<<<<<<<<<<PROMPT FOR SIDE BAR>>>>>>>>>>>>>>>>>>>

from typing import Optional

@app.get("/medlife/ask_ai/")
async def ask_ai(query: str, api_key: str, provider: str = "openai", email: Optional[str] = None, member_data: Optional[str] = None, fallback_provider: Optional[str] = None):
    prompt_text = f"Act as an Healthcare AI assistant, answer health questions based on patient data. "
    
    if member_data and member_data != "undefined":
        try:
            member = json.loads(member_data)
            prompt_text += f"\n\nPatient Details:\n"
            prompt_text += f"Name: {member.get('firstName', '')} {member.get('lastName', '')}\n"
            prompt_text += f"Date of Birth: {member.get('dob', '')}\n"
            prompt_text += f"Gender: {member.get('gender', '')}\n"
            prompt_text += f"Race: {member.get('race', '')}\n"
            prompt_text += f"Height: {member.get('height', '')}\n"
            prompt_text += f"Weight: {member.get('weight', '')}\n"
            prompt_text += f"A1C Level: {member.get('a1c', '')}\n"
            prompt_text += f"Blood Pressure: {member.get('bloodPressure', '')}\n"
            prompt_text += f"Current Medications: {member.get('medicine', '')}\n"
        except json.JSONDecodeError:
            pass
    
    prompt_text += f"\n\nQuestion: {query}"

    config = get_provider_config(provider)
    model = config["models"][0] if config and "models" in config else "gpt-3.5-turbo"
    
    try:
        final_answer = ask_provider(prompt_text, api_key, provider, model, fallback=fallback_provider)
        return final_answer
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

#<<<<<<<<<<<<<<<<<PROMPT FOR CHAT>>>>>>>>>>>>>>>>>>
@app.get("/medlife/prompt/")
async def prompt(query: str, api_key: str):
    if not api_key:
        raise HTTPException(status_code=400, detail="OpenAI API key is required")
    
    try:
        final_answer = ask_openai(f"Act as an Healthcare AI assistant, that means you can answer only health related question, given data contains patient details and patient's question, here it is :--- {query} ", api_key)
        return final_answer
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

#<<<<<<<<<<<<<<<<<ADD TOKEN>>>>>>>>>>>>>>>>>>
@app.get("/medlife/tokens/")
async def increment_tokens(email: str, member_name: str):
    conn = get_db_connection()
    try:
        cursor = conn.execute("SELECT * FROM family_members WHERE email = ?", (email,))
        row = cursor.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="User not found")
        # Find the member index by matching firstName and lastName
        member_index = None
        for i in range(1, 5):
            prefix = f"member{i}_"
            if row[prefix + "firstName"] == member_name:
                member_index = i
                break
        if member_index is None:
            raise HTTPException(status_code=404, detail="Member not found")
        current_tokens = row[f"member{member_index}_tokens"] or 0
        if current_tokens >= 100:
            raise HTTPException(status_code=400, detail="Question limit exceeded.")
        new_tokens = current_tokens + 1
        conn.execute(
            f"UPDATE family_members SET member{member_index}_tokens = ? WHERE email = ?",
            (new_tokens, email)
        )
        conn.commit()
        return {"message": str(new_tokens)}
    finally:
        conn.close()

#<<<<<<<<<<<<<<<<<GET TOKEN COUNT>>>>>>>>>>>>>>>>>>
@app.get("/medlife/tokensCount/")
async def get_token_count(email: str, member_name: str):
    conn = get_db_connection()
    try:
        cursor = conn.execute("SELECT * FROM family_members WHERE email = ?", (email,))
        row = cursor.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="User not found")
        member_index = None
        for i in range(1, 5):
            prefix = f"member{i}_"
            if row[prefix + "firstName"] == member_name:
                member_index = i
                break
        if member_index is None:
            raise HTTPException(status_code=404, detail="Member not found")
        tokens = row[f"member{member_index}_tokens"] or 0
        return {"message": str(tokens)}
    finally:
        conn.close()

@app.get("/api/member-details/{email}/{member_index}")
async def get_member_details(email: str, member_index: int):
    """
    Fetch complete details for a specific family member
    """
    if member_index < 1 or member_index > 4:
        raise HTTPException(status_code=400, detail="Invalid member index. Must be between 1 and 4")
    
    conn = get_db_connection()
    try:
        cursor = conn.execute(
            "SELECT * FROM family_members WHERE email = ?", 
            (email,)
        )
        row = cursor.fetchone()
        
        if not row:
            raise HTTPException(status_code=404, detail="User not found")
        
        prefix = f"member{member_index}_"
        if not row[prefix + "firstName"]:
            raise HTTPException(status_code=404, detail=f"Member {member_index} not found")
        
        member_details = {
            "memberIndex": member_index,
            "firstName": row[prefix + "firstName"],
            "lastName": row[prefix + "lastName"],
            "dob": row[prefix + "dob"],
            "race": row[prefix + "race"],
            "gender": row[prefix + "gender"],
            "height": row[prefix + "height"],
            "weight": row[prefix + "weight"],
            "a1c": row[prefix + "a1c"],
            "bloodPressure": row[prefix + "bloodPressure"],
            "medicine": row[prefix + "medicine"],
            "tokens": row[prefix + "tokens"] or 0,
            "fullName": f"{row[prefix + 'firstName']} {row[prefix + 'lastName']}"
        }
        
        return {"member": member_details}
        
    except sqlite3.Error as e:
        logging.error(f"Database error fetching member details: {e}")
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        conn.close()

#<<<<<<<<<<<<<<<<<<<<<<<<<<<<CHAT AREA>>>>>>>>>>>>>>>>>>>>>>>>>>>

import json
import os
from typing import List, Dict, Any

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CHAT_DATA_DIR = os.path.join(BASE_DIR, 'chat_data')

if not os.path.exists(CHAT_DATA_DIR):
    os.makedirs(CHAT_DATA_DIR)

def save_chat_data_to_file(email: str, member_name: str, chat_data: list):
    file_name = f"{email}_{member_name}.json"
    file_path = os.path.join(CHAT_DATA_DIR, file_name)

    with open(file_path, 'w') as file:
        json.dump(chat_data, file)

def load_chat_data_from_file(email: str, member_name: str):
    file_name = f"{email}_{member_name}.json"
    file_path = os.path.join(CHAT_DATA_DIR, file_name)

    if not os.path.exists(file_path):
        return []

    with open(file_path, 'r') as file:
        chat_data = json.load(file)
    
    return chat_data

#<<<<<<<<<<<<<<<<<FETCH CHAT DATA>>>>>>>>>>>>>>>>>>>>
@app.get("/medlife/fetchChat/")
async def fetch_chat(email: str, member_name: str):
    chat_data = load_chat_data_from_file(email, member_name)
    return {"chat": chat_data}

#<<<<<<<<<<<<<<<<<SAVE CHAT DATA>>>>>>>>>>>>>>>>>>>>
from fastapi import Request

@app.post("/medlife/saveChat/")
async def save_chat(email: str, member_name: str, request: Request):
    data = await request.json()
    chat = data.get("chat", [])
    # ... process the chat data

    save_chat_data_to_file(email, member_name, chat)
    return {"message": "Chat data saved successfully"}
                                                                                                                                    