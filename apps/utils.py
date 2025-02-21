import re
import bcrypt
import logging
from datetime import datetime, timedelta
from jose import jwt, JWTError
from fastapi import HTTPException, Depends
from fastapi.security import OAuth2PasswordBearer
from config import settings  # Import settings from a secure config file

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

# Securely fetch secret key and algorithm
SECRET_KEY = settings.SECRET_KEY  # Ensure SECRET_KEY is stored securely in config
ALGORITHM = "HS256"
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


def hash_password(password: str) -> str:
    """Hashes the given password securely using bcrypt."""
    try:
        return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
    except Exception as e:
        logging.error(f"❌ Error hashing password: {e}")
        raise HTTPException(status_code=500, detail="Internal server error while hashing password.")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verifies a password against its hashed version."""
    try:
        return bcrypt.checkpw(plain_password.encode("utf-8"), hashed_password.encode("utf-8"))
    except Exception as e:
        logging.error(f"❌ Error verifying password: {e}")
        raise HTTPException(status_code=500, detail="Internal server error while verifying password.")


def validate_password(password: str):
    """
    Validates password complexity.
    - Must be at least 8 characters.
    - Must include letters, numbers, and a special character.
    """
    pattern = r"^(?=.*[A-Za-z])(?=.*\d)(?=.*[@$!%*#?&])[A-Za-z\d@$!%*#?&]{8,}$"
    if not re.fullmatch(pattern, password):
        raise HTTPException(
            status_code=400,
            detail="Password must be at least 8 characters long and include letters, numbers, and a special symbol."
        )


def validate_email(email: str):
    """Validates email format using regex."""
    pattern = r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$"
    if not re.fullmatch(pattern, email):
        raise HTTPException(status_code=400, detail="Invalid email format.")


def validate_phone(phone: str):
    """Validates phone number format (10 digits, starting with 6-9)."""
    pattern = r"^[6-9]\d{9}$"
    if not re.fullmatch(pattern, phone):
        raise HTTPException(status_code=400, detail="Invalid phone number format. Must be a 10-digit number starting with 6-9.")


def create_access_token(data: dict, expires_delta: timedelta = timedelta(minutes=15)) -> str:
    """
    Generates a JWT access token.
    - Default expiration: 15 minutes.
    - Encodes user data securely.
    """
    try:
        to_encode = data.copy()
        expire = datetime.utcnow() + expires_delta
        to_encode.update({"exp": expire})
        return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    except JWTError as e:
        logging.error(f"❌ JWT Encoding Error: {e}")
        raise HTTPException(status_code=500, detail="Error generating access token.")
    except Exception as e:
        logging.error(f"❌ Unexpected Error Generating Token: {e}")
        raise HTTPException(status_code=500, detail="Internal server error while generating access token.")


def verify_token(token: str = Depends(oauth2_scheme)) -> dict:
    """
    Verifies and decodes a JWT access token.
    - Raises 401 if invalid/expired.
    """
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except JWTError:
        logging.warning("⚠ Invalid or expired token.")
        raise HTTPException(status_code=401, detail="Invalid or expired token.")
    except Exception as e:
        logging.error(f"❌ Unexpected Error Verifying Token: {e}")
        raise HTTPException(status_code=500, detail="Internal server error while verifying token.")
