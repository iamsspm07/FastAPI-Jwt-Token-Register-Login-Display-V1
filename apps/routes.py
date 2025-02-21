import logging
from datetime import timedelta
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from sqlalchemy.exc import SQLAlchemyError
from typing import List, Optional
from database import get_db
from models import UserRegistration as User  # Corrected model import
from schemas import (
    UserRegistrationRequest,
    UserLoginRequest,
    TokenResponse,
    UserDeleteRequest,
    UserResponse,
    UserResponseRegister
)
from crud import (
    create_user,
    authenticate_user,
    delete_user_by_phone,
    get_all_users
)
from utils import create_access_token
from config import settings
from jose import JWTError, jwt
from fastapi.security import OAuth2PasswordBearer

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

# Set up API router
router = APIRouter()

# JWT authentication setup
SECRET_KEY = settings.SECRET_KEY
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = settings.ACCESS_TOKEN_EXPIRE_MINUTES
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")  # Fixed tokenUrl


def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    """
    Validates the JWT token and retrieves the current user.
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid authentication credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: Optional[str] = payload.get("sub")

        if not email:
            raise credentials_exception

        user = db.query(User).filter(User.user_mail == email).first()
        if not user:
            raise credentials_exception
        return user

    except JWTError:
        raise credentials_exception


@router.post("/register/", response_model=dict)
def register_user(user_data: UserRegistrationRequest, db: Session = Depends(get_db)):
    """
    Register a new user.
    """
    try:
        user_id = create_user(db, user_data)
        if not user_id:
            raise HTTPException(status_code=400, detail="Invalid role or profession.")
        
        logging.info(f"✅ User registered successfully: {user_data.email}")
        return {"message": "User registered successfully!", "user_id": user_id}

    except SQLAlchemyError as e:
        logging.error(f"❌ Database error during registration: {str(e)}")
        raise HTTPException(status_code=500, detail="Internal Server Error.")
    
    except Exception as e:
        logging.error(f"❌ Unexpected error: {str(e)}")
        raise HTTPException(status_code=500, detail="An unexpected error occurred.")


@router.post("/login/", response_model=TokenResponse)
def login(user_data: UserLoginRequest, db: Session = Depends(get_db)):
    """
    Authenticate user and return JWT token.
    """
    try:
        user = authenticate_user(db, user_data.email, user_data.password)
        if not user:
            logging.warning(f"⚠ Login failed: Invalid credentials for {user_data.email}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid credentials",
                headers={"WWW-Authenticate": "Bearer"},
            )
        
        access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = create_access_token(data={"sub": user.user_mail}, expires_delta=access_token_expires)

        logging.info(f"✅ User logged in successfully: {user_data.email}")
        return {"access_token": access_token, "token_type": "bearer"}

    except SQLAlchemyError as e:
        logging.error(f"❌ Database error during login: {str(e)}")
        raise HTTPException(status_code=500, detail="Internal Server Error.")
    
    except Exception as e:
        logging.error(f"❌ Unexpected error: {str(e)}")
        raise HTTPException(status_code=500, detail="An unexpected error occurred.")


@router.delete("/delete/", response_model=dict)
def delete_user(user_data: UserDeleteRequest, db: Session = Depends(get_db), current_user=Depends(get_current_user)):
    """
    Delete a user by phone number (requires authentication).
    """
    try:
        phone_number = user_data.phone
        success = delete_user_by_phone(db, phone_number)

        if not success:
            logging.warning(f"⚠ User deletion failed: No user found for phone {phone_number}")
            raise HTTPException(status_code=404, detail="User not found")

        logging.info(f"✅ User deleted successfully: {phone_number}")
        return {"message": "User deleted successfully!"}

    except Exception as e:
        logging.error(f"❌ Unexpected error: {str(e)}")
        raise HTTPException(status_code=500, detail="An unexpected error occurred.")


@router.get("/usersmaster/", response_model=List[UserResponse])
def get_all_registered_users(db: Session = Depends(get_db), current_user=Depends(get_current_user)):
    """
    Fetch all users (requires authentication).
    """
    try:
        users = get_all_users(db)
        return [
            UserResponse(
                id=user.id,
                username=user.username,
                email=user.user_mail,
                phone=user.user_number,
                role=user.role.role_name if user.role else "Unknown",
                profession=user.profession.profession_name if user.profession else None,
                country=user.country,
                city=user.city,
                registration_date=user.registration_date,
                deregister_date=user.deregister_date if user.deregister_date else None
            )
            for user in users
        ]
    except Exception as e:
        logging.error(f"❌ Error fetching users: {str(e)}")
        raise HTTPException(status_code=500, detail="An error occurred while fetching users.")


@router.get("/usersregistered/", response_model=List[UserResponseRegister])
def get_active_users(db: Session = Depends(get_db), current_user=Depends(get_current_user)):
    """
    Fetch registered users without deregistered ones (requires authentication).
    """
    try:
        users = get_all_users(db)
        return [
            UserResponseRegister(
                id=user.id,
                username=user.username,
                email=user.user_mail,
                phone=user.user_number,
                role=user.role.role_name if user.role else "Unknown",
                profession=user.profession.profession_name if user.profession else None,
                country=user.country,
                city=user.city,
                registration_date=user.registration_date
            )
            for user in users if not user.deregister_date  # Exclude deregistered users
        ]
    except Exception as e:
        logging.error(f"❌ Error fetching registered users: {str(e)}")
        raise HTTPException(status_code=500, detail="An error occurred while fetching users.")
