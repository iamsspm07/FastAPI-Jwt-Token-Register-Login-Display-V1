import logging
from pydantic import BaseModel, EmailStr, Field
from typing import Optional, Annotated
from datetime import datetime

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

# User Registration Request Schema
class UserRegistrationRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=50, description="Username must be between 3 and 50 characters.")
    email: EmailStr
    password: Annotated[str, Field(min_length=8, description="Password must be at least 8 characters long.")]
    phone: Annotated[str, Field(pattern=r"^[6-9]\d{9}$", description="Phone number must be a valid 10-digit Indian mobile number.")]
    role: str = Field(..., description="User role is required.")
    profession: str = Field(..., description="User profession is required.")
    country: str
    city: str

# User Response Schema (Used for returning user data)
class UserResponse(BaseModel):
    id: int
    username: str
    email: EmailStr
    phone: str
    role: str
    profession: Optional[str] = None
    country: str
    city: str
    registration_date: datetime
    deregister_date: Optional[datetime] = None

# User Login Schema
class UserLoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=8, description="Password must be at least 8 characters long.")

# Token Response Schema
class TokenResponse(BaseModel):
    access_token: str
    token_type: str

# User Deletion Schema
class UserDeleteRequest(BaseModel):
    phone: Annotated[str, Field(pattern=r"^[6-9]\d{9}$", description="Phone number must be a valid 10-digit Indian mobile number.")]


# User Response Schema (Used for returning user data)
class UserResponseRegister(BaseModel):
    id: int
    username: str
    email: EmailStr
    phone: str
    role: str
    profession: Optional[str] = None
    country: str
    city: str
    registration_date: datetime
