from pydantic import BaseModel, EmailStr
from datetime import datetime
from typing import Optional
from passlib.context import CryptContext

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# User schemas for authentication
class UserBase(BaseModel):
    username: str
    email: EmailStr
    role: str = "user"

class UserCreate(UserBase):
    password: str

# Schema for admins creating a user (can set role)
class AdminUserCreate(UserCreate):
    role: str = "user"

# Schema for admins updating a user (can change anything)
class AdminUserUpdate(BaseModel):
    username: Optional[str] = None
    email: Optional[EmailStr] = None
    role: Optional[str] = None

class User(UserBase):
    id: int
    created_at: datetime
    updated_at: Optional[datetime]

    class Config:
        from_attributes = True

class UserUpdate(BaseModel):
    username: Optional[str] = None
    email: Optional[EmailStr] = None

class UserPasswordUpdate(BaseModel):
    current_password: str
    new_password: str

class UserInDB(User):
    hashed_password: str

class Login(BaseModel):
    username: str
    password: str

class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"

# --- Email Request Schema (updated) ---
class EmailRequest(BaseModel):
    from_email: Optional[EmailStr] = None
    to_email: EmailStr
    subject: str
    body: str