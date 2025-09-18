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

class User(UserBase):
    id: int
    created_at: datetime
    updated_at: Optional[datetime]

    class Config:
        from_attributes = True

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