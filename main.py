import os
import json
from dotenv import load_dotenv

load_dotenv()

GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")
JWT_SECRET = os.getenv("JWT_SECRET")
SENDGRID_API_KEY = os.getenv("SENDGRID_API_KEY")
SENDGRID_FROM_EMAIL = os.getenv("SENDGRID_FROM_EMAIL")

from fastapi import FastAPI, Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.staticfiles import StaticFiles
from sqlalchemy.orm import Session
from jose import JWTError, jwt
from passlib.context import CryptContext
from datetime import datetime, timedelta
from typing import Optional
import sendgrid
from sendgrid.helpers.mail import Mail
from authlib.integrations.starlette_client import OAuth
from starlette.middleware.sessions import SessionMiddleware
from starlette.config import Config
from starlette.responses import RedirectResponse
import uvicorn

from database import SessionLocal, engine
from typing import List
from models import Base, User as DBUser
from schemas import EmailRequest, User as UserSchema, UserUpdate, AdminUserCreate, AdminUserUpdate, UserPasswordUpdate

app = FastAPI()

from fastapi.middleware.cors import CORSMiddleware

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.add_middleware(
    SessionMiddleware,
    secret_key=JWT_SECRET
)

Base.metadata.create_all(bind=engine)

# Security
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# OAuth config for Google
config = Config('.env')
oauth = OAuth(config)

if GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET:
    oauth.register(
        name='google',
        client_id=GOOGLE_CLIENT_ID,
        client_secret=GOOGLE_CLIENT_SECRET,
        server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
        client_kwargs={
            'scope': 'openid email profile',
            'redirect_uri': 'http://localhost:8000/auth/google/callback'
        },
    )
else:
    print("Warning: Google OAuth not configured.")

# DB dependency
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Password utils
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

# User utils
def get_user(db: Session, username: str):
    return db.query(DBUser).filter(DBUser.username == username).first()

def get_user_by_email(db: Session, email: str):
    return db.query(DBUser).filter(DBUser.email == email).first()

def authenticate_user(db: Session, username: str, password: str):
    user = get_user(db, username)
    if not user:
        return False
    if not verify_password(password, user.hashed_password):
        return False
    return user

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, JWT_SECRET, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    user = get_user(db, username=username)
    if user is None:
        raise credentials_exception
    return user

def get_current_admin_user(current_user: DBUser = Depends(get_current_user)):
    if current_user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="The user does not have administrative privileges"
        )
    return current_user

# --- Admin User Management Endpoints ---

@app.get("/admin/users", response_model=List[UserSchema])
def get_all_users(db: Session = Depends(get_db), admin: DBUser = Depends(get_current_admin_user)):
    return db.query(DBUser).all()

@app.post("/admin/users", response_model=UserSchema, status_code=status.HTTP_201_CREATED)
def create_user(user_create: AdminUserCreate, db: Session = Depends(get_db), admin: DBUser = Depends(get_current_admin_user)):
    # Check for conflicts
    if get_user(db, user_create.username):
        raise HTTPException(status_code=400, detail="Username already registered")
    if get_user_by_email(db, user_create.email):
        raise HTTPException(status_code=400, detail="Email already registered")
        
    hashed_password = get_password_hash(user_create.password)
    new_user = DBUser(
        username=user_create.username,
        email=user_create.email,
        hashed_password=hashed_password,
        role=user_create.role
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return new_user

@app.put("/admin/users/{user_id}", response_model=UserSchema)
def update_user(user_id: int, user_update: AdminUserUpdate, db: Session = Depends(get_db), admin: DBUser = Depends(get_current_admin_user)):
    user_to_update = db.query(DBUser).filter(DBUser.id == user_id).first()
    if not user_to_update:
        raise HTTPException(status_code=404, detail="User not found")

    if user_update.username:
        user_to_update.username = user_update.username
    if user_update.email:
        user_to_update.email = user_update.email
    if user_update.role:
        user_to_update.role = user_update.role

    db.commit()
    db.refresh(user_to_update)
    return user_to_update

@app.delete("/admin/users/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_user(user_id: int, db: Session = Depends(get_db), admin: DBUser = Depends(get_current_admin_user)):
    user_to_delete = db.query(DBUser).filter(DBUser.id == user_id).first()
    if not user_to_delete:
        raise HTTPException(status_code=404, detail="User not found")
    
    db.delete(user_to_delete)
    db.commit()


# Endpoints
@app.post("/token")
async def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/auth/google")
async def google_login(request: Request):
    if not GOOGLE_CLIENT_ID or not GOOGLE_CLIENT_SECRET:
        raise HTTPException(status_code=500, detail="Google Oauth not configured.")
    redirect_uri = "http://localhost:8000/auth/google/callback"
    return await oauth.google.authorize_redirect(request, redirect_uri)

@app.get("/auth/google/callback")
async def google_callback(request: Request, db: Session = Depends(get_db)):
    if not GOOGLE_CLIENT_ID or not GOOGLE_CLIENT_SECRET:
        raise HTTPException(status_code=500, detail="Google OAuth not configured.")
    
    try:
        token = await oauth.google.authorize_access_token(request)
        user_info_response = await oauth.google.get('https://www.googleapis.com/oauth2/v3/userinfo', token=token)
        user_info = user_info_response.json()
        
        if user_info and 'email' in user_info:
            email = user_info['email']
            db_user = get_user_by_email(db, email)

            if not db_user:
                return RedirectResponse(url="http://localhost:8000/?contact_admin=1", status_code=302)
            else:
                access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
                access_token = create_access_token(data={"sub": db_user.username}, expires_delta=access_token_expires)
                return RedirectResponse(url=f"http://localhost:8000/?token={access_token}", status_code=302)
        else:
            raise HTTPException(status_code=400, detail="Google login failed: Could not retrieve email.")
            
    except Exception as e:
        # For security, log the actual error to the console but return a generic message to the user.
        print(f"An error occurred during Google authentication: {e}")
        raise HTTPException(status_code=500, detail="An internal error occurred during Google authentication.")

@app.get("/users/me", response_model=UserSchema)
async def read_users_me(current_user: DBUser = Depends(get_current_user)):
    return current_user

@app.put("/users/me/update", response_model=UserSchema)
async def update_user_me(
    user_update: UserUpdate,
    db: Session = Depends(get_db),
    current_user: DBUser = Depends(get_current_user)
):
    # Check for username conflicts
    if user_update.username and user_update.username != current_user.username:
        existing_user = get_user(db, user_update.username)
        if existing_user:
            raise HTTPException(status_code=400, detail="Username already registered")
        current_user.username = user_update.username

    # Check for email conflicts
    if user_update.email and user_update.email != current_user.email:
        existing_user = get_user_by_email(db, user_update.email)
        if existing_user:
            raise HTTPException(status_code=400, detail="Email already registered")
        current_user.email = user_update.email
    
    db.commit()
    db.refresh(current_user)
    return current_user

@app.put("/users/me/change-password")
async def change_password(
    password_update: UserPasswordUpdate,
    db: Session = Depends(get_db),
    current_user: DBUser = Depends(get_current_user)
):
    # Verify the current password
    if not verify_password(password_update.current_password, current_user.hashed_password):
        raise HTTPException(status_code=400, detail="Incorrect current password")

    # Hash the new password and update the user
    current_user.hashed_password = get_password_hash(password_update.new_password)
    db.commit()

    return {"message": "Password updated successfully"}

@app.post("/api/send-email")
async def send_email(email_request: EmailRequest, current_user: DBUser = Depends(get_current_user)):
    if not SENDGRID_API_KEY:
        raise HTTPException(status_code=500, detail="SendGrid not configured")
    try:
        sg = sendgrid.SendGridAPIClient(api_key=SENDGRID_API_KEY)
        message = Mail(
            from_email=email_request.from_email or SENDGRID_FROM_EMAIL,
            to_emails=email_request.to_email,
            subject=email_request.subject,
            plain_text_content=email_request.body
        )
        response = sg.send(message)
        return {"status": "success", "message": "Email sent"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# Serve frontend
app.mount("/", StaticFiles(directory=".", html=True), name="static")

if __name__ == "__main__":
    uvicorn.run(app, host="localhost", port=8000)