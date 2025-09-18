import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from dotenv import load_dotenv

load_dotenv()

# Get the database URL from the environment variables
SQLALCHEMY_DATABASE_URL = os.getenv("DATABASE_URL")

# Check if the database URL is set
if not SQLALCHEMY_DATABASE_URL:
    raise ValueError("No DATABASE_URL found in environment variables")

# The connect_args are specific to SQLite and not needed for PostgreSQL
engine = create_engine(SQLALCHEMY_DATABASE_URL)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def get_db():

    db = SessionLocal()

    try:

        yield db

    finally:

        db.close()