import os
import time
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base

# Use sqlite by default if DATABASE_URL is not set
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./jass.db")

if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

engine = create_engine(
    DATABASE_URL, 
    connect_args={"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

def init_db():
    max_retries = 5
    for i in range(max_retries):
        try:
            Base.metadata.create_all(bind=engine)
            break
        except Exception as e:
            if i < max_retries - 1:
                print(f"Database connection failed. Retrying in 3 seconds... ({e})")
                time.sleep(3)
            else:
                raise

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
