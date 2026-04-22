from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base

import os
from sqlalchemy import create_engine

# This finds the directory where database.py lives
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

db_path = os.path.join(BASE_DIR, "../..", "vault.db")

DATABASE_URL = f"sqlite:///{db_path}"
engine = create_engine(DATABASE_URL, echo=True)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

def get_session():
    return SessionLocal()