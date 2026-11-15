from fastapi import FastAPI, Depends, HTTPException
from fastapi.responses import PlainTextResponse
from sqlalchemy import create_engine, Column, Integer, String, Boolean
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from pydantic import BaseModel
import os
import secrets

DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL not set")
if DATABASE_URL.startswith("postgresql://"):
    DATABASE_URL = DATABASE_URL.replace("postgresql://", "postgresql+psycopg://", 1)

engine = create_engine(DATABASE_URL, pool_pre_ping=True)
SessionLocal = sessionmaker(bind=engine)
Base = declarative_base()

app = FastAPI()

class Key(Base):
    __tablename__ = "keys"
    id = Column(Integer, primary_key=True)
    key_value = Column(String(64), unique=True, nullable=False)
    banned = Column(Boolean, default=False)

Base.metadata.create_all(bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

@app.get("/validate", response_class=PlainTextResponse)
def validate(key: str, db=Depends(get_db)):
    k = db.query(Key).filter(Key.key_value == key, Key.banned == False).first()
    return "valid" if k else "invalid"

class KeyCreate(BaseModel):
    amount: int = 1

@app.post("/gen")
def gen(data: KeyCreate, db=Depends(get_db)):
    keys = []
    for _ in range(data.amount):
        k = Key(key_value=secrets.token_hex(32))
        db.add(k)
        keys.append(k.key_value)
    db.commit()
    return {"keys": keys}

@app.get("/")
def root():
    return {"status": "ok", "endpoints": ["/validate?key=...", "/gen"]}
