from fastapi import FastAPI, Depends
from sqlalchemy.orm import Session

from .database import engine, get_db
from .models import Base, User


Base.metadata.create_all(bind=engine)


app = FastAPI(
    title="APICipher API",
    description="API used for security testing and risk assessment",
    version="1.0.0"
)


@app.get("/")
def home():
    return {
        "message": "APICipher API is running",
        "status": "online"
    }


@app.get("/health")
def health_check():
    return {
        "status": "healthy"
    }


@app.get("/users")
def get_users(db: Session = Depends(get_db)):
    users = db.query(User).all()

    return users