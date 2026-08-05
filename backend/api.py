from sqlalchemy import create_engine, Column, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm import Session
from fastapi import FastAPI, Depends 
from pydantic import BaseModel

app=FastAPI()

DATABASE_URL= "sqlite:///./test.db"

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})

SessionLocal = sessionmaker(autocommit=False, autoflush=False,bind=engine)

Base = declarative_base()

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    name= Column(String, index=True)
    email= Column(String, unique=True, index=True)

Base.metadata.create_all(bind=engine)
#DATABASE SESSION
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# @app.post("/users/", response_model=User)
# def create_user(user:UserCreate,db:Session=Depends(get_db))
#pydantic 
class UserCreate(BaseModel):
    name: str
    email: str

#api
@app.post("/users/", response_model=User)
def create_user(user: UserCreate, db: Session= Depends(get_db)):
    db_user = User(name=user.name, email=user.email)
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user
