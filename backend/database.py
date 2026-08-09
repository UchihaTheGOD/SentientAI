from sqlalchemy import create_engine, Column, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

#for database url
SQLALCHEMY_DATABASE_URL ="sqlite://./test.db"

#connectin to db
#" SQLALCHEMY_DATABASE_URL,connect_args=("check_same_thread":False)" this help to connect fastapi with multi thread

engine =create_engine(
    SQLALCHEMY_DATABASE_URL,connect_args={"check_same_thread":False}
)
#use for saving the connection session
SessionLocal = sessionmaker(autocommit=False, autoflush=False,bind=engine)

Base = declarative_base()
