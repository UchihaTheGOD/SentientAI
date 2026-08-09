from sqlalchemy import Column, Integer, String
from database import Base
from database import engine
#class name User gonna use in TEST.db
class User(Base):
#table name "users"
    __tablename__ = "users"
    #what gonna be saved in that table
    id= Column(Integer, primary_key=True, index=True)
    username= Column(String, unique= True, index=True)
    hashed_password = Column(String)


#create table if not 
User.metadata.create_all(bind=engine)
