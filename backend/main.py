#bro why we importing this many shit
from fastapi import FastAPI, Depends, HTTPException, status
from sqlalchemy.orm import Session
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from datetime import datetime, timedelta, timezone
from passlib.context import CryptContext
from models import User
from database import SessionLocal, engine
from pydantic import BaseModel
from fastapi.middleware.cors import CORSMiddleware

app=FastAPI()
#indetify where JWT and only who have valid token
oauth_scheme = OAuth2PasswordBearer(tokenUrl="token")

origin = [
    "http://localhost:3000"
    #"prod"
]
#allowing origin all request 
app.add_middleware(
    CORSMiddleware,
    allow_origins=origin,
    allow_credentials=True,
    allow_methods=["*"], #allow all method
    allow_headers=["*"],#allow all header
)
#creating session and cloe to reduse the cpu  
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
#use for hashing
pwd_context = CryptContext(schemes=["bcrypt"],deprecated="auto")

#JWT AND ALGO 

SECRET_KEY ="KEY"
#ALGORITHM to use
ALGORITHM = "HS256"
#valid for what time
ACCESS_TOKEN_EXPIRE_MINUTES = 60
#class to take user and pass
class UserCreate(BaseModel):
    username: str
    password: str
#creat new user via username
def get_user_by_username(db:Session, username: str):
    return db.query(User).filter(User.username == username).first()
#create user
def create_user(db: Session, user:UserCreate):
    hashed_password = pwd_context.hash(user.password)
    db_user = User(username=user.username,hashed_password=hashed_password)
    db.add(db_user)
    db.commit()
    return "complete OK"
#Fastapi to register and check if user exist or not
@app.post("/register/")
def register_user(user: UserCreate, db: Session = Depends(get_db)):
    db_user = get_user_by_username(db, username=user.username)
    #this to check if user exist or not
    if db_user:
        raise HTTPException(status_code=400, detail="Username already register")
    return create_user(db=db, user=user)

#auth the user and  check the if legit or not
#check if the user is verify or not
def authenticate_user (username: str, password: str, db: Session):
    user = db.query(User).filter(User.username == username).first()
    if not user:
        return False
    if not pwd_context.verify(password, user.hashed_password):
        return False
    return user
#create access token
def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    #For validity of token
    if expires_delta:
        expire = datetime.now(timezone.utc)+expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=15)
    to_encode.update({"exp":expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt
#TOKEN
@app.post("/token")
def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends(),db: Session = Depends(get_db)):
    user = authenticate_user(form_data.username, form_data.password, db)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="INCORRECT USERNAME AND PASSWORD",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return{"access_token":access_token,"token_type":"bearer"}
def verify_token(token: str = Depends(oauth_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=403,detail="Token is invalid or expired")
        return payload
    except JWTError:
        raise HTTPException(status_code=403, detail="Token is invalid or expired")

#Used to check if token is valid or not
@app.get("/verify-token/{token}")
async def verify_user_token(token: str):
    verify_token(token=token)
    return {"message": "Token is valid"}


