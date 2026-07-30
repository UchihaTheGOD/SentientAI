from fastapi import FastAPI
from pydantic import BaseModel,EmailStr,conint



app = FastAPI()

class User(BaseModel):
    name:str
    mail:EmailStr
    age:conint(ge=10)



@app.post("/register/")
async def reg_user(user:User):
    return user