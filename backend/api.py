from fastapi import FastAPI
from pydantic import BaseModel, Field, field_validator

app= FastAPI()

class User(BaseModel):
    name:str
    age:int = Field(...,gt=0,le=120)

    @field_validator('name')
    def name_not_empty(cls,v):
        if not v:
            raise ValueError("NOPE U CAN't do that")
        return v


@app.post("/user/")

async def create_user(user:User):
    u={"name":user.name,"age":user.age}
    return u