from fastapi import FastAPI

app= FastAPI()

@app.get('/user/{id}/info')
def info(id:int, email:bool=False):
    if email:
        return{'id':id,'email':"u not cooked"}
    else:
        return{'id':id,'email':"nope u cooked"}