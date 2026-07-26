from fastapi import FastAPI

app = FastAPI()

@app.get('/hello')

def helloworld():
    return {'message' :'hello world!'}