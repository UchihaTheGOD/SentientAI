from fastapi import FastAPI

app = FastAPI()

items = []

@app.get('/hello')

def helloworld():
    return {'message' :'hello world!'}

@app.post('/items')
def create_items(item: str):
    items.append(item)
    return items

@app.get('/items/{item_id}')
def get_item(item_id: int):
    item = items[item_id]
    return item

@app.put('/items/{id}')
def update(id: int, item:str):
    return {"item": id, "item":item}