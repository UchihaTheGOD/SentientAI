from fastapi import FastAPI, Form, UploadFile, File
from typing import List
app = FastAPI()

# @app.post("/form/")
# async def FORM_DATA(name:str=Form(...),age:int=Form(...)):
#     return {"name": name,"message": "login OK"}

# @app.post("/file/")
# async def file(file: UploadFile = File(...)):
#     return {"filename": file.filename}


# @app.post("/savefile/")
# async def save(file: UploadFile = File(...)):
#     with open(f'uploads/{file.filename}',"wb") as f:
#         f.write(file.file.read())
#     return {"message":"FILE UPLOADED"}


@app.post("/multifile/")
async def multi_file(files: List[UploadFile]=File(...)):
    return {"filename": [file.filename for file in files]}