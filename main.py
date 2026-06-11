

from fastapi import FastAPI

app = FastAPI()

@app.post("/")
def receive_trigger():
    return "hey"