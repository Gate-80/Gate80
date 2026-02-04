from fastapi import FastAPI

app = FastAPI()

@app.get("/")
def root():
    return {"status": "backend running"}

@app.get("/hello")
def hello():
    return {"message": "Hello from RASD"}
