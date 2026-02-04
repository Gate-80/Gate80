from fastapi import FastAPI

app = FastAPI()

@app.get("/health")
def health_check():
    return {"status": "ok"}

@app.get("/hello")
def hello():
    return {"message": "Hello from RASD"}

