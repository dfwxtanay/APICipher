from fastapi import FastAPI

app = FastAPI(
    title="APICipher API",
    description="API used for security testing and risk assessment",
    version="1.0.0"
)


@app.get("/")
def home():
    return {
        "message": "APICipher API is running",
        "status": "online"
    }


@app.get("/health")
def health_check():
    return {
        "status": "healthy"
    }