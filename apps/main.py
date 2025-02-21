import logging
from fastapi import FastAPI, Request, HTTPException
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from starlette.responses import JSONResponse
from routes import router

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

# Initialize FastAPI app
app = FastAPI(
    title="Iamsspm07",
    description="A production-ready FastAPI app with MySQL, authentication, and deployment setup",
    version="1.0.0"
)

# CORS Middleware - Restrict in production
ALLOWED_ORIGINS = ["http://localhost:3000", "https://yourfrontend.com"]  # Update for production

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["*"],
)

# Log API Startup
@app.on_event("startup")
async def startup_event():
    logging.info("🚀 Iamsspm07 API is starting...")

# Global Exception Handler for HTTP Errors
@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    logging.error(f"❌ HTTP Exception: {exc.detail} - {request.url}")
    return JSONResponse(status_code=exc.status_code, content={"error": exc.detail})

# Global Exception Handler for Validation Errors
@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    logging.error(f"⚠️ Validation Error: {exc.errors()} - {request.url}")
    return JSONResponse(status_code=422, content={"error": "Invalid request data", "details": exc.errors()})

# Global Exception Handler for Unexpected Errors
@app.exception_handler(Exception)
async def generic_exception_handler(request: Request, exc: Exception):
    logging.critical(f"🔥 Server Error: {str(exc)} - {request.url}")
    return JSONResponse(status_code=500, content={"error": "Internal server error. Please try again later."})

# Root Endpoint (Health Check)
@app.get("/")
async def health_check():
    return {"message": "✅ Iamsspm07 is running!"}

# Include Routes
app.include_router(router)

# Graceful Shutdown Hook
@app.on_event("shutdown")
async def shutdown_event():
    logging.info("🛑 Iamsspm07 is shutting down...")
