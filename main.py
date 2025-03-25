import jwt
import datetime
import time
from fastapi import FastAPI, HTTPException, Depends, status, Request
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, validator, Field
from typing import Optional
import re

# Initialize FastAPI app
app = FastAPI(title="Secure API Lab")

# Security configuration
SECRET_KEY = "your_super_secret_key_change_in_production"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

# CORS setup to restrict cross-origin requests
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:8080"],  # Restrict to specific origins
    allow_credentials=True,
    allow_methods=["GET", "POST"],  # Restrict HTTP methods
    allow_headers=["*"],
)

# OAuth2 scheme for token authentication
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Mock user database (In a real app, use a proper database)
fake_users_db = {
    "testuser": {
        "username": "testuser",
        "password": "password123",
        "email": "testuser@example.com",
        "full_name": "Test User"
    }
}

# Rate limiting configuration
RATE_LIMIT_DURATION = 60  # seconds
RATE_LIMIT_REQUESTS = 10  # requests per duration
rate_limit_data = {}

# Models with validation
class User(BaseModel):
    username: str
    email: Optional[str] = None
    full_name: Optional[str] = None
    
    @validator('username')
    def username_alphanumeric(cls, v):
        if not re.match(r'^[a-zA-Z0-9_]+$', v):
            raise ValueError('Username must be alphanumeric')
        return v

class Token(BaseModel):
    access_token: str
    token_type: str

class LoginData(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    password: str = Field(..., min_length=8)
    
    @validator('username')
    def username_alphanumeric(cls, v):
        if not re.match(r'^[a-zA-Z0-9_]+$', v):
            raise ValueError('Username must be alphanumeric')
        return v

# Rate limiting middleware
@app.middleware("http")
async def rate_limit_middleware(request: Request, call_next):
    # Get client IP
    client_ip = request.client.host
    
    # Check if IP is in rate limit data
    current_time = time.time()
    if client_ip in rate_limit_data:
        # Clean up old request timestamps
        rate_limit_data[client_ip] = [
            timestamp for timestamp in rate_limit_data[client_ip]
            if current_time - timestamp < RATE_LIMIT_DURATION
        ]
        
        # Check if rate limit is exceeded
        if len(rate_limit_data[client_ip]) >= RATE_LIMIT_REQUESTS:
            return JSONResponse(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                content={"detail": "Rate limit exceeded. Try again later."}
            )
        
        # Add current request timestamp
        rate_limit_data[client_ip].append(current_time)
    else:
        # First request from this IP
        rate_limit_data[client_ip] = [current_time]
    
    # Process the request
    response = await call_next(request)
    return response

# Helper Functions
def verify_password(plain_password, username):
    # In a real app, use password hashing (bcrypt, etc.)
    return plain_password == fake_users_db[username]["password"]

def get_user(username):
    if username in fake_users_db:
        user_dict = fake_users_db[username]
        return User(**user_dict)
    return None

def authenticate_user(username, password):
    user = get_user(username)
    if not user:
        return False
    if not verify_password(password, username):
        return False
    return user

def create_access_token(data: dict, expires_delta: datetime.timedelta = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.datetime.utcnow() + expires_delta
    else:
        expire = datetime.datetime.utcnow() + datetime.timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except jwt.PyJWTError:
        raise credentials_exception
    user = get_user(username)
    if user is None:
        raise credentials_exception
    return user

# Routes
@app.get("/")
def home():
    return {"message": "Welcome to the Secure API"}

@app.post("/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = datetime.timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/users/me", response_model=User)
async def read_users_me(current_user: User = Depends(get_current_user)):
    return current_user

@app.get("/secure-data")
async def get_secure_data(current_user: User = Depends(get_current_user)):
    return {
        "message": f"Hello, {current_user.username}!",
        "data": "This is protected data accessible only with a valid JWT token."
    }

# API health check endpoint
@app.get("/health")
async def health_check():
    return {"status": "healthy"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000, ssl_keyfile="key.pem", ssl_certfile="cert.pem")
