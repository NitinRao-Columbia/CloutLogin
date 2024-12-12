import json
from fastapi import FastAPI, Request, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from authlib.integrations.starlette_client import OAuth
from starlette.middleware.sessions import SessionMiddleware
from starlette.config import Config
import requests
import os
from fastapi.responses import RedirectResponse
from starlette.responses import JSONResponse, HTMLResponse
from starlette.requests import Request
import requests  # For making HTTP requests
import jwt
import datetime
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import secrets


SECRET_KEY = "secret"  # Use a secure, randomly generated key

def create_jwt(payload: dict, expiration_minutes: int = 60) -> str:
    expiration = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=expiration_minutes)
    payload["exp"] = int(expiration.timestamp())
    token = jwt.encode(payload, SECRET_KEY, algorithm="HS256")
    return token

http_bearer = HTTPBearer()

def authenticate_user(credentials: HTTPAuthorizationCredentials = Depends(http_bearer)):
    """Authenticate the user using the JWT token from the Authorization header."""
    token = credentials.credentials
    try:
        # Decode and verify the JWT token
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        return payload  # Return the decoded payload if valid
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token has expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")
    


# Load environment variables (e.g., GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET)
import set_env

# Initialize FastAPI app
app = FastAPI()

# Secret key for session management
app.add_middleware(SessionMiddleware, secret_key=os.getenv('SECRET_KEY', set_env.SECRET_KEY), https_only=False, same_site='lax',max_age=3600)


# Add CORS middleware to allow requests from the frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://localhost:5002"],  # Frontend URLs
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# OAuth configuration
config = Config(environ={
    "GOOGLE_CLIENT_ID": set_env.GOOGLE_CLIENT_ID,
    "GOOGLE_CLIENT_SECRET": set_env.GOOGLE_CLIENT_SECRET,
})
oauth = OAuth(config)

google = oauth.register(
    name='google',
    client_id=config.get('GOOGLE_CLIENT_ID'),
    client_secret=config.get('GOOGLE_CLIENT_SECRET'),
    access_token_url='https://accounts.google.com/o/oauth2/token',
    authorize_url='https://accounts.google.com/o/oauth2/auth',
    api_base_url='https://www.googleapis.com/oauth2/v1/',
    userinfo_endpoint='https://openidconnect.googleapis.com/v1/userinfo',
    client_kwargs={
        'scope': 'openid email profile',
        'state': True  # Enable state parameter
    },
    jwks_uri="https://www.googleapis.com/oauth2/v3/certs"
)

"""google = oauth.register(
    name='google',
    client_id=config.get('GOOGLE_CLIENT_ID'),
    client_secret=config.get('GOOGLE_CLIENT_SECRET'),
    access_token_url='https://accounts.google.com/o/oauth2/token',
    access_token_params=None,
    authorize_url='https://accounts.google.com/o/oauth2/auth',
    authorize_params=None,
    api_base_url='https://www.googleapis.com/oauth2/v1/',
    userinfo_endpoint='https://openidconnect.googleapis.com/v1/userinfo',
    # This is only needed if using openId to fetch user info
    client_kwargs={'scope': 'openid email profile'},
    jwks_uri = "https://www.googleapis.com/oauth2/v3/certs"
)"""

profile_url = "https://www.googleapis.com/oauth2/v3/userinfo"


def get_user_info(access_token):
    auth = f"Bearer {access_token}"
    headers = {"Authorization": auth}
    try:
        rsp = requests.get(profile_url, headers=headers)
        rsp.raise_for_status()  # Raise an HTTPError for bad responses (4xx or 5xx)
        return rsp.json()
    except requests.exceptions.RequestException as e:
        print(f"Error fetching user info: {e}")
        return None


@app.get("/")
def index():
    return {"message": "Welcome to the FastAPI Google OAuth example"}


@app.get('/login')
async def login(request: Request):
    state = secrets.token_urlsafe(16)
    request.session['state'] = state
    redirect_uri = 'http://localhost:5001/oauth2/callback'
    return await oauth.google.authorize_redirect(
        request, 
        redirect_uri,
        state=state,
        access_type='offline'
    )


@app.get('/home')
async def home(request: Request):
    try:
        # Get token from session
        token = request.session.get('user_token')
        if not token:
            return RedirectResponse(url='/login', status_code=302)
        
        # Verify the token
        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
            return RedirectResponse(
                url='http://localhost:5002/home',
                status_code=302
            )
        except jwt.InvalidTokenError:
            request.session.clear()
            return RedirectResponse(url='/login', status_code=302)
            
    except Exception as e:
        print(f"Home Error: {e}")
        return RedirectResponse(url='/login', status_code=302)

@app.get('/oauth2/callback')
async def auth(request: Request):
    try:
        # Verify state
        state = request.query_params.get("state")
        print("GETSTATE", request.query_params) # THE PROBLEM IS THAT THERE ARE NO QUERY PARAMS
        print("SESSION.GET",request.session.get('state'))
        if state != request.session.get('state'):
            raise HTTPException(status_code=400, detail="Invalid state parameter")

        # Get token
        token = await oauth.google.authorize_access_token(request)
        access_token = token.get("access_token")
        
        # Get user profile
        profile = get_user_info(access_token)
        if profile is None:
            raise HTTPException(status_code=400, detail="Failed to fetch user profile")

        # Create payload
        name = profile["name"]
        email = profile["email"]
        names = name.split(" ", 1)
        payload = {
            "first_name": names[0],
            "last_name": names[1] if len(names) > 1 else "",
            "email": email
        }

        # Create JWT token
        jwt_token = create_jwt(payload, expiration_minutes=60)
        
        # Store token in session before redirect
        request.session['user_token'] = jwt_token
        
        # Return redirect response
        response = RedirectResponse(
            url='http://localhost:5002/home',
            status_code=302
        )
        return response

    except Exception as e:
        print(f"Authentication Error: {e}")
        raise HTTPException(status_code=400, detail=str(e))


@app.get('/logout')
def logout(request: Request):
    # Clear session data
    request.session.clear()
    return RedirectResponse(url='/')

def validate_token(token: str):
    if token == "valid_token":
        return {"id": 1, "username": "testuser"}
    return None

@app.get('/protected')
async def protected_route(user: dict = Depends(authenticate_user)):
    """A route protected by JWT authentication."""
    return {"message": "Welcome!", "user": user}


@app.get("/me")
def get_current_user(request: Request):
    """Return the currently authenticated user."""
    user = request.session.get("user")
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    return {"user": user}


@app.get('/users')
async def get_users(request: Request):
    # Get token from the Authorization header
    auth_header = request.headers.get("Authorization")
    if not auth_header:
        raise HTTPException(status_code=401, detail="Missing Authorization header")
    
    # Extract the token from the "Bearer <token>" format
    token = auth_header.split("Bearer ")[-1]
    
    # Validate the token
    user = validate_token(token)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    
    return {"message": "Welcome, you are authenticated!", "user": user}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="localhost", port=5001)