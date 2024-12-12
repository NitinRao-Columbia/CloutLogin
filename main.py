import json
from fastapi import FastAPI, Request, Depends, HTTPException
from fastapi.responses import RedirectResponse
from authlib.integrations.starlette_client import OAuth
from starlette.middleware.sessions import SessionMiddleware
from starlette.config import Config
from starlette.requests import Request
from starlette.responses import JSONResponse, HTMLResponse
from starlette.middleware.sessions import SessionMiddleware
import requests  # For making HTTP requests
from requests.exceptions import RequestException, ConnectionError  # For handling request-related exceptions
import os
import jwt
import datetime
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

SECRET_KEY = "your-secret-key"  # Use a secure, randomly generated key

def create_jwt(payload: dict, expiration_minutes: int = 60) -> str:
    expiration = datetime.datetime.utcnow() + datetime.timedelta(minutes=expiration_minutes)
    payload["exp"] = int(expiration.timestamp())  # Convert datetime to Unix timestamp
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
    

# This is a "hack" to avoid setting environment variables.
# set_env.py is a python file in the local directory that has the
# secret information needed to call the API.
#
# DO NOT ADD THIS FILE TO GITHUB
#
# To see an example of the format, look at sample_set_env.py. You can use this
# example to create your own set_env.py
#
import set_env

from time import sleep

# Load environment variables from a .env file (containing GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET)
# from dotenv import load_dotenv
# load_dotenv("/Users/donald.ferguson/Dropbox/000/000-Columbia-Courses/W4153-Cloud-Computing-Base/simple_examples/.env")

# Initialize FastAPI app
app = FastAPI()

# Secret key for session management
# DFF Changed
# app.add_middleware(SessionMiddleware, secret_key=os.getenv('SECRET_KEY', 'your-secret-key'))

app.add_middleware(SessionMiddleware, secret_key=os.getenv('SECRET_KEY',
                                                           set_env.SECRET_KEY))



# OAuth configuration
# DFF also changed.
# TODO Move back to environment variables.
#
print("Checkpoint 2")
config = Config(environ={
    "GOOGLE_CLIENT_ID": set_env.GOOGLE_CLIENT_ID,
    "GOOGLE_CLIENT_SECRET": set_env.GOOGLE_CLIENT_SECRET
})
oauth = OAuth(config)


print("Checkpoint 1")

google = oauth.register(
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
)

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


@app.get('/')
def index():
    return {"message": "Welcome to the FastAPI Google OAuth example"}


@app.get('/login')
async def login(request: Request):
    state = "some_random_state"  # Generate a secure random state
    request.session['state'] = state  # Save it in session
    redirect_uri = 'http://localhost:5001/oauth2/callback'
    return await oauth.google.authorize_redirect(request, redirect_uri, state=state)


@app.get('/oauth2/callback')
async def auth(request: Request):
    # Verify the state matches
    state = request.query_params.get("state")
    if state != request.session.get('state'):
        raise HTTPException(status_code=400, detail="Invalid state parameter")

    try:
        # Exchange the code for a token
        token = await oauth.google.authorize_access_token(request)
        access_token = token.get("access_token")

        # Fetch user info from the token
        profile = get_user_info(access_token)
        if profile is None:
            raise HTTPException(status_code=400, detail="Failed to fetch user profile")

        print("Full profile = \n", json.dumps(profile, indent=2))

        # Generate the response HTML with JWT token handling

        name = profile["name"]
        picture = profile["picture"]
        email = profile["email"]

        names = name.split(" ", 1)
        first_name = names[0]
        last_name = names[1] if len(names) > 1 else ""

        # Define the backend user creation endpoint
        url = "http://3.145.144.209:8001/users"

        # Create the payload expected by the create_user endpoint
        payload = {
            "first_name": first_name,
            "last_name": last_name,
            "email": email
        }

        # Create JWT token
        token = create_jwt(payload, expiration_minutes=60)
        print("JWT Token:", token)

        # POST request to the user creation endpoint - create_user
        headers = {"Authorization": f"Bearer {token}"}
        print(headers)
        try:
            response = requests.post(url, json=payload, headers=headers)
            if response.status_code == 201:
                print("User created successfully!")
                print("User Details:", response.json())
            elif response.status_code == 400:
                print("Error:", response.json()["detail"])
            elif response.status_code == 409:
            # Handle existing user
            # Option 1: Retrieve existing user details using the same JWT token
                try:
                    # Assuming there's a GET endpoint to fetch user by email
                    get_user_url = f"http://3.145.144.209:8001/users/email/{payload['email']}"
                    print("URL:",get_user_url)
                    get_response = requests.get(get_user_url, headers=headers)
                    
                    if get_response.status_code == 200:
                        existing_user = get_response.json()
                        print("Existing User Details:", existing_user)
                        
                        # Optionally, you can regenerate a JWT token for the existing user
                        existing_user_token = create_jwt({
                            "email": existing_user['email'],
                            "first_name": existing_user['first_name'],
                            "last_name": existing_user['last_name']
                        }, expiration_minutes=60)
                        
                        # Here you could:
                        # 1. Store the token in a session
                        request.session['user_token'] = existing_user_token
                        
                        # 2. Or prepare to pass it back in the response
                        # You might want to modify get_response_html to accept the token
                        
                    else:
                        print("Failed to retrieve existing user details")
                
                except Exception as e:
                    print(f"Error handling existing user: {e}")
        
            else:
                print("Unexpected response:", response.status_code, response.text)
        except requests.ConnectionError as e:
            print("Connection Error:", e)

        result_html = f"""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <title>Login Result</title>
        </head>
        <body>
            <h1>Login Success!</h1>
            Full name: {name}<br>
            Email: {email}<br>
            <br>
            <a href="{picture}">Profile Picture</a>
        </body>
        </html>
        """

        return HTMLResponse(result_html)
    except Exception as e:
        print(f"Authentication Error: {e}")
        raise HTTPException(status_code=400, detail="Authentication failed")

@app.get('/logout')
def logout(request: Request):
    # Clear session data
    request.session.clear()
    return RedirectResponse(url='/')

# Protected route for users
def validate_token(token: str):
    if token == "valid_token":
        return {"id": 1, "username": "testuser"}
    return None

@app.get('/protected')
async def protected_route(user: dict = Depends(authenticate_user)):
    """A route protected by JWT authentication."""
    return {"message": "Welcome!", "user": user}

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

# Run the application
if __name__ == '__main__':
    import uvicorn
    print("Checkpoint 3")
    uvicorn.run(app, host="localhost", port=5001)