import json
from fastapi import FastAPI, Request, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse, JSONResponse
from authlib.integrations.starlette_client import OAuth
from starlette.middleware.sessions import SessionMiddleware
from starlette.config import Config
import requests
import os

# Load environment variables (e.g., GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET)
import set_env

# Initialize FastAPI app
app = FastAPI()

# Secret key for session management
app.add_middleware(SessionMiddleware, secret_key=os.getenv('SECRET_KEY', set_env.SECRET_KEY))

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
    client_kwargs={'scope': 'openid email profile'},
)

profile_url = "https://www.googleapis.com/oauth2/v3/userinfo"


def get_user_info(access_token):
    """Fetch user info from Google using the access token."""
    headers = {"Authorization": f"Bearer {access_token}"}
    response = requests.get(profile_url, headers=headers)
    try:
        return response.json()
    except Exception as e:
        print(f"Error parsing user info: {e}")
        return None


@app.get("/")
def index():
    return {"message": "Welcome to the FastAPI Google OAuth example"}


@app.get("/login")
async def login(request: Request):
    """Redirect the user to Google's OAuth2 authorization URL."""
    redirect_uri = "http://localhost:5001/oauth2/callback"  # The callback URL
    return await oauth.google.authorize_redirect(request, redirect_uri)


@app.get("/oauth2/callback")
async def auth(request: Request):
    """Handle the OAuth2 callback."""
    try:
        # Get the token and user info after user authorization
        token = await oauth.google.authorize_access_token(request)
        access_token = token.get("access_token")
        profile = get_user_info(access_token)

        if not profile:
            raise HTTPException(status_code=400, detail="Failed to fetch user profile")

        print("User profile:", json.dumps(profile, indent=2))

        # Call Flask backend to check if the user already exists
        check_user_url = f"http://3.145.144.209:8001/users?email={profile.get('email')}"
        check_response = requests.get(check_user_url)
        if check_response.status_code == 200:
            print("User already exists. Skipping creation.")
        else:
            # Create a new user in Flask backend
            create_user_url = "http://3.145.144.209:8001/users"
            payload = {
                "first_name": profile.get("given_name"),
                "last_name": profile.get("family_name"),
                "email": profile.get("email"),
            }
            create_response = requests.post(create_user_url, json=payload)
            create_response.raise_for_status()
            print("User created successfully.")

        # Store user info in session for authentication
        request.session["user"] = profile

        # Redirect to React app after successful login
        return RedirectResponse(url="http://localhost:3000/home")
    except Exception as e:
        print(f"Error during authentication: {e}")
        raise HTTPException(status_code=400, detail="Authentication failed")


@app.get("/logout")
def logout(request: Request):
    """Clear session data and log out the user."""
    request.session.clear()
    return RedirectResponse(url="/")


@app.get("/me")
def get_current_user(request: Request):
    """Return the currently authenticated user."""
    user = request.session.get("user")
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    return {"user": user}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="localhost", port=5001)