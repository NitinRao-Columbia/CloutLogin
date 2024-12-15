import json
from fastapi import FastAPI, Request, Depends, HTTPException
from fastapi.responses import RedirectResponse
from authlib.integrations.starlette_client import OAuth
from starlette.middleware.sessions import SessionMiddleware
from starlette.config import Config
from starlette.responses import JSONResponse
import requests
import os
from datetime import datetime, timedelta, timezone
import jwt
from fastapi.middleware.cors import CORSMiddleware
import secrets
import set_env

app = FastAPI()

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5002"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.add_middleware(
    SessionMiddleware,
    secret_key=set_env.SECRET_KEY,
    session_cookie="session",
    max_age=3600,  # 1 hour
    same_site="lax",
    https_only=False 
)

# JWT settings
JWT_SECRET = set_env.JWT_SECRET
JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# OAuth configuration
config = Config(environ={
    "GOOGLE_CLIENT_ID": set_env.GOOGLE_CLIENT_ID,
    "GOOGLE_CLIENT_SECRET": set_env.GOOGLE_CLIENT_SECRET
})

oauth = OAuth()
oauth.register(
    name='google',
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_id=config.get('GOOGLE_CLIENT_ID'),
    client_secret=config.get('GOOGLE_CLIENT_SECRET'),
    client_kwargs={
        'scope': 'openid email profile'
    }
)

def create_jwt_token(data: dict):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, JWT_SECRET, algorithm=JWT_ALGORITHM)
    return encoded_jwt

@app.get('/login')
async def login(request: Request):
    # Generate a secure random state parameter
    state = secrets.token_urlsafe(16)
    request.session['oauth_state'] = state
    
    redirect_uri = 'http://localhost:5001/oauth2/callback'
    return await oauth.google.authorize_redirect(
        request,
        redirect_uri,
        state=state
    )



@app.get('/oauth2/callback')
async def auth(request: Request):
    try:
        # Verify state parameter
        state = request.query_params.get('state')
        session_state = request.session.get('oauth_state')
        
        if not state or not session_state or state != session_state:
            raise HTTPException(status_code=400, detail="Invalid state parameter")
        
        request.session.pop('oauth_state', None)
        
        # Get token
        token = await oauth.google.authorize_access_token(request)
        
        
        # Get user info
        userinfo = await oauth.google.parse_id_token(request, token)


        
        
        if not userinfo:
            raise HTTPException(status_code=400, detail="Failed to get user info")
        
        # Create JWT token
        jwt_token = create_jwt_token({
            "sub": userinfo["email"],
            "name": userinfo.get("name", ""),
            "email": userinfo["email"]
        })

        name = userinfo.get("name")
        email = userinfo["email"]

        names = name.split(" ", 1)
        first_name = names[0]
        last_name = names[1] if len(names) > 1 else ""
        
        url = "http://3.145.144.209:8001/users"

        # Create the payload expected by the create_user endpoint
        payload = {
        "first_name": first_name,
        "last_name": last_name,
        "email": email
        }

        # POST request to the user creation endpoint - create_user
        headers = {"Authorization": f"Bearer {jwt_token}"}
        print(headers)
        try:
            response = requests.post(url, json=payload, headers=headers)
            if response.status_code == 201:
                print("User created successfully!")
                print("User Details:", response.json())
            elif response.status_code == 400:
                print("Error:", response.json()["detail"])
            elif response.status_code == 409:
                try:
                    get_user_url = f"http://3.145.144.209:8001/users/email/{payload['email']}"
                    print("URL:",get_user_url)
                    get_response = requests.get(get_user_url, headers=headers)

                    if get_response.status_code == 200:
                        existing_user = get_response.json()
                    else:
                        print("Failed to retrieve existing user details")

                except Exception as e:
                    print(f"Error handling existing user: {e}")
            else:
                print("Unexpected response:", response.status_code, response.text)
        except requests.ConnectionError as e:
            print("Connection Error:", e)
        frontend_url = f"http://localhost:5002/auth-callback?token={jwt_token}"
        return RedirectResponse(url=frontend_url)
    except Exception as e:
        print(f"Authentication Error: {e}")
        raise HTTPException(status_code=400, detail="Authentication failed")

@app.get("/verify-token")
async def verify_token(request: Request):
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Invalid authentication credentials")
    
    token = auth_header.split(" ")[1]
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return {"valid": True, "user": payload}
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token has expired")
    except jwt.JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")
    
@app.get("/logout")
async def logout(request: Request):
    request.session.clear()
    return JSONResponse({"message": "Successfully logged out"})

if __name__ == '__main__':
    import uvicorn
    uvicorn.run(app, host="localhost", port=5001)