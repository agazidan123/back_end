from fastapi import FastAPI, HTTPException, status, Depends
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel, EmailStr
from sqlalchemy import create_engine, MetaData, select
from passlib.context import CryptContext
from authlib.integrations.starlette_client import OAuth
from dotenv import load_dotenv
from starlette.requests import Request
from typing import List, Optional
from datetime import datetime, timedelta, timezone
import jwt
from sqlalchemy import Table, Column, Integer, String


load_dotenv()

app = FastAPI()

SECRET_KEY = "d38b291ccebc18af95d4df97a0a98f9bb9eea3c820e771096fa1c5e3a58f3d53"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

DATABASE_URL = r"mssql+pyodbc://admin:12tourism#app34@tourism.cnqy0qogeve8.us-east-1.rds.amazonaws.com/TouristaDB?driver=ODBC+Driver+17+for+SQL+Server&Integrated_Security=True"
engine = create_engine(DATABASE_URL)
metadata = MetaData()

users = Table(
    "users",
    metadata,
    Column("user_id", Integer, primary_key=True, index=True),
    Column("first_name", String(length=255)),
    Column("last_name", String(length=255)),
    Column("user_email", String),
    Column("user_password", String),
    Column("user_location", String),
)

metadata.create_all(bind=engine)


def query_database(country: str, governorate: str, category: str, name: str) -> List[str]:
    return []


class UserRegistration(BaseModel):
    first_name: str
    last_name: str
    user_password: str
    user_email: EmailStr
    user_location: Optional[str] = None


class UserLogin(BaseModel):
    user_email: EmailStr
    user_password: str


class UserUpdate(BaseModel):
    first_name: str
    last_name: str
    user_location: str


class UserResetPassword(BaseModel):
    user_identifier: str
    new_password: str


oauth = OAuth()
oauth.register(
    name='google',
    client_id='YOUR_GOOGLE_CLIENT_ID',
    client_secret='YOUR_GOOGLE_CLIENT_SECRET',
    authorize_url='https://accounts.google.com/o/oauth2/auth',
    authorize_params={'scope': 'openid email profile'},
    access_token_url='https://accounts.google.com/o/oauth2/token',
    access_token_params=None,
    userinfo_url='https://openidconnect.googleapis.com/v1/userinfo',
    userinfo_params=None,
    client_kwargs={'token_endpoint_auth_method': 'client_secret_post'}
)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

password_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def hash_password(password: str):
    return password_context.hash(password)


def verify_user_credentials(user_email: str, user_password: str):
    conn = engine.connect()
    query = select(users.c.user_email, users.c.user_password).where(users.c.user_email == user_email)
    result = conn.execute(query).fetchone()

    if result and password_context.verify(user_password, result[1]):
        return True
    return False


def register_user(user: UserRegistration):
    conn = engine.connect()
    conn.execute(users.insert().values(
        first_name=user.first_name,
        last_name=user.last_name,
        user_password=hash_password(user.user_password),
        user_email=user.user_email,
        user_location=user.user_location,
    ))
    conn.commit()


def delete_user(user_id: int):
    conn = engine.connect()
    conn.execute(users.delete().where(users.c.user_id == user_id))
    conn.commit()


def update_user(user_id: int, updated_user: UserUpdate):
    conn = engine.connect()
    conn.execute(users.update().where(users.c.user_id == user_id).values(
        first_name=updated_user.first_name,
        last_name=updated_user.last_name,
        user_location=updated_user.user_location,
    ))
    conn.commit()


def reset_password(user_identifier: str, new_password: str):
    conn = engine.connect()
    hashed_password = hash_password(new_password)
    if '@' in user_identifier:
        conn.execute(users.update().where(users.c.user_email == user_identifier).values(
            user_password=hashed_password
        ))
    else:
        pass
    conn.commit()


UTC = timezone.utc


def create_access_token(data: dict, expires_delta: timedelta = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)):
    to_encode = data.copy()
    expire = datetime.now(UTC) + expires_delta
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def get_user_from_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_email = payload.get("sub")
        if user_email is None:
            return None
        return user_email
    except jwt.JWTError:
        return None


@app.post("/register")
async def register(user: UserRegistration):
    if verify_user_credentials(user.user_email, user.user_password):
        raise HTTPException(status_code=400, detail="User already registered")

    register_user(user)
    return {"message": "Registration successful"}


@app.post("/login")
async def login(user: UserLogin):
    user_email = user.user_email
    user_password = user.user_password

    if not verify_user_credentials(user_email, user_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

    access_token = create_access_token(data={"sub": user_email})
    return {"access_token": access_token, "token_type": "bearer", "message": "Login successful"}


@app.delete("/delete")
async def delete(user_id: int):
    delete_user(user_id)
    return {"message": "User deleted successfully"}


@app.put("/update")
async def update(user_id: int, updated_user: UserUpdate):
    update_user(user_id, updated_user)
    return {"message": "User updated successfully"}


@app.post("/reset_password")
async def reset_password_route(user_reset: UserResetPassword):
    user_identifier = user_reset.user_identifier
    new_password = user_reset.new_password

    reset_password(user_identifier, new_password)
    return {"message": "Password reset successful"}


recent_searches = []


@app.post("/search/")
async def search(country: str, governorate: str, category: str, name: str):
    search_results = query_database(country, governorate, category, name)

    recent_searches.append((country, governorate, category, name))

    if len(recent_searches) > 10:
        recent_searches.pop(0)

    return {"results": search_results}


@app.put("/change_password")
async def change_password(user_id: int, current_password: str, new_password: str):
    conn = engine.connect()
    query = select(users.c.user_password).where(users.c.user_id == user_id)
    result = conn.execute(query).fetchone()

    if result:
        current_hashed_password = result[0]
        if password_context.verify(current_password, current_hashed_password):
            hashed_new_password = hash_password(new_password)
            conn.execute(users.update().where(users.c.user_id == user_id).values(
                user_password=hashed_new_password
            ))
            conn.commit()
            return {"message": "Password changed successfully"}

    raise HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail="Invalid current password"
    )


history = []


@app.post("/add_plan/")
async def add_input(new_input: str):
    history.append(new_input)
    return {"message": f"Input '{new_input}' processed. History: {history}"}


@app.get("/login_google")
async def login_google(request: Request):
    redirect_uri = request.url_for('google_callback')
    return await oauth.google.authorize_redirect(request, redirect_uri)


@app.get("/google_callback")
async def google_callback(request: Request):
    token = await oauth.google.authorize_access_token(request)
    user_info = await oauth.google.parse_id_token(request, token)
    return {"token": token, "user_info": user_info}


@app.get("/protected_resource")
async def protected_resource(token: str = Depends(oauth2_scheme)):
    return {"token": token}


@app.get("/history/")
async def get_history():
    return {"history": history}


@app.get("/recent_searches/")
async def get_recent_searches():
    return {"recent_searches": recent_searches}
