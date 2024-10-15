#json web token
from jose import JWTError, jwt #library for implementing jwt
from passlib.context import CryptContext #for hashing password
from fastapi import HTTPException, Depends #dependency injection
from fastapi.security import OAuth2PasswordBearer # mechanism for exchanging passwords between front end and backend
from datetime import datetime, timedelta


fake_users_db = {
    "johndoe": {
        "username": "johndoe",
        "full_name": "John Doe",
        "email": "johndoe@example.com",
        "password": "john123", #dont store password as plain text in db
        "disabled": False,
        "status":"VIP"
    },
    "johnboe": {
        "username": "johnboe",
        "full_name": "John Boe",
        "email": "johnboe@example.com",
        "password": "john1234", #dont store password as plain text in db
        "disabled": False,
        "status":"Regular"
    }
}

SECRET_KEY = "7ff9b67b4b584ab0be8422b0fc5ff279dfc2011ef424655bee89401a9b6f6a04"
# for signing JWT and verifying its originality
# dont store credentials in code


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
#bcrypt is for hashing passwords. it also adds salt to the password in real time

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")
#how to exchange password and generate jwt. when we go to swagger,
#we will use its authorization thanks to oauth2_scheme 

def verify_password(plain_password,original_password):
    return plain_password == original_password

def get_user(db, username: str):
    if username in db:
        user_dict = db[username]
        return user_dict #returns users, else returns None
    
def authenticate_user(db, username: str, password: str):
    user = get_user(db, username) #get user from our db
    if not user:
        return False #user does not exist in our system
    if not verify_password(password, user["password"]):
        return False #user entered wrong password
    return user #success, user is authenticated


def create_access_token(data, expires_delta = None):
    to_encode = data.copy() #{"sub": username}
    if expires_delta:
        expire = datetime.now() + expires_delta
    else:
        expire = datetime.now() + timedelta(minutes=15)
    to_encode.update({"exp": expire}) #now jwt payload has username and expire date
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm="HS256") 
    return encoded_jwt #our jwt token

def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        username = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=401,detail="Could not validate credentials")
    except JWTError:
        raise HTTPException(status_code=401,detail="Could not validate credentials")
    return {"username":username}
