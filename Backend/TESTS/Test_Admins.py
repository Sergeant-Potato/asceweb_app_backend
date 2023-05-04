from sqlalchemy.orm import Session
from Backend.DATABASE.Administrators_Table import Administrators_Table
import Backend.SCHEMAS.Administrators_Schemas as adminSchema
from Backend.API.Security import Secuirity as sc
import os
import jwt
from datetime import datetime, timedelta
from fastapi import Header, HTTPException
from pydantic import SecretStr
from fastapi.responses import JSONResponse
from typing import Optional

__sc = sc()
'''
    If working properly, functions to be moved elsewhere in the future.
'''

def getAdmins(db: Session):
    entries = db.query(Administrators_Table).all()
    return [adminSchema.Administrator_LookAccount_OUT(idAdministrators=entry.idadministrators,name=entry.name,userName=entry.username,password=entry.password,email=entry.email,adminLevel=entry.admin_level, createdAt=entry.created_at, updatedAt=entry.updated_at) for entry in entries]

def getAdminbyEmail(db: Session, email: str):
    return db.query(Administrators_Table).filter(Administrators_Table.email == email).first()

def getAdminbyUserName(db: Session, username: str):
    return db.query(Administrators_Table).filter(Administrators_Table.username == username).first()

def createAdmin(db: Session, admin: adminSchema.Administrator_CreateAccount_OUT):
    dbAdmin = Administrators_Table(name=admin.name, email=admin.email, username=admin.userName.get_secret_value(), password=__sc.encrypt(admin.passwd.get_secret_value()), admin_level=admin.adminLevel,created_at=admin.createdAt, updated_at=admin.updatedAt)
    db.add(dbAdmin)
    db.commit()
    db.refresh(dbAdmin)
    return admin

def validateUser(db: Session,user: adminSchema.Administrator_LoginAccount_OUT):
    username = user.userName.get_secret_value()
    password = user.passwd.get_secret_value()
    database = db.query(Administrators_Table.username, Administrators_Table.password).filter(Administrators_Table.username == username).first()
    # print(database, database[0], database[1])
    if username == database[0] and __sc.verify(password,database[1]):
        return {'msg': "User validated"}
    else:
        return {'msg':'Wrong username or password'}

def loginAdmin(db: Session, admin: adminSchema.Administrator_LoginAccount_OUT) -> bool:
    entries = db.query(Administrators_Table).all()
    for entry in entries:
        if(__sc.verify(admin.passwd.get_secret_value(),entry.password) == True):
            return True
    return False

#------------------------------------------------TOKEN FUNCTIONS
"""
1. function to validate username and password
2. function to create token
3. function to validate token from frontend
   a. Get token
   b. Validate username and password from login
   c. Get username and verify username in database
   d. If token is expired, then create new token

"""

class HttpReturn():
    def __init__(self, status_code: int, detail: dict):
        self.status_code = status_code
        self.detail = detail


def validateUsers(db: Session,username:str,password:SecretStr, token: str):
    """Validate username and password as well as token"""
    schema = adminSchema.Administrator_LoginAccount_OUT(userName=username, passwd=password)
    db_information = db.query(Administrators_Table.username, Administrators_Table.password, Administrators_Table.admin_level).filter(Administrators_Table.username == schema.userName).first()
    # print(db_information, username, schema.passwd.get_secret_value())
    # print(validate_token("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6IktlbHZpbjIwMyIsImV4cF9kYXRlIjoxNjgzMjQ4OTA0LjkxMTY2MiwibGV2ZWwiOiJNQSJ9.Myc4567hJjDIHy60kWWOwY86XWJTuquKmtf1MPcGFLM"))
    try:
        # print(schema.userName == db_information[0], __sc.verify(schema.passwd.get_secret_value(), db_information[1]) )
        if schema.userName == db_information[0] and __sc.verify(schema.passwd.get_secret_value(), db_information[1]):
            return {'status_code': 200, 'Token': validate_token(token)}
            # return {'status_code': 200, 'Token': createToken({'username':schema.userName, 'admin_level': db_information[2]})}  
        else:
            raise HTTPException(status_code=401, detail={'msg': 'Invalid Username or Password'})

    except Exception as e:
        return {'status_code': 401, 'msg': 'Invalid username of password'} 


def createToken(data: dict):
    SECRET_KEY = os.getenv("SECRET_KEY") #Environment variable containing the following: 529ee2aeb7494bce418ed1927c7cfb9531522d453322c62f1c58eb3995db632a
    # print("Secret Key: " + SECRET_KEY)
    token_payload = {
        'username': data['username'],
        'exp_date': (datetime.utcnow() + timedelta(minutes=1)).timestamp(),
        'level': data['admin_level']
    }
    return jwt.encode(token_payload,SECRET_KEY, algorithm="HS256")
    
# def decodeToken(data:str):
#     return jwt.decode(data,os.getenv("SECRET_KEY"), algorithms=["HS256"])

def validate_token(token: str):
    try:
        token_data = jwt.decode(token, os.getenv("SECRET_KEY"), algorithms="HS256")
        return token_data
    except jwt.ExpiredSignatureError as e:
        return "no pasas"


"""
if not token, validate username and password in db and create token
if token, validate username and password in db and validate the token content (username, admin_level):
1. If token is not changed and not expired then pass
    * Username == token[username] and admin_level == token[admin_level] and not expired: return token and access
2. If token is not changed but is expired, create new token
    * Username == token[username] and admin_level == token[admin_level] and expired: return new token and access
2. If token is changed, then return error
    * Username == token[username] and admin_level == token[admin_level]: return error



"""
def validateUserToken(token: str = Header(None)):
    if not token:
        raise HTTPException(status_code=401, detail="Unauthorized")
    try:
        decoded_token = jwt.decode(token,os.getenv("SECRET_KEY"), algorithms=["HS256"])
    except jwt.exceptions.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid Token")
    
    exp_date = datetime.utcfromtimestamp(decoded_token["exp_date"])
    if exp_date < datetime.utcnow():
        raise HTTPException(status_code=401, detail="Token Expired")
    else:
        return decoded_token


