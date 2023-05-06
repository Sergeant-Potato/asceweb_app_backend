# from fastapi import FastAPI
# from Backend.CRUD_FUNCTIONS.router import user
# import os

# app = FastAPI()

# app.include_router(user)

# if _name_ == "_main_":
#     import uvicorn
#     uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", 8000)))

import os
from fastapi import Depends, FastAPI, HTTPException, APIRouter, Response
from sqlalchemy.orm import Session
from pydantic import SecretStr
from typing import Optional

from Backend.TESTS import Test_Admins as ta
from Backend.DATABASE.Administrators_Table import Administrators_Table
from Backend.SCHEMAS import Administrators_Schemas
from Backend.CONFIG.connection import engine, Base, SessionLocal
from starlette.status import HTTP_201_CREATED, HTTP_204_NO_CONTENT, HTTP_401_UNAUTHORIZED, HTTP_200_OK

# chapter_members.Base.metadata.create_all(bind=connection.engine)
Base.metadata.create_all(bind = engine)

app = FastAPI()
# user= APIRouter()
#dependency
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Changed this functino response model
@app.get("/ASCEPUPR/ADMIN/GET_ADMINS/", response_model=list[Administrators_Schemas.Administrator_GETTER])
def getAdmins(db: Session = Depends(get_db)):
    dbAdmins = ta.getAdmins(db)
    return dbAdmins

@app.post("/ASCEPUPR/ADMIN/CREATE_ACCOUNT/{userName}/{passwd}/{name}/{email}/{adminLevel}", status_code=HTTP_200_OK)
def createAdmin(userName:str, passwd:str, name:str, email:str, adminLevel:str, db: Session = Depends(get_db)):
    admin = Administrators_Schemas.Administrator_CreateAccount_INPUTS(userName=userName, passwd=passwd,name=name,email=email,adminLevel=adminLevel)
    dbAdmin = ta.getAdminbyEmail(db, email=admin.email)
    if dbAdmin:
        raise HTTPException(status_code=400, detail="Email already registered")
    dbAdmin = ta.getAdminbyUserName(db, username=admin.userName)
    if dbAdmin:
        raise HTTPException(status_code=400, detail="User Name already registered")
    ta.createAdmin(db=db, admin=admin)
    return {'response':HTTP_200_OK, 'message':"User created"}

@app.get("/ASCEPUPR/ADMIN/LOGIN/{userName}/{passwd}", status_code=HTTP_200_OK, response_model=Administrators_Schemas.Administrator_Validate_User)
def loginAdmin(userName:str, passwd: str, token: str, db: Session = Depends(get_db)):
    admin = Administrators_Schemas.Administrator_LoginAccount_INPUTS(userName=userName,passwd=passwd,token=token)
    a = ta.loginAdmin(db,admin = admin)
    if type(a) == str:
        return {"status_code":HTTP_200_OK, 'body':a}
    elif type(a) == bool:
        if a == True:
            return {"status_code":HTTP_200_OK, 'body':"Access Re - Granted"}
        else:
            return {"status_code":HTTP_401_UNAUTHORIZED, 'body': 'Not AUTHORIZED'}

# @app.post("/Content/AdminLogin/")
# def loginAdmin(admin: Administrators_Schemas.Administrator_LoginAccount_IN, db: Session = Depends(get_db)) -> bool:
#     dbAdmin = ta.loginAdmin(db,admin=admin)
#     if dbAdmin == False:
#         raise HTTPException(status_code=401, detail="Wrong User Name or Password")
#     return dbAdmin

# # @app.post("/validation/", response_model=Administrators_Schemas.get_adta)
# @app.post("/validation/", status_code=200 )
# def validateuser(user: Administrators_Schemas.Administrator_LoginAccount_IN, db: Session = Depends(get_db)):
#     # a = ta.validateUser(db, username=admin.userName.get_secret_value(), password=admin.password.get_secret_value())
#     a = ta.validateUser(db, user=user)
#     print(a)
#     if a['msg'] == "User validated":
#         return {"status":HTTP_200_OK, 'message':a}
#     # print(a)
#     # return Response(status_code=HTTP_200_OK)
#     # return {"status":HTTP_200_OK, 'message':a}
#     # return {'userName':a[0], 'password':a[1], 'status': HTTP_200_OK}

@app.get("/ASCEPUPR/ADMIN/CHANGE_PASSWD/{userName}/{oldPasswd}/{newPasswd}", status_code=HTTP_200_OK)
def changeAdminPasswd(userName: str, oldPasswd: str, newPasswd: str, db: Session = Depends(get_db)):
    admin = Administrators_Schemas.Administrator_ChangePasswd_INPUTS(userName=userName, passwd=oldPasswd, newPasswd=newPasswd)
    a = ta.changeAdminPasswd(db=db,admin=admin)
    if a == True:
        return {"status_code":HTTP_200_OK, 'body':"Password was changed"}
    return {"status_code":HTTP_401_UNAUTHORIZED, 'body': 'Password Not Changed'}
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
