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
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from pydantic import SecretStr
from typing import Optional

from Backend.TESTS import Test_Admins as ta
from Backend.DATABASE.Administrators_Table import Administrators_Table
from Backend.SCHEMAS import Administrators_Schemas
from Backend.CONFIG.connection import engine, Base, SessionLocal
from starlette.status import HTTP_201_CREATED, HTTP_204_NO_CONTENT, HTTP_401_UNAUTHORIZED, HTTP_200_OK


Base.metadata.create_all(bind = engine)

app = FastAPI()

"""
To allow certain origins this is needed at the time of deployment
origins = [
    "https://www.inezki.com"
]

app.add_middleware(
    CORSMiddleware,
    allow_origings=origins, 
)"""

# user= APIRouter()
#dependency
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

@app.post("/Content/AdminCreate/", status_code=HTTP_200_OK)
def createAdmin(admin: Administrators_Schemas.Administrator_CreateAccount_IN, db: Session = Depends(get_db)):
    dbAdmin = ta.getAdminbyEmail(db, email=admin.email)
    if dbAdmin:
        raise HTTPException(status_code=400, detail="Email already registered")
    dbAdmin = ta.getAdminbyUserName(db, username=admin.userName.get_secret_value())
    if dbAdmin:
        raise HTTPException(status_code=400, detail="User Name already registered")
    ta.createAdmin(db=db, admin=admin)
    return {'response':HTTP_200_OK, 'message':"User created"}

@app.post("/Content/AdminLogin/")
def loginAdmin(admin: Administrators_Schemas.Administrator_LoginAccount_IN, db: Session = Depends(get_db)) -> bool:
    dbAdmin = ta.loginAdmin(db,admin=admin)
    if dbAdmin == False:
        raise HTTPException(status_code=401, detail="Wrong User Name or Password")
    return dbAdmin

# Changed this functino response model
@app.get("/Content/Admins/", response_model=list[Administrators_Schemas.Administrator_LookAccount_OUT])
def getAdmins(db: Session = Depends(get_db)):
    dbAdmins = ta.getAdmins(db)
    print(dbAdmins)
    return dbAdmins

# @app.post("/validation/", response_model=Administrators_Schemas.get_adta)
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

@app.get("/ascepupr/user/login/", status_code=HTTP_200_OK, response_model=Administrators_Schemas.Validate_user)
def validation(username: str, password: SecretStr, token: str = None, db: Session = Depends(get_db)):
    a = ta.validateUsers(db,username, password, token)
    if a['status_code'] == 200:
        return {"status_code":HTTP_200_OK, 'data':a['body']}
    else:
        return {"status_code":HTTP_401_UNAUTHORIZED, 'data':a['body']}




if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)

